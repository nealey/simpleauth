package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	"git.woozle.org/neale/simpleauth/pkg/token"
)

const CookieName = "simpleauth-token"

var secret []byte = make([]byte, 256)
var lifespan time.Duration
var cryptedPasswords map[string]string
var loginHtml []byte

func authenticationValid(username, password string) bool {
	c := crypt.SHA256.New()
	if crypted, ok := cryptedPasswords[username]; ok {
		if err := c.Verify(crypted, []byte(password)); err == nil {
			return true
		}
	}
	return false
}

func rootHandler(w http.ResponseWriter, req *http.Request) {
	if cookie, err := req.Cookie(CookieName); err == nil {
		t, _ := token.ParseString(cookie.Value)
		if t.Valid(secret) {
			fmt.Print(w, "Valid token")
			return
		}
	}

	acceptsHtml := false
	if strings.Contains(req.Header.Get("Accept"), "text/html") {
		acceptsHtml = true
	}

	authenticated := false
	if username, password, ok := req.BasicAuth(); ok {
		authenticated = authenticationValid(username, password)
	}

	// Log the request
	clientIP := req.Header.Get("X-Real-IP")
	if clientIP == "" {
		clientIP = req.RemoteAddr
	}
	log.Printf("%s %s %s [auth:%v]", clientIP, req.Method, req.URL, authenticated)

	if !authenticated {
		w.Header().Set("Content-Type", "text/html")
		if !acceptsHtml {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"simpleauth\"")
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(loginHtml)
		return
	}

	// Set Cookie
	t := token.New(secret, time.Now().Add(lifespan))
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    t.String(),
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	// Set cookie value in our fancypants header
	w.Header().Set("X-Simpleauth-Token", t.String())

	if req.Header.Get("X-Simpleauth-Login") != "" {
		// Caddy treats any response <300 as "please serve original content",
		// so we'll use 302 (Found).
		// According to RFC9110, the server SHOULD send a Location header with 302.
		// We don't do that, because we don't know where to send you.
		// It's possible 300 is a less incorrect code to use here.
		w.WriteHeader(http.StatusFound)
	}
	fmt.Fprintln(w, "Authenticated")
}

func main() {
	listen := flag.String(
		"listen",
		":8080",
		"Bind address for incoming HTTP connections",
	)
	flag.DurationVar(
		&lifespan,
		"lifespan",
		100*24*time.Hour,
		"How long an issued token is valid",
	)
	passwordPath := flag.String(
		"passwd",
		"/run/secrets/passwd",
		"Path to a file containing passwords",
	)
	secretPath := flag.String(
		"secret",
		"/dev/urandom",
		"Path to a file containing some sort of secret, for signing requests",
	)
	htmlPath := flag.String(
		"html",
		"web",
		"Path to HTML files",
	)
	flag.Parse()

	cryptedPasswords = make(map[string]string, 10)
	if f, err := os.Open(*passwordPath); err != nil {
		log.Fatal(err)
	} else {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				username := parts[0]
				password := parts[1]
				cryptedPasswords[username] = password
			}
		}
	}

	var err error

	loginHtml, err = ioutil.ReadFile(path.Join(*htmlPath, "login.html"))
	if err != nil {
		log.Fatal(err)
	}

	// Read in secret
	f, err := os.Open(*secretPath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	l, err := f.Read(secret)
	if l < 8 {
		log.Fatalf("Secret file provided %d bytes. That's not enough bytes!", l)
	} else if err != nil {
		log.Fatal(err)
	}
	secret = secret[:l]

	http.HandleFunc("/", rootHandler)

	fmt.Println("listening on", *listen)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
