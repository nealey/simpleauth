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
	"github.com/nealey/simpleauth/pkg/token"
)

const CookieName = "auth"

var secret []byte = make([]byte, 256)
var lifespan time.Duration
var cryptedPasswords map[string]string
var loginHtml []byte
var successHtml []byte

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
			// Bypass logging and cookie setting:
			// otherwise there is a torrent of logs
			w.Write(successHtml)
			return
		}
	}

	authenticated := ""

	if username, password, ok := req.BasicAuth(); ok {
		if authenticationValid(username, password) {
			authenticated = "HTTP-Basic"
		}
	}

	if authenticationValid(req.FormValue("username"), req.FormValue("password")) {
		authenticated = "Form"
	}

	// Log the request
	clientIP := req.Header.Get("X-Real-IP")
	if clientIP == "" {
		clientIP = req.RemoteAddr
	}
	log.Printf("%s %s %s [%s]", clientIP, req.Method, req.URL, authenticated)

	if authenticated == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(loginHtml)
	} else {
		t := token.New(secret, time.Now().Add(lifespan))
		http.SetCookie(w, &http.Cookie{
			Name:     CookieName,
			Value:    t.String(),
			Path:     "/",
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusOK)
		w.Write(successHtml)
	}
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
		"static",
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
	successHtml, err = ioutil.ReadFile(path.Join(*htmlPath, "success.html"))
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
