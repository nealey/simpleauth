package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/nealey/simpleauth/pkg/token"
)

const CookieName = "auth"

var secret []byte = make([]byte, 256)
var lifespan time.Duration
var password string
var loginHtml []byte
var successHtml []byte

func rootHandler(w http.ResponseWriter, req *http.Request) {
	authenticated := false
	if _, passwd, _ := req.BasicAuth(); passwd == password {
		authenticated = true
	}
	if req.FormValue("passwd") == password {
		authenticated = true
	}
	if cookie, err := req.Cookie(CookieName); err == nil {
		t, _ := token.ParseString(cookie.Value)
		if t.Valid(secret) {
			authenticated = true
		}
	}

	if authenticated {
		t := token.New(secret, time.Now().Add(lifespan))
		http.SetCookie(w, &http.Cookie{
			Name:     CookieName,
			Value:    t.String(),
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		w.Write(successHtml)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(loginHtml)
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
		"/run/secrets/password",
		"Path to a file containing the password",
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

	passwordBytes, err := ioutil.ReadFile(*passwordPath)
	if err != nil {
		log.Fatal(err)
	}
	password = strings.TrimSpace(string(passwordBytes))

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
	if l == 0 {
		log.Fatal("Secret file provided 0 bytes. That's not enough bytes!")
	} else if err != nil {
		log.Fatal(err)
	}
	secret = secret[:l]

	http.HandleFunc("/", rootHandler)

	fmt.Println("I am listening on ", *listen)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
