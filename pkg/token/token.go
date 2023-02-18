package token

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"log"
	"time"
)

type T struct {
	Expiration time.Time
	Username   string
	Mac        []byte
}

func (t T) computeMac(secret []byte) []byte {
	zt := t
	zt.Mac = nil

	mac := hmac.New(sha256.New, secret)
	mac.Write(zt.Bytes())
	return mac.Sum([]byte{})
}

// Bytes encodes the token
func (t T) Bytes() []byte {
	f := new(bytes.Buffer)
	enc := gob.NewEncoder(f)
	if err := enc.Encode(t); err != nil {
		log.Fatal(err)
	}
	return f.Bytes()
}

// String returns the ASCII string encoding of the token
func (t T) String() string {
	return base64.StdEncoding.EncodeToString(t.Bytes())
}

// Valid returns true iff the token is valid for the given secret and current time
func (t T) Valid(secret []byte) bool {
	if time.Now().After(t.Expiration) {
		return false
	}
	if !hmac.Equal(t.Mac, t.computeMac(secret)) {
		return false
	}

	return true
}

// New returns a new token
func New(secret []byte, username string, expiration time.Time) T {
	t := T{
		Username:   username,
		Expiration: expiration,
	}
	t.Mac = t.computeMac(secret)
	return t
}

// Parse returns a new token from the given bytes
func Parse(b []byte) (T, error) {
	var t T
	f := bytes.NewReader(b)
	dec := gob.NewDecoder(f)
	err := dec.Decode(&t)
	return t, err
}

// ParseString parses an ASCII-encoded string, as created by T.String()
func ParseString(s string) (T, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return T{}, nil
	}
	return Parse(b)
}
