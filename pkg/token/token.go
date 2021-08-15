package token

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"time"
)

type T struct {
	expiration time.Time
	mac        []byte
}

func (t T) computeMac(secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	binary.Write(mac, binary.BigEndian, t.expiration)
	return mac.Sum([]byte{})
}

// String returns the string encoding of the token
func (t T) String() string {
	f := new(bytes.Buffer)
	binary.Write(f, binary.BigEndian, t.expiration)
	f.Write(t.mac)
	return base64.StdEncoding.EncodeToString(f.Bytes())
}

// Valid returns true iff the token is valid for the given secret and current time
func (t T) Valid(secret []byte) bool {
	if time.Now().After(t.expiration) {
		return false
	}
	if !hmac.Equal(t.mac, t.computeMac(secret)) {
		return false
	}

	return true
}

// New returns a new token
func New(secret []byte, expiration time.Time) T {
	t := T{
		expiration: expiration,
	}
	t.mac = t.computeMac(secret)
	return t
}

// Parse returns a new token from the given bytes
func Parse(b []byte) (T, error) {
	t := T{
		mac: make([]byte, sha256.Size),
	}
	f := bytes.NewReader(b)
	if err := binary.Read(f, binary.BigEndian, &t.expiration); err != nil {
		return t, err
	}
	if n, err := f.Read(t.mac); err != nil {
		return t, err
	} else {
		t.mac = t.mac[:n]
	}
	return t, nil
}

// ParseString parses a base64-encoded string, as created by T.String()
func ParseString(s string) (T, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return T{}, nil
	}
	return Parse(b)
}
