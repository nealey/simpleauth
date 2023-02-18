package token

import (
	"testing"
	"time"
)

func TestToken(t *testing.T) {
	secret := []byte("bloop")
	username := "rodney"
	token := New(secret, username, time.Now().Add(10*time.Second))

	if token.Username != username {
		t.Error("Wrong username")
	}
	if !token.Valid(secret) {
		t.Error("Not valid")
	}

	tokenStr := token.String()
	if nt, err := ParseString(tokenStr); err != nil {
		t.Error("ParseString", err)
	} else if nt.Username != token.Username {
		t.Error("Decoded username wrong")
	}
}
