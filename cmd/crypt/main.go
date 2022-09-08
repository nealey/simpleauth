package main

import (
	"fmt"
	"log"
	"os"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("Usage: crypt USERNAME PASSWORD")
	}
	username := os.Args[1]
	password := os.Args[2]
	c := crypt.SHA256.New()
	if crypted, err := c.Generate([]byte(password), nil); err != nil {
		log.Fatal(err)
	} else {
		fmt.Printf("%s:%s\n", username, crypted)
	}
}
