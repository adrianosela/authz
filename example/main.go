package main

import (
	"log"

	"github.com/adrianosela/authz"
)

func main() {
	if _, err := authz.Load("./policy.yaml"); err != nil {
		log.Fatal(err)
	}
}
