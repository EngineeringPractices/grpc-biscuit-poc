package main

import (
	"crypto/rand"
	"io/ioutil"

	"github.com/flynn/biscuit-go/sig"
)

func main() {
	privateKeyPath := "./private.demo.key"
	publicKeyPath := "./public.demo.key"
	kp := sig.GenerateKeypair(rand.Reader)
	if err := ioutil.WriteFile(privateKeyPath, kp.Private().Bytes(), 0600); err != nil {
		panic(err)
	}
	if err := ioutil.WriteFile(publicKeyPath, kp.Public().Bytes(), 0644); err != nil {
		panic(err)
	}
}
