package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io/ioutil"

	"github.com/flynn/biscuit-go/sig"
)

func main() {
	privateKeyPath := "./root.private.demo.key"
	publicKeyPath := "./root.public.demo.key"
	if err := generateRS255KeyPair(privateKeyPath, publicKeyPath); err != nil {
		panic(err)
	}

	audiencePrivateKeyPath := "./audience.private.demo.key"
	audiencePublicKeyPath := "./audience.public.demo.key"
	if err := generateECDSAKeyPair(audiencePrivateKeyPath, audiencePublicKeyPath); err != nil {
		panic(err)
	}

	userPrivateKeyPath := "./user.private.demo.key"
	userPublicKeyPath := "./user.public.demo.key"
	if err := generateECDSAKeyPair(userPrivateKeyPath, userPublicKeyPath); err != nil {
		panic(err)
	}
}

func generateRS255KeyPair(privateKeyPath, publicKeyPath string) error {
	kp := sig.GenerateKeypair(rand.Reader)
	if err := ioutil.WriteFile(privateKeyPath, kp.Private().Bytes(), 0600); err != nil {
		return err
	}
	if err := ioutil.WriteFile(publicKeyPath, kp.Public().Bytes(), 0644); err != nil {
		return err
	}
	return nil
}

func generateECDSAKeyPair(privateKeyPath, publicKeyPath string) error {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(privateKeyPath, privKeyBytes, 0600); err != nil {
		return err
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(publicKeyPath, pubKeyBytes, 0644); err != nil {
		return err
	}

	return nil
}
