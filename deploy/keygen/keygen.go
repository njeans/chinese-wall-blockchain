package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
  "fmt"
  "os"
	"path"
	"strconv"
)

// GenerateKeyPair generates a new key pair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return privkey, &privkey.PublicKey
}

// PrivateKeyToBytes private key to bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

// PublicKeyToBytes public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes
}

func main() {
  if len(os.Args) != 3 {
    panic("Total number of required organizations as input and directory")
  }

  num_orgs, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}
  dir := os.Args[2]
  for i := 0; i < num_orgs; i++ {
    priv,pub := GenerateKeyPair(2048)
    privb := PrivateKeyToBytes(priv)
    privfile := fmt.Sprintf("priv%v.pem",i+1)
    privpath := path.Join(dir,privfile)
    f1, err := os.Create(privpath)
		if err != nil {
			panic(err)
		}
    _, err = f1.Write(privb)
		if err != nil {
			panic(err)
		}
    pubb := PublicKeyToBytes(pub)
    pubfile := fmt.Sprintf("pub%v.pem",i+1)
    pubpath := path.Join(dir,pubfile)
    f2, err := os.Create(pubpath)
		if err != nil {
			panic(err)
		}
    _, err = f2.Write(pubb)
		if err != nil {
			panic(err)
		}
  }
}
