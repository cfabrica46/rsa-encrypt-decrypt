package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {

	privateKey, err := getPrivateKey()

	if err != nil {
		log.Fatal(err)
	}

	publicKey, err := getPublicKey()

	if err != nil {
		log.Fatal(err)
	}

	dataOrigen, err := ioutil.ReadFile("txt.txt")

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", dataOrigen)

	dataEncriptada, err := encrypt(dataOrigen, publicKey)

	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile("encrypt.txt", dataEncriptada, 0644)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%x\n", dataEncriptada)

	dataDesencriptada, err := decrypt(dataEncriptada, privateKey)

	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile("decrypt.txt", dataDesencriptada, 0644)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", dataDesencriptada)

}

func getPrivateKey() (privateKey *rsa.PrivateKey, err error) {

	dataKeyPrivada, err := ioutil.ReadFile("private.pem")

	if err != nil {
		return
	}

	block, _ := pem.Decode(dataKeyPrivada)

	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes

	if enc {
		fmt.Println("1 is encrypted pem block")

		b, err = x509.DecryptPEMBlock(block, []byte("cfabrica46"))

		if err != nil {
			return
		}
	}

	privateKey, err = x509.ParsePKCS1PrivateKey(b)

	if err != nil {
		return
	}

	return

}

func getPublicKey() (publicKey *rsa.PublicKey, err error) {

	dataKeyPublic, err := ioutil.ReadFile("public.pem")

	if err != nil {
		return
	}

	block, _ := pem.Decode(dataKeyPublic)

	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes

	if enc {
		fmt.Println("2 is encrypted pem block")

		b, err = x509.DecryptPEMBlock(block, []byte("cfabrica46"))

		if err != nil {
			return
		}

	}

	ifc, err := x509.ParsePKIXPublicKey(b)

	if err != nil {

		log.Fatal(err)

	}

	publicKey, ok := ifc.(*rsa.PublicKey)

	if !ok {

		log.Fatal("no es llave publica")

	}
	return
}

func encrypt(dataOrigen []byte, publicKey *rsa.PublicKey) (dataEncriptada []byte, err error) {

	label := []byte("OAEP Encrypted")

	rng := rand.Reader

	dataEncriptada, err = rsa.EncryptOAEP(sha256.New(), rng, publicKey, dataOrigen, label)

	if err != nil {
		return
	}

	return
}

func decrypt(dataEncriptada []byte, privateKey *rsa.PrivateKey) (dataDesencriptada []byte, err error) {

	label := []byte("OAEP Encrypted")

	rng := rand.Reader

	dataDesencriptada, err = rsa.DecryptOAEP(sha256.New(), rng, privateKey, dataEncriptada, label)

	if err != nil {
		return
	}

	return
}
