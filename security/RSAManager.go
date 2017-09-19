package security

import (
	"io/ioutil"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"crypto/rsa"
)

var PrivateKey *rsa.PrivateKey
var PublicKey *rsa.PublicKey

func init(){
	var err error
	PrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(ReadFile("privkey.pem"))
	check(err)
	PublicKey, err = jwt.ParseRSAPublicKeyFromPEM(ReadFile("pubkey.pem"))
	check(err)
}

type JWKRSA struct {
	Kty 	string 	`json:"kty"`
	N		string	`json:"n"`
	E		string	`json:"e"`
	Alg		string	`json:"alg"`
	Kid		string	`json:"kid"`
}

func ReadFile(file string) []byte{
	dat, err := ioutil.ReadFile(file)
	check(err)
	fmt.Print(string(dat))
	return dat
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
