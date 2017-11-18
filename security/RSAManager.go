package security

import (
	"crypto/rsa"
	"io/ioutil"
	"strconv"

	"github.com/dgrijalva/jwt-go"
)

var PrivateKey *rsa.PrivateKey
var PublicKey *rsa.PublicKey
var PublicKeyKWT JWKRSA

func init() {
	var err error
	PrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(ReadFile("jwtpriv.pem"))
	check(err)
	PublicKey, err = jwt.ParseRSAPublicKeyFromPEM(ReadFile("jwtpub.pem"))
	check(err)
	PublicKeyKWT = JWKRSA{
		Kty: "RSA",
		N:   PublicKey.N.String(),
		E:   strconv.Itoa(PublicKey.E),
		Alg: "RS512",
		Kid: "go-auth-ms",
	}
}

type JWKRSA struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

func ReadFile(file string) []byte {
	dat, err := ioutil.ReadFile(file)
	check(err)
	//fmt.Print(string(dat))
	return dat
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
