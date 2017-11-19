package services

import (
	"crypto/rsa"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/plopezm/gosm/gingonic/support"
)

var JWTPrivateKey *rsa.PrivateKey
var JWTPublicKey *rsa.PublicKey
var JWKInfoToken *support.JWKInfo

func GenerateNewJWT(claims jwt.Claims) (tokenString string) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(JWTPrivateKey)

	if err != nil {
		fmt.Println("[generateNewJWT]: ", err)
	}
	return tokenString
}
