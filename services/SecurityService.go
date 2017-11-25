package services

import (
	"fmt"

	"github.com/plopezm/gosm/gingonic/rsastore"

	jwt "github.com/dgrijalva/jwt-go"
)

var Keystore *rsastore.RsaKeystore

func GenerateNewJWT(claims jwt.Claims) (tokenString string) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(Keystore.PrivateKey)

	if err != nil {
		fmt.Println("[generateNewJWT]: ", err)
	}
	return tokenString
}
