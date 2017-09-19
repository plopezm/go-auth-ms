package main

import (
	"github.com/gin-gonic/gin"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"fmt"
	"github.com/plopezm/go-auth-ms/security"
	"strconv"
)

func generateNewJWT(claims jwt.Claims) (tokenString string){
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(security.PrivateKey)

	fmt.Println("Token string generated: ",tokenString, err)
	return tokenString
}

func GetPublicKey(c *gin.Context){
	c.JSON(http.StatusOK, security.JWKRSA{
		Kty: "RSA",
		N: security.PublicKey.N.String(),
		E: strconv.Itoa(security.PublicKey.E),
		Alg: "RS512",
		Kid: "go-auth-ms",
	})
}

func Login(c *gin.Context){
	c.Header("Authorization", "Bearer "+generateNewJWT(jwt.MapClaims{
		"user": "test",
	}))
	c.Status(http.StatusOK)
}

func Verify(c *gin.Context){
}

func Refresh(c *gin.Context){
	value, exists := c.Get("claims")
	if !exists {
		c.Status(http.StatusBadRequest)
		return
	}
	if claims, ok := value.(jwt.MapClaims); !ok{
		c.Header("Authorization", "Bearer "+generateNewJWT(claims))
		c.Status(http.StatusOK)
		return
	}
	c.Status(http.StatusBadRequest)
}

