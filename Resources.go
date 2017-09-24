package main

import (
	"github.com/gin-gonic/gin"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"fmt"
	"github.com/plopezm/go-auth-ms/security"
)

type AuthToken struct {
	Type			string	`json:"type"`
	Token			string	`json:"token"`
}

func generateNewJWT(claims jwt.Claims) (tokenString string){
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(security.PrivateKey)

	fmt.Println("Token string generated: ",tokenString, err)
	return tokenString
}

func GetPublicKey(c *gin.Context){
	c.JSON(http.StatusOK, security.PublicKeyKWT)
}

func Login(c *gin.Context){
	//c.Writer.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	//c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
	//c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")
	//c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
	//c.Writer.Header().Set("Access-Control-Max-Age", "86400")
	token := generateNewJWT(jwt.MapClaims{
		"user": "test",
	})
	c.Writer.Header().Set("Authorization", "Bearer "+token)
	c.JSON(http.StatusOK, AuthToken{
		Type: "jwt",
		Token:token,
	})
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

