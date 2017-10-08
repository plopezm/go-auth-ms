package main

import (
	"github.com/gin-gonic/gin"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"fmt"
	"github.com/plopezm/go-auth-ms/security"
	"github.com/plopezm/go-auth-ms/services"
	"strconv"
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
	username, ok := c.Get("username")
	if !ok {
		c.Status(http.StatusUnauthorized)
		return
	}

	token := generateNewJWT(jwt.MapClaims{
		"user": username,
	})
	c.Writer.Header().Set("Authorization", "Bearer "+token)
	c.JSON(http.StatusOK, AuthToken{
		Type: "Bearer",
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

func GetUsers(c *gin.Context){
	users, err := services.FindAllUsers()
	if err != nil{
		fmt.Println("Error finding users: ", err)
		c.JSON(http.StatusNotFound, err)
		return
	}
	c.JSON(http.StatusOK, users)
}

func GetUserById(c *gin.Context){
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil{
		c.JSON(http.StatusBadRequest, err)
		return
	}
	users, err := services.GetUserById(id)
	if err != nil{
		c.JSON(http.StatusNotFound, err)
		return
	}
	c.JSON(http.StatusOK, users)
}

