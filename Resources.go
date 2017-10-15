package main

import (
	"github.com/gin-gonic/gin"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"fmt"
	"github.com/plopezm/go-auth-ms/security"
	"github.com/plopezm/go-auth-ms/services"
	"strconv"
	"time"
)

type AuthToken struct {
	Type			string	`json:"type"`
	Token			string	`json:"token"`
}

func generateNewJWT(claims jwt.Claims) (tokenString string){
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(security.PrivateKey)

	if err != nil {
		fmt.Println("[generateNewJWT]: ", err)
	}
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
		"exp": time.Now().Add(time.Second * 4).Unix(),
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

func CreateUser(c *gin.Context){
	var user services.User
	c.BindJSON(&user)
	user, err := services.CreateUser(user)
	if err != nil {
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}
	c.JSON(http.StatusCreated, user)
}

func UpdateUser(c *gin.Context){
	var user services.User
	c.BindJSON(&user)
	user, err := services.UpdateUser(user)
	if err != nil {
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}
	c.JSON(http.StatusCreated, user)
}

func DeleteUser(c *gin.Context){
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil{
		c.JSON(http.StatusBadRequest, err)
		return
	}
	user, err := services.DeleteUserById(id)
	if err != nil{
		c.JSON(http.StatusNotFound, err)
		return
	}
	c.JSON(http.StatusOK, user)
}

func GetRoles(c *gin.Context){
	roles, err := services.FindAllRoles()
	if err != nil{
		fmt.Println("Error finding roles: ", err)
		c.JSON(http.StatusNotFound, err)
		return
	}
	c.JSON(http.StatusOK, roles)
}

func GetRoleById(c *gin.Context){
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil{
		c.JSON(http.StatusBadRequest, err)
		return
	}
	role, err := services.GetRoleById(id)
	if err != nil{
		c.JSON(http.StatusNotFound, err)
		return
	}
	c.JSON(http.StatusOK, role)
}

func CreateRole(c *gin.Context){
	var role services.Role
	c.BindJSON(&role)
	user, err := services.CreateRole(role)
	if err != nil {
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}
	c.JSON(http.StatusCreated, user)
}

func UpdateRole(c *gin.Context){
	var role services.Role
	c.BindJSON(&role)
	user, err := services.UpdateRole(role)
	if err != nil {
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}
	c.JSON(http.StatusCreated, user)
}

func DeleteRole(c *gin.Context){
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil{
		c.JSON(http.StatusBadRequest, err)
		return
	}
	role, err := services.DeleteRoleById(id)
	if err != nil{
		c.JSON(http.StatusNotFound, err)
		return
	}
	c.JSON(http.StatusOK, role)
}