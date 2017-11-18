package resources

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/plopezm/go-auth-ms/models"
	"github.com/plopezm/go-auth-ms/security"
	"github.com/plopezm/go-auth-ms/security/jwtmodels"
	"github.com/plopezm/go-auth-ms/services"
)

func generateNewJWT(claims jwt.Claims) (tokenString string) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(security.PrivateKey)

	if err != nil {
		fmt.Println("[generateNewJWT]: ", err)
	}
	return tokenString
}

func GetPublicKey(c *gin.Context) {
	c.JSON(http.StatusOK, security.PublicKeyKWT)
}

func Login(c *gin.Context) {
	username, ok := c.Get("username")
	if !ok {
		c.Status(http.StatusUnauthorized)
		return
	}
	token := generateNewJWT(jwt.MapClaims{
		"user": username,
		"exp":  time.Now().Add(time.Millisecond * jwtmodels.TOKEN_TTL).Unix(),
	})
	c.Writer.Header().Set("Authorization", "Bearer "+token)
	c.JSON(http.StatusOK, jwtmodels.AuthToken{
		Type:  "Bearer",
		Token: token,
	})
}

func Refresh(c *gin.Context) {
	value, exists := c.Get("claims")
	if !exists {
		c.String(http.StatusBadRequest, "Token does not exist")
		return
	}
	if claims, ok := value.(jwt.MapClaims); ok {
		claims["exp"] = time.Now().Add(time.Second * jwtmodels.TOKEN_TTL).Unix()
		token := generateNewJWT(claims)
		c.Header("Authorization", "Bearer "+token)
		c.JSON(http.StatusOK, jwtmodels.AuthToken{
			Type:  "Bearer",
			Token: token,
		})
		return
	}
	c.String(http.StatusBadRequest, "Claims not valid")
}

func GetUsers(c *gin.Context) {
	users, err := services.FindAllUsers()
	if err != nil {
		fmt.Println("Error finding users: ", err)
		c.JSON(http.StatusNotFound, err)
		return
	}
	c.JSON(http.StatusOK, users)
}

func GetUserById(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}
	users, err := services.GetUserById(id)
	if err != nil {
		c.JSON(http.StatusNotFound, err)
		return
	}
	c.JSON(http.StatusOK, users)
}

func CreateUser(c *gin.Context) {
	var user models.User
	c.BindJSON(&user)
	user, err := services.CreateUser(user)
	if err != nil {
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}
	c.JSON(http.StatusCreated, user)
}

func UpdateUser(c *gin.Context) {
	var user models.User
	c.BindJSON(&user)
	user, err := services.UpdateUser(user)
	if err != nil {
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}
	c.JSON(http.StatusCreated, user)
}

func DeleteUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}
	user, err := services.DeleteUserById(id)
	if err != nil {
		c.JSON(http.StatusNotFound, err)
		return
	}
	c.JSON(http.StatusOK, user)
}

func GetRoles(c *gin.Context) {
	roles, err := services.FindAllRoles()
	if err != nil {
		fmt.Println("Error finding roles: ", err)
		c.JSON(http.StatusNotFound, err)
		return
	}
	c.JSON(http.StatusOK, roles)
}

func GetRoleById(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}
	role, err := services.GetRoleById(id)
	if err != nil {
		c.JSON(http.StatusNotFound, err)
		return
	}
	c.JSON(http.StatusOK, role)
}

func CreateRole(c *gin.Context) {
	var role models.Role
	c.BindJSON(&role)
	user, err := services.CreateRole(role)
	if err != nil {
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}
	c.JSON(http.StatusCreated, user)
}

func UpdateRole(c *gin.Context) {
	var role models.Role
	c.BindJSON(&role)
	user, err := services.UpdateRole(role)
	if err != nil {
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}
	c.JSON(http.StatusCreated, user)
}

func DeleteRole(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}
	role, err := services.DeleteRoleById(id)
	if err != nil {
		c.JSON(http.StatusNotFound, err)
		return
	}
	c.JSON(http.StatusOK, role)
}
