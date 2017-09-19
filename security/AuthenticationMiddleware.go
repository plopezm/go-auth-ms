package security

import (
	"github.com/gin-gonic/gin"
	"strings"
	"net/http"
	"encoding/base64"
	"github.com/dgrijalva/jwt-go"
	"fmt"
)

type handler func(c *gin.Context)


func BasicAuth(ptr handler) gin.HandlerFunc{
	return func(c *gin.Context){
		auth := strings.SplitN(c.GetHeader("Authorization"), " ", 2)
		if len(auth) != 2 || auth[0] != "Basic" {
			c.Status(http.StatusUnauthorized)
			return
		}
		payload, _ := base64.StdEncoding.DecodeString(auth[1])
		pair := strings.SplitN(string(payload), ":", 2)

		if len(pair) != 2 || !validate(pair[0], pair[1]) {
			c.Status(http.StatusUnauthorized)
			return
		}
		ptr(c)
	}
}

func BearerAuth(ptr handler) gin.HandlerFunc {
	return func(c *gin.Context){
		tokenString := strings.SplitN(c.GetHeader("Authorization"), " ", 2)
		if len(tokenString) != 2 || tokenString[0] != "Bearer" {
			c.String(http.StatusUnauthorized, "Bearer header required")
			return
		}

		token, err := jwt.Parse(tokenString[1], func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
			return PublicKey, nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("claims", claims)
		} else {
			fmt.Println(err)
			c.String(http.StatusUnauthorized, "Token not valid: ", err)
			return
		}
		ptr(c)
	}
}

func validate(username, password string) bool {
	if username == "test" && password == "test" {
		return true
	}
	return false
}