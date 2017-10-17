package security

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/plopezm/go-auth-ms/services"
	"net/http"
	"strings"
	"time"
)

type handler func(c *gin.Context)

func sendUnauthorized(c *gin.Context, err error) {
	fmt.Println(err.Error())
	c.String(http.StatusUnauthorized, "Token not valid: ", err.Error())
	return
}

func BasicAuth(ptr gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		//setCORSEnabled(c)

		auth := strings.SplitN(c.GetHeader("Authorization"), " ", 2)
		if len(auth) != 2 || auth[0] != "Basic" {
			c.Status(http.StatusUnauthorized)
			return
		}
		payload, _ := base64.StdEncoding.DecodeString(auth[1])
		pair := strings.SplitN(string(payload), ":", 2)

		if len(pair) != 2 || !validateUser(c, pair[0], pair[1]) {
			c.Status(http.StatusUnauthorized)
			return
		}
		ptr(c)
	}
}

func getTokenRemainingValidity(timestamp interface{}) int {
	if validity, ok := timestamp.(float64); ok {
		tm := time.Unix(int64(validity), 0)
		remainer := tm.Sub(time.Now())
		if remainer > 0 {
			return int(remainer.Seconds())
		}
	}
	return -1
}

func BearerAuth(ptr gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		//setCORSEnabled(c)

		tokenString := strings.SplitN(c.GetHeader("Authorization"), " ", 2)
		if len(tokenString) != 2 || tokenString[0] != "Bearer" {
			c.String(http.StatusUnauthorized, "Bearer header required")
			return
		}

		token, err := jwt.Parse(tokenString[1], func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validateUser the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
			return PublicKey, nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			expires, ok := claims["exp"]
			if !ok {
				sendUnauthorized(c, errors.New("Token not valid"))
				return
			}

			if getTokenRemainingValidity(expires) == -1 {
				sendUnauthorized(c, errors.New("Token validity expired"))
				return
			}

			c.Set("claims", claims)
		} else {
			sendUnauthorized(c, err)
			return
		}
		ptr(c)
	}
}

func validateUser(c *gin.Context, username, password string) bool {

	user, err := services.GetUserByAccount(username, password)
	if err != nil {
		return false
	}
	c.Set("username", user.Email)
	return true
}
