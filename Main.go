package main

import (
	"github.com/gin-gonic/gin"
	"github.com/plopezm/go-auth-ms/security"
	_ "github.com/mattn/go-sqlite3"
	"github.com/plopezm/goedb"
	"fmt"
	"os"
	"github.com/plopezm/go-auth-ms/services"
)

var router *gin.Engine

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func checkError(err error){
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init(){
	goedb.Initialize()

	em, err := goedb.GetEntityManager("testing")
	checkError(err)
	err = em.Migrate(&services.Role{})
	//checkError(err)
	err = em.Migrate(&services.User{})
	//checkError(err)

	role := &services.Role{
		Name: "Admin",
	}

	_, err = em.Insert(role)
	//checkError(err)
	em.First(role, "Role.Name = :name", map[string]interface{}{
		"name": "Admin",
	})

	user := &services.User{
		Email: "admin",
		Password: "admin",
		Role: *role,
	}

	_, err = em.Insert(user)
	//checkError(err)
}

func main() {
	router = gin.Default()
	router.GET("/login", security.BasicAuth(Login))
	router.GET("/verify", security.BearerAuth(Verify))
	router.GET("/refresh", security.BearerAuth(Refresh))
	router.GET("/pubkey", GetPublicKey)

	router.Use(CORSMiddleware())
	router.Run("0.0.0.0:9090")
}
