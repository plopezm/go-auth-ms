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
		fmt.Println("Generating CORS headers")
		c.Writer.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET, POST, PUT, DELETE")
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


func AddAuthRoutes(router *gin.Engine){
}



func main() {
	router = gin.Default()
	router.Use(CORSMiddleware())
	v1 := router.Group("/api/v1")
	v1.GET("/login", security.BasicAuth(Login))
	v1.GET("/verify", security.BearerAuth(Verify))
	v1.GET("/refresh", security.BearerAuth(Refresh))
	v1.GET("/pubkey", GetPublicKey)
	v1.GET("/users", security.BearerAuth(GetUsers))
	v1.GET("/users/:id", security.BearerAuth(GetUserById))
	router.Run("0.0.0.0:9090")
}
