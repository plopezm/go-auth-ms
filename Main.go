package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"github.com/plopezm/go-auth-ms/models"
	"github.com/plopezm/go-auth-ms/resources"
	"github.com/plopezm/go-auth-ms/security"
	"github.com/plopezm/goedb"
)

var router *gin.Engine

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		//fmt.Println("Generating CORS headers")
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

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	goedb.Initialize()

	em, err := goedb.GetEntityManager("testing")
	checkError(err)
	err = em.Migrate(&models.Role{}, true, true)
	//checkError(err)
	err = em.Migrate(&models.Permission{}, true, true)
	//checkError(err)
	err = em.Migrate(&models.User{}, true, true)
	//checkError(err)

	role := &models.Role{
		Name:        "Admin",
		Description: "Full access role",
	}
	result, err := em.Insert(role)
	checkError(err)
	//checkError(err)
	role.ID = int(result.LastInsertId)

	permission := &models.Permission{
		Name:        "sysadmin",
		Description: "Full access",
		Role:        *role,
	}
	_, err = em.Insert(permission)
	//checkError(err)

	user := &models.User{
		Email:    "admin",
		Password: "admin",
		Role:     *role,
	}
	_, err = em.Insert(user)
	//checkError(err)
}

func parseCommandInput(args []string) (port string, secure bool) {
	port = "80"
	secure = false

	for _, arg := range args {
		if strings.HasPrefix(arg, "https") {
			secure = true
			if port == "80" {
				port = "443"
			}
		}
		if strings.HasPrefix(arg, "p=") {
			port = strings.TrimPrefix(arg, "p=")
		}
	}
	return port, secure
}

func main() {
	port, secure := parseCommandInput(os.Args)

	router = gin.Default()
	router.Use(CORSMiddleware())
	v1 := router.Group("/api/v1")
	v1.GET("/login", security.BasicAuth(resources.Login))
	//v1.GET("/verify", security.BearerAuth(Verify))
	v1.GET("/refresh", security.BearerAuth(resources.Refresh))
	v1.GET("/pubkey", resources.GetPublicKey)
	v1.GET("/users", security.BearerAuth(resources.GetUsers))
	v1.GET("/users/:id", security.BearerAuth(resources.GetUserById))
	v1.POST("/users", security.BearerAuth(resources.CreateUser))
	v1.PUT("/users", security.BearerAuth(resources.UpdateUser))
	v1.DELETE("/users/:id", security.BearerAuth(resources.DeleteUser))
	v1.GET("/roles", security.BearerAuth(resources.GetRoles))
	v1.GET("/roles/:id", security.BearerAuth(resources.GetRoleById))
	v1.POST("/roles", security.BearerAuth(resources.CreateRole))
	v1.PUT("/roles", security.BearerAuth(resources.UpdateRole))
	v1.DELETE("/roles/:id", security.BearerAuth(resources.DeleteRole))

	log.Println("Launching server at port", port, "with security", secure)

	if secure {
		log.Fatal(http.ListenAndServeTLS("0.0.0.0:"+port, "server.crt", "server.key", router))
	} else {
		http.ListenAndServe("0.0.0.0:"+port, router)
	}
}
