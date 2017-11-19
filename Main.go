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
	"github.com/plopezm/go-auth-ms/services"
	"github.com/plopezm/goedb"
	"github.com/plopezm/gosm/gingonic/cors"
	"github.com/plopezm/gosm/gingonic/security/basic"
	"github.com/plopezm/gosm/gingonic/security/jwt"
	"github.com/plopezm/gosm/gingonic/support"
)

var router *gin.Engine

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
	router.Use(cors.Middleware("http://localhost:3000",
		"Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With",
		"OPTIONS, GET, POST, PUT, DELETE",
		true,
		86400))

	// privKey, publicKey, jwkInfo := rsa.GetJWTKeys("go-auth", "jwkpriv.pem", "jwkpub.pem")
	services.JWTPrivateKey, services.JWTPublicKey, services.JWKInfoToken = support.GetJWTKeys("go-auth", "jwkpriv.pem", "jwkpub.pem")

	v1 := router.Group("/api/v1")
	v1.GET("/login", basic.AuthMiddleware(resources.Login, services.ValidateUser))
	v1.GET("/refresh", jwt.BearerAuthMiddleware(resources.Refresh, services.JWTPrivateKey, services.JWTPublicKey))
	v1.GET("/pubkey", resources.GetPublicKey)
	v1.GET("/users", jwt.BearerAuthMiddleware(resources.GetUsers, services.JWTPrivateKey, services.JWTPublicKey))
	v1.GET("/users/:id", jwt.BearerAuthMiddleware(resources.GetUserById, services.JWTPrivateKey, services.JWTPublicKey))
	v1.POST("/users", jwt.BearerAuthMiddleware(resources.CreateUser, services.JWTPrivateKey, services.JWTPublicKey))
	v1.PUT("/users", jwt.BearerAuthMiddleware(resources.UpdateUser, services.JWTPrivateKey, services.JWTPublicKey))
	v1.DELETE("/users/:id", jwt.BearerAuthMiddleware(resources.DeleteUser, services.JWTPrivateKey, services.JWTPublicKey))
	v1.GET("/roles", jwt.BearerAuthMiddleware(resources.GetRoles, services.JWTPrivateKey, services.JWTPublicKey))
	v1.GET("/roles/:id", jwt.BearerAuthMiddleware(resources.GetRoleById, services.JWTPrivateKey, services.JWTPublicKey))
	v1.POST("/roles", jwt.BearerAuthMiddleware(resources.CreateRole, services.JWTPrivateKey, services.JWTPublicKey))
	v1.PUT("/roles", jwt.BearerAuthMiddleware(resources.UpdateRole, services.JWTPrivateKey, services.JWTPublicKey))
	v1.DELETE("/roles/:id", jwt.BearerAuthMiddleware(resources.DeleteRole, services.JWTPrivateKey, services.JWTPublicKey))

	log.Println("Launching server at port", port, "with security", secure)

	if secure {
		log.Fatal(http.ListenAndServeTLS("0.0.0.0:"+port, "server.crt", "server.key", router))
	} else {
		http.ListenAndServe("0.0.0.0:"+port, router)
	}
}
