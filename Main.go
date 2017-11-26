package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/plopezm/gosm/gingonic/rsastore"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"github.com/plopezm/go-auth-ms/models"
	"github.com/plopezm/go-auth-ms/resources"
	"github.com/plopezm/go-auth-ms/services"
	"github.com/plopezm/goedb"
	"github.com/plopezm/gosm/gingonic/cors"
	"github.com/plopezm/gosm/gingonic/security"
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
	err = em.Migrate(&models.PermissionsGroup{}, true, true)
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
	}
	_, err = em.Insert(permission)
	//checkError(err)

	permissionGroup := &models.PermissionsGroup{
		Role:       *role,
		Permission: *permission,
	}
	_, err = em.Insert(permissionGroup)

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
	services.Keystore = rsastore.GetJWTKeys("go-auth", "jwkpriv.pem", "jwkpub.pem")

	v1 := router.Group("/api/v1")
	v1.GET("/login", security.BasicAuthMiddleware(resources.Login, services.ValidateUser))
	v1.GET("/refresh", security.JwtRsaBearerAuthMiddleware(resources.Refresh, services.Keystore))
	v1.GET("/pubkey", resources.GetPublicKey)
	v1.GET("/users", security.JwtRsaBearerAuthMiddleware(resources.GetUsers, services.Keystore))
	v1.GET("/users/:id", security.JwtRsaBearerAuthMiddleware(resources.GetUserById, services.Keystore))
	v1.POST("/users", security.JwtRsaBearerAuthMiddleware(resources.CreateUser, services.Keystore))
	v1.PUT("/users", security.JwtRsaBearerAuthMiddleware(resources.UpdateUser, services.Keystore))
	v1.DELETE("/users/:id", security.JwtRsaBearerAuthMiddleware(resources.DeleteUser, services.Keystore))
	v1.GET("/roles", security.JwtRsaBearerAuthMiddleware(resources.GetRoles, services.Keystore))
	v1.GET("/roles/:id", security.JwtRsaBearerAuthMiddleware(resources.GetRoleById, services.Keystore))
	v1.POST("/roles", security.JwtRsaBearerAuthMiddleware(resources.CreateRole, services.Keystore))
	v1.PUT("/roles", security.JwtRsaBearerAuthMiddleware(resources.UpdateRole, services.Keystore))
	v1.DELETE("/roles/:id", security.JwtRsaBearerAuthMiddleware(resources.DeleteRole, services.Keystore))
	v1.GET("/permissions", security.JwtRsaBearerAuthMiddleware(resources.GetPermissions, services.Keystore))
	v1.GET("/permissions/:id", security.JwtRsaBearerAuthMiddleware(resources.GetPermissionById, services.Keystore))
	v1.POST("/permissions", security.JwtRsaBearerAuthMiddleware(resources.CreatePermission, services.Keystore))
	v1.PUT("/permissions", security.JwtRsaBearerAuthMiddleware(resources.UpdatePermission, services.Keystore))
	v1.DELETE("/permissions/:id", security.JwtRsaBearerAuthMiddleware(resources.DeletePermission, services.Keystore))

	log.Println("Launching server at port", port, "with security", secure)
	if secure {
		log.Fatal(http.ListenAndServeTLS("0.0.0.0:"+port, "server.crt", "server.key", router))
	} else {
		http.ListenAndServe("0.0.0.0:"+port, router)
	}
}
