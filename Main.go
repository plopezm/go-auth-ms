package main

import (
	"github.com/gin-gonic/gin"
	"github.com/plopezm/go-auth-ms/security"
)

var router *gin.Engine

func init()  {
	router = gin.Default()
	router.GET("/login", security.BasicAuth(Login))
	router.GET("/verify", security.BearerAuth(Verify))
	router.GET("/refresh", security.BearerAuth(Refresh))
	router.GET("/pubkey", GetPublicKey)
}

func GetMainEngine() *gin.Engine {
	return router
}

func main() {
	GetMainEngine().Run("0.0.0.0:9090")
}
