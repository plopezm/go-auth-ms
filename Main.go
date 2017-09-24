package main

import (
	"github.com/gin-gonic/gin"
	"github.com/plopezm/go-auth-ms/security"
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

func init()  {
	router = gin.Default()
	router.GET("/login", security.BasicAuth(Login))
	router.GET("/verify", security.BearerAuth(Verify))
	router.GET("/refresh", security.BearerAuth(Refresh))
	router.GET("/pubkey", GetPublicKey)

	router.Use(CORSMiddleware())
}

func GetMainEngine() *gin.Engine {
	return router
}

func main() {
	GetMainEngine().Run("0.0.0.0:9090")
}
