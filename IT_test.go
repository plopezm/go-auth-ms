package main

import (
	"testing"
	"net/http"
	"github.com/stretchr/testify/assert"
	"encoding/base64"
	"net/http/httptest"
	"github.com/gin-gonic/gin"
	"github.com/plopezm/go-auth-ms/security"
)

func TestGetPublicKey(t *testing.T) {
	req, _ := http.NewRequest("GET", "/pubkey", nil)
	w := httptest.NewRecorder()

	r := gin.Default()
	r.GET("/pubkey", GetPublicKey)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLoginNotAuthorized(t *testing.T) {
	req, _ := http.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()

	r := gin.Default()
	r.GET("/login", security.BasicAuth(Login))
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogin(t *testing.T) {
	req, _ := http.NewRequest("GET", "/login", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("test:test")))
	w := httptest.NewRecorder()

	r := gin.Default()
	r.GET("/login", security.BasicAuth(Login))
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}