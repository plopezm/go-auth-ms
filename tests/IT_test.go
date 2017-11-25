package tests

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plopezm/gosm/gingonic/rsastore"

	"github.com/plopezm/gosm/gingonic/security"

	"github.com/gin-gonic/gin"
	"github.com/plopezm/go-auth-ms/resources"
	"github.com/plopezm/go-auth-ms/services"
	"github.com/stretchr/testify/assert"
)

func init() {
	services.Keystore = rsastore.GetJWTKeys("go-auth", "jwkpriv.pem", "jwkpub.pem")
}

func TestGetPublicKey(t *testing.T) {
	req, _ := http.NewRequest("GET", "/pubkey", nil)
	w := httptest.NewRecorder()

	r := gin.Default()
	r.GET("/pubkey", resources.GetPublicKey)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLoginNotAuthorized(t *testing.T) {
	req, _ := http.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()

	r := gin.Default()
	r.GET("/login", security.BasicAuthMiddleware(resources.Login, services.ValidateUser))
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLoginUnauthorized(t *testing.T) {
	req, _ := http.NewRequest("GET", "/login", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:notAuth")))
	w := httptest.NewRecorder()

	r := gin.Default()
	r.GET("/login", security.BasicAuthMiddleware(resources.Login, services.ValidateUser))
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogin(t *testing.T) {
	req, _ := http.NewRequest("GET", "/login", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:admin")))
	w := httptest.NewRecorder()

	r := gin.Default()
	r.GET("/login", security.BasicAuthMiddleware(resources.Login, services.ValidateUser))
	r.GET("/refresh", security.JwtRsaBearerAuthMiddleware(resources.GetUserById, services.Keystore))
	r.ServeHTTP(w, req)

	var token resources.AuthToken
	json.Unmarshal(w.Body.Bytes(), &token)

	assert.Equal(t, "Bearer", token.Type)
	assert.NotNil(t, token.Token)
	assert.NotEqual(t, "", token.Token)
	assert.Equal(t, http.StatusOK, w.Code)

	refreshReq, _ := http.NewRequest("GET", "/refresh", nil)
	refreshReq.Header.Set("Authorization", "Bearer "+token.Token)
	w = httptest.NewRecorder()

	assert.Equal(t, http.StatusOK, w.Code)
}
