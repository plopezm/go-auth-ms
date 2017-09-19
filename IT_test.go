package main

import (
	"testing"
	"net/http"
	"github.com/stretchr/testify/assert"
	"encoding/base64"
	"strings"
	"net/http/httptest"
)

func TestLogin(t *testing.T){
	req, err := http.NewRequest("GET", "http://localhost:9090/login", nil)
	assert.Nil(t, err)
	assert.NotNil(t, req)

	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("test:test")))

	httptest.NewServer(GetMainEngine().Handl)

	client := &http.Client{}
	resp, err := client.Do(req)
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	defer resp.Body.Close()

	header := resp.Header.Get("Authorization")
	assert.NotNil(t, header)
	authHeader := strings.SplitN(header, " ", 2)
	assert.Equal(t, 2, len(authHeader))
}