package jwtmodels

// 24 hours
const TOKEN_TTL = 86400000

type AuthToken struct {
	Type  string `json:"type"`
	Token string `json:"token"`
}
