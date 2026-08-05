package server

import (
	"crypto/rand"
	"encoding/base64"
	"io"
)

// authorizationCodeSize and refreshTokenSize are the byte lengths of a
// generated authorization code / refresh token — 256 bits each.
const (
	authorizationCodeSize = 32
	refreshTokenSize      = 32
)

func generateAuthorizationCode(random io.Reader) (string, error) {
	return generateRandomToken(random, authorizationCodeSize)
}

func generateRefreshToken(random io.Reader) (string, error) {
	return generateRandomToken(random, refreshTokenSize)
}

func generateRandomToken(random io.Reader, size int) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
