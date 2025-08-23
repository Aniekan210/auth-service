package pkg

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var accessTokenSecret = []byte(os.Getenv("ACCESS_SECRET"))
var refreshTokenSecret = []byte(os.Getenv("REFRESH_SECRET"))

// access token generation
func GenerateAccessToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(accessTokenSecret)
}

// access token validation
func ValidateAccessToken(accessToken string) (jwt.MapClaims, error) {
	return sharedValidate(accessToken, accessTokenSecret)
}

// refresh token creation
func GenerateRefreshToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(168 * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(refreshTokenSecret)
}

// refresh token validation
func ValidateRefreshToken(refreshToken string) (jwt.MapClaims, error) {
	return sharedValidate(refreshToken, refreshTokenSecret)
}

func sharedValidate(token string, secretKey []byte) (jwt.MapClaims, error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		// check alg
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return secretKey, nil
	})
	if err != nil {
		return nil, err
	}

	// extract claims
	if claims, ok := parsed.Claims.(jwt.MapClaims); ok && parsed.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
