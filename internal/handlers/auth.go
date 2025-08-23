package handlers

import (
	"net/http"
	"strings"

	"github.com/Aniekan210/auth-service/internal/services"
	"github.com/Aniekan210/auth-service/pkg"
	"github.com/gin-gonic/gin"
)

func Authenticate(c *gin.Context) {

	// get authorization header
	authHeader := c.GetHeader("Authorization")
	accessToken := func() string {
		parts := strings.Split(authHeader, " ")
		if len(parts) > 1 {
			return parts[1]
		}
		return ""
	}()

	if accessToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "no authorization token given",
		})
		return
	}

	// validate access token
	_, err := pkg.ValidateAccessToken(accessToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Unauthorized",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "authenticated successfully",
	})

}

func Reauthenticate(c *gin.Context) {
	// get token from request
	type request struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	body := request{}
	err := c.ShouldBindBodyWithJSON(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "no token provided",
		})
		return
	}

	// validate refresh token 
	claims, err := services.VerifyRefreshToken(body.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "unauthorized",
		})
		return
	}

	// parse claims
	userId, err := claims.GetSubject()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid token",
		})
		return
	}

	// give new access token
	accessToken, err := pkg.GenerateAccessToken(userId)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "an error occurred",
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"message": "access token granted",
	})
}
