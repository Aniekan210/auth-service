package handlers

import (
	"net/http"

	"github.com/Aniekan210/auth-service/internal/services"
	"github.com/Aniekan210/auth-service/pkg"
	"github.com/gin-gonic/gin"
)

func Register(c *gin.Context) {
	// get request body
	type request struct {
		Email     string `json:"email" binding:"required"`
		Password  string `json:"password" binding:"required"`
		Device    string `json:"device" binding:"required"`
		IpAddress string `json:"ip_address" binding:"required"`
	}
	body := request{}
	err := c.ShouldBindBodyWithJSON(&body)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "please try again.",
		})
		return
	}

	// validate request body
	err = services.ValidateEmail(body.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	err = services.ValidatePassword(body.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// create user
	user, err := services.CreateUser(body.Email, body.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// create access token
	accessToken, err := pkg.GenerateAccessToken(user.UserId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// create refresh token
	refreshToken, err := services.CreateRefreshToken(user.UserId, body.Device, body.IpAddress)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// response {access_token, refresh_token, email_confirmation_token}
	c.JSON(http.StatusCreated, gin.H{
		"access_token":             accessToken,
		"refresh_token":            refreshToken,
		"email_confirmation_token": user.EmailConfirmationToken,
		"message":                  "signup successful",
	})
}

func Login(c *gin.Context) {
	// get request body
	type request struct {
		Email     string `json:"email" binding:"required"`
		Password  string `json:"password" binding:"required"`
		Device    string `json:"device" binding:"required"`
		IpAddress string `json:"ip_address" binding:"required"`
	}
	body := request{}
	err := c.ShouldBindBodyWithJSON(&body)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "please try again.",
		})
		return
	}

	// validate request body
	err = services.ValidateEmail(body.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// log user in
	user, err := services.Login(body.Email, body.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// create access token
	accessToken, err := pkg.GenerateAccessToken(user.UserId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// create refresh token
	refreshToken, err := services.CreateRefreshToken(user.UserId, body.Device, body.IpAddress)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// response {access_token, refresh_token}
	c.JSON(http.StatusCreated, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"message":       "login successful",
	})
}

func Logout(c *gin.Context) {
	type request struct {
		Token string `json:"refresh_token" binding:"required"`
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
	_, err = services.VerifyRefreshToken(body.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}

	// revoke refresh token
	err = services.RevokeRefreshToken(body.Token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "logout successful",
	})
}

func ForgotPassword(c *gin.Context) {
	// get email
	type request struct {
		Email string `json:"email" binding:"required"`
	}
	body := request{}
	err := c.ShouldBindBodyWithJSON(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "email is required",
		})
		return
	}

	// validate email
	err = services.ValidateEmail(body.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// get password reset token
	passwordResetToken, err := services.CreatePasswordResetToken(body.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"password_reset_token": passwordResetToken,
		"message":              "reset token granted",
	})

}

func ResetPassword(c *gin.Context) {
	// get request
	type request struct {
		NewPassword string
		ResetToken  string
	}
	body := request{}
	err := c.ShouldBindBodyWithJSON(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	// validate new password
	err = services.ValidatePassword(body.NewPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// validate reset token
	claims, err := pkg.ValidatePasswordToken(body.ResetToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "unauthorized",
		})
		return
	}

	// parse claims for user id
	userId, err := claims.GetSubject()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid token",
		})
		return
	}

	// change password
	err = services.ResetPassword(body.NewPassword, userId)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "password reset successfully",
	})
}
