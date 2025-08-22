package handlers

import (
	"net/http"

	"github.com/Aniekan210/auth-service/internal/services"
	"github.com/gin-gonic/gin"
)

func Register(c *gin.Context) {

	// get request body
	type request struct {
		Email       string `json:"email" binding:"required"`
		Password    string `json:"password" binding:"required"`
		Device_name string `json:"device_name" binding:"required"`
		Ip_address  string `json:"ip_address" binding:"required"`
	}
	body := request{}
	err := c.ShouldBindBodyWithJSON(&body)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "please try again.",
		})
	}

	// validate request body
	err = services.ValidateEmail(body.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
	}

	err = services.ValidatePassword(body.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
	}

	// create user
	// user, err := services.CreateUser(body.Email, body.Password)
	_, err = services.CreateUser(body.Email, body.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
	}

	// create access token

	// create refresh token

	// response

}
