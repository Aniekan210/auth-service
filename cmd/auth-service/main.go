package main

import (
	"net/http"

	"github.com/Aniekan210/auth-service/internal/db"
	"github.com/gin-gonic/gin"
)

func main() {
	// open db connection
	err := db.Init("./test.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// start server
	router := gin.Default()

	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})

	router.Run() // listen and serve on 0.0.0.0:8080
}
