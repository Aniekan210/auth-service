package main

import (
	"os"

	"github.com/Aniekan210/auth-service/internal/db"
	"github.com/Aniekan210/auth-service/internal/handlers"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {

	// Load .env file
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}

	// open db connection
	dbString := os.Getenv("DB_CONNECTION_STRING")
	err = db.Init(dbString)

	if err != nil {
		panic(err)
	}
	defer db.Close()

	// start server
	router := gin.Default()

	router.POST("/register", handlers.Register)
	router.POST("/login", handlers.Login)
	router.POST("/logout", handlers.Logout)

	router.GET("/authenticate", handlers.Authenticate)
	router.GET("/reauthenticate", handlers.Reauthenticate)

	router.Run() // listen and serve on 0.0.0.0:8080
}
