package services

import (
	"errors"
	"time"
	"github.com/google/uuid"

	"github.com/Aniekan210/auth-service/internal"
	"github.com/Aniekan210/auth-service/internal/db"
	"github.com/Aniekan210/auth-service/pkg"
)

func CreateUser(email string, password string) (*internal.User, error) {
	// make new user struct
	newUser := internal.User{}

	// check if user exists
	existingUser, _ := db.FindUserByEmail(email)
	if existingUser != nil {
		return nil, errors.New("user already exists, please log in")
	}

	// hash password
	passwordHash, err := pkg.HashPassword(password)
	if err != nil {
		return nil, errors.New("something went wrong")
	}

	// fill in use data
	newUser.Email = email
	newUser.HashedPassword = passwordHash
	newUser.Role = internal.RoleUser
	newUser.EmailConfirmed = false
	newUser.EmailConfirmationToken = uuid.NewString()
	newUser.CreatedAt = time.Now()
	newUser.LastSignedIn = time.Now()

	// create user
	err = db.CreateUser(&newUser)
	if err != nil {
		return nil, errors.New("something went wrong")
	}

	return &newUser, nil
}