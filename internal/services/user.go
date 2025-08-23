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

func Login(email string, unHashedPassword string) (*internal.User, error) {

	// check if user exists
	existingUser, _ := db.FindUserByEmail(email)
	if existingUser == nil {
		return nil, errors.New("no user, please sign up")
	}

	// compare to hashed password
	err := pkg.ComparePasswordAndHash(unHashedPassword, existingUser.HashedPassword)
	if err != nil {
		return nil, errors.New("password does not match")
	}

	return existingUser, nil
}

func CreatePasswordResetToken(email string) (string, error) {
	// verify user existence
	user, err := db.FindUserByEmail(email)
	if user == nil {
		return "", errors.New("user does not exist")
	}
	if err != nil {
		return "", errors.New("an error occurred")
	}

	// create password reset token
	passwordResetToken, err := pkg.GeneratePasswordToken(user.UserId)
	if err != nil {
		return "", errors.New("error creating token")
	}

	return passwordResetToken, nil
}

func ResetPassword(newPassword string, userId string) error {
	// hash password
	hashedPassword, err := pkg.HashPassword(newPassword)
	if err != nil {
		return errors.New("an error occurred")
	}

	// change password
	err = db.UpdatePassword(hashedPassword, userId)
	if err != nil {
		return errors.New("error updating password")
	}

	return nil
}
