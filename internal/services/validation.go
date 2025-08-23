package services

import (
	"errors"
	"regexp"
)

func ValidateEmail(email string) error {
	// Check minimum length
	if len(email) < 5 {
		return errors.New("invalid email format")
	}

	// Simple regex pattern: something@something.something
	emailRegex := regexp.MustCompile(`^[^@]+@[^@]+\.[^@]+$`)
	if !emailRegex.MatchString(email) {
		return errors.New("invalid email format")
	}

	return nil
}

func ValidatePassword(password string) error {
	// Check minimum length
	if len(password) < 7 {
		return errors.New("password must be more than 8 characters long")
	}
	return nil
}
