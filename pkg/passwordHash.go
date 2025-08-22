package pkg

import (
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) ([]byte, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 16)
	return hashedPassword, err
}

func ComparePasswordAndHash(passwordGiven string, passwordHash []byte) error {
	return bcrypt.CompareHashAndPassword(passwordHash, []byte(passwordGiven))
}
