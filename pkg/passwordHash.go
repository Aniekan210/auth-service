package pkg

import (
	//"os"
	//"strconv"

	"golang.org/x/crypto/bcrypt"
)

//var hashCost, _ = strconv.Atoi(os.Getenv("HASH_COST"))

func HashPassword(password string) ([]byte, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 5)
	return hashedPassword, err
}

func ComparePasswordAndHash(passwordGiven string, passwordHash []byte) error {
	return bcrypt.CompareHashAndPassword(passwordHash, []byte(passwordGiven))
}
