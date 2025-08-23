package services

import (
	"errors"

	"github.com/Aniekan210/auth-service/internal"
	"github.com/Aniekan210/auth-service/internal/db"
	"github.com/Aniekan210/auth-service/pkg"
)

func CreateRefreshToken(userId string, device string, ipAddress string) (string, error) {
	// create the token
	token, err := pkg.GenerateRefreshToken(userId)
	if err != nil {
		return "", err
	}

	//create token object
	rt := internal.Session{
		UserId:       userId,
		RefreshToken: token,
		Device:       device,
		IpAddress:    ipAddress,
	}

	// save in the session store
	err = db.CreateSession(&rt)
	if err != nil {
		return "", errors.New("error creating session")
	}

	return token, nil
}

func VerifyRefreshToken(token string) error {
	// is it signed and not expired?
	_, err := pkg.ValidateRefreshToken(token)
	if err != nil {
		return errors.New("invalid token")
	}

	// does it exist?
	_, err = db.GetSession(token)
	if err != nil {
		return errors.New("token does not exist")
	}

	return nil
}

func RevokeRefreshToken(token string) error {
	// delete session
	err := db.DeleteSession(token)
	if err != nil {
		return errors.New("an error occurred")
	}
	return nil
}
