package internal

import (
	"time"
)

type User struct {
	UserId                 string
	Email                  string
	HashedPassword         []byte
	Role                   Role
	EmailConfirmed         bool
	EmailConfirmationToken string
	CreatedAt              time.Time
	LastSignedIn           time.Time
}

type Role string

const (
	RoleAdmin    Role = "ADMIN"
	RoleUser     Role = "USER"
	RoleEmployee Role = "EMPLOYEE"
)

type Session struct {
	SessionId    string
	UserId       string
	RefreshToken string
	Device       string
	IpAddress    string
	ExpiryDate   string
	CreatedAt    string
}
