package db

import (
	"database/sql"
	"strconv"

	"github.com/Aniekan210/auth-service/internal"
	_ "github.com/mattn/go-sqlite3"
)

// change all this to postgres in production

var Conn *sql.DB // package-level global

func Init(dataSource string) error {
	var err error
	Conn, err = sql.Open("sqlite3", dataSource)
	if err != nil {
		return err
	}

	// Create users table
	createTablesSQL := `
	CREATE TABLE IF NOT EXISTS users (
		user_id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		hashed_password TEXT NOT NULL,
		role TEXT CHECK(role IN ('ADMIN', 'EMPLOYEE', 'USER')) NOT NULL DEFAULT 'USER',
		email_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
		email_confirmation_token TEXT,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_signed_in TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS sessions (
		session_id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		refresh_token TEXT NOT NULL,
		device TEXT,
		ip_address TEXT,
		expiry_date TIMESTAMP NOT NULL DEFAULT (datetime('now', '+7 days')),
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
	);
	`

	_, err = Conn.Exec(createTablesSQL)
	if err != nil {
		return err
	}

	return nil
}

func Close() error {
	if Conn != nil {
		return Conn.Close()
	}
	return nil
}

func FindUserByEmail(email string) (*internal.User, error) {
	var user internal.User

	row := Conn.QueryRow("SELECT * FROM users WHERE email=?", email)
	err := row.Scan(&user.UserId, &user.Email, &user.HashedPassword, &user.Role, &user.EmailConfirmed, &user.EmailConfirmationToken, &user.CreatedAt, &user.LastSignedIn)
	if err != nil {
		return nil, err
	}
	return &user, nil

}

func CreateUser(user *internal.User) error {
	res, err := Conn.Exec("INSERT INTO users (email, hashed_password, role, email_confirmed, email_confirmation_token, created_at, last_signed_in) VALUES (?, ?, ?, ?, ?, ?, ?)",
		user.Email, user.HashedPassword, user.Role, user.EmailConfirmed, user.EmailConfirmationToken, user.CreatedAt, user.LastSignedIn)
	if err != nil {
		return err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	user.UserId = strconv.FormatInt(id, 10)
	return nil
}

func CreateSession(s *internal.Session) error {

	_, err := Conn.Exec("INSERT INTO sessions (user_id, refresh_token, device, ip_address) VALUES (?, ?, ?, ?)", s.UserId, s.RefreshToken, s.Device, s.IpAddress)
	if err != nil {
		return err
	}

	return nil
}

func GetSession(refreshToken string) (*internal.Session, error) {
	var s internal.Session

	row := Conn.QueryRow("SELECT * FROM sessions WHERE refresh_token=?", refreshToken)
	err := row.Scan(&s.SessionId, &s.UserId, &s.RefreshToken, &s.Device, &s.IpAddress, &s.ExpiryDate, &s.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &s, nil
}

func DeleteSession(refreshToken string) error {

	_, err := Conn.Exec("DELETE FROM sessions WHERE refresh_token=?", refreshToken)
	if err != nil {
		return err
	}

	return nil
}
