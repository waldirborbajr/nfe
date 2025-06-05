package database

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// DBConn represents a database connection
type DBConn struct {
	db *sql.DB
}

// User represents a user in the database
type User struct {
	ID       int
	Username string
	Password string
}

// Session represents a user session
type Session struct {
	ID        string
	UserID    int
	CSRFToken string
	ExpiresAt time.Time
}

// NewDBConn initializes a new SQLite database connection
func NewDBConn(dbPath string) (*DBConn, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Create users table if it doesn't exist
	createUsersTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	);
	`
	_, err = db.Exec(createUsersTableSQL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create users table: %v", err)
	}

	// Check if username column exists and add it if missing
	var columnExists bool
	err = db.QueryRow(`
		SELECT EXISTS (
			SELECT 1
			FROM pragma_table_info('users')
			WHERE name = 'username'
		)
	`).Scan(&columnExists)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to check username column: %v", err)
	}
	if !columnExists {
		_, err = db.Exec("ALTER TABLE users ADD COLUMN username TEXT NOT NULL DEFAULT ''")
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to add username column: %v", err)
		}
		// Ensure uniqueness constraint (SQLite doesn't support adding UNIQUE via ALTER, so recreate table if needed)
		// For simplicity, we'll enforce uniqueness in application logic for existing users
	}

	// Create sessions table if it doesn't exist
	createSessionsTableSQL := `
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		csrf_token TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);
	`
	_, err = db.Exec(createSessionsTableSQL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create sessions table: %v", err)
	}

	// Insert default admin user if not exists
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to hash password: %v", err)
	}
	_, err = db.Exec("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", "admin", string(hashedPassword))
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to insert default user: %v", err)
	}

	// Update empty usernames to 'admin' for default user (in case column was just added)
	_, err = db.Exec("UPDATE users SET username = 'admin' WHERE username = '' AND password = ?", string(hashedPassword))
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to update default user username: %v", err)
	}

	return &DBConn{db: db}, nil
}

// Close closes the database connection
func (c *DBConn) Close() error {
	return c.db.Close()
}

// ValidateUser validates user login credentials
func (c *DBConn) ValidateUser(username, password string) (*User, error) {
	var user User
	err := c.db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("invalid username or password")
		}
		return nil, fmt.Errorf("failed to query user: %v", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, errors.New("invalid username or password")
	}

	return &user, nil
}

// CreateSession creates a new session
func (c *DBConn) CreateSession(userID int, sessionID, csrfToken string, expiresAt time.Time) error {
	_, err := c.db.Exec("INSERT INTO sessions (id, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
		sessionID, userID, csrfToken, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	return nil
}

// GetSession retrieves a session by ID
func (c *DBConn) GetSession(sessionID string) (*Session, error) {
	var session Session
	err := c.db.QueryRow("SELECT id, user_id, csrf_token, expires_at FROM sessions WHERE id = ?", sessionID).
		Scan(&session.ID, &session.UserID, &session.CSRFToken, &session.ExpiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("session not found")
		}
		return nil, fmt.Errorf("failed to query session: %v", err)
	}
	if session.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("session expired")
	}
	return &session, nil
}

// DeleteSession removes a session
func (c *DBConn) DeleteSession(sessionID string) error {
	_, err := c.db.Exec("DELETE FROM sessions WHERE id = ?", sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %v", err)
	}
	return nil
}

// CleanupExpiredSessions removes expired sessions
func (c *DBConn) CleanupExpiredSessions() error {
	_, err := c.db.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %v", err)
	}
	return nil
}
