package main

import (
	"database/sql"
	"fmt"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// DBConn holds the database connection
type DBConn struct {
	db *sql.DB
}

// User represents a user in the database
type User struct {
	ID      int
	Usuario string
	Senha   string // Hashed password
}

// NewDBConn initializes a new SQLite database connection
func NewDBConn(dbPath string) (*DBConn, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Create users table if it doesn't exist
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		usuario TEXT NOT NULL UNIQUE,
		senha TEXT NOT NULL
	);`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		db.Close()
		return nil, err
	}

	// Insert default user if not exists (for testing)
	defaultUser := User{
		Usuario: "admin",
		Senha:   "admin123", // Will be hashed
	}
	err = insertDefaultUser(db, defaultUser)
	if err != nil {
		db.Close()
		return nil, err
	}

	return &DBConn{db: db}, nil
}

// Close closes the database connection
func (conn *DBConn) Close() error {
	return conn.db.Close()
}

// insertDefaultUser inserts a default user if it doesn't exist
func insertDefaultUser(db *sql.DB, user User) error {
	// Check if user exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE usuario = ?", user.Usuario).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil // User already exists
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Senha), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Insert user
	_, err = db.Exec("INSERT INTO users (usuario, senha) VALUES (?, ?)", user.Usuario, hashedPassword)
	return err
}

// ValidateUser checks if the provided credentials are valid
func (conn *DBConn) ValidateUser(usuario, senha string) (User, error) {
	var user User
	err := conn.db.QueryRow("SELECT id, usuario, senha FROM users WHERE usuario = ?", usuario).Scan(&user.ID, &user.Usuario, &user.Senha)
	if err != nil {
		if err == sql.ErrNoRows {
			return User{}, fmt.Errorf("usuário não encontrado")
		}
		return User{}, err
	}

	// Compare hashed password
	err = bcrypt.CompareHashAndPassword([]byte(user.Senha), []byte(senha))
	if err != nil {
		return User{}, fmt.Errorf("senha incorreta")
	}

	return user, nil
}
