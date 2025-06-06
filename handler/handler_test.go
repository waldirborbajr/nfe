package handler

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/waldirborbajr/nfe/database"
	"github.com/waldirborbajr/nfe/entity"
)

// mockDBConn is a mock for database.DBConn
type mockDBConn struct {
	getSessionFunc func(sessionID string) (*database.Session, error)
}

func (m *mockDBConn) GetSession(sessionID string) (*database.Session, error) {
	if m.getSessionFunc != nil {
		return m.getSessionFunc(sessionID)
	}
	return nil, nil
}

// Other DBConn methods are not needed for LoginHandler tests

func TestLoginHandler_DBConnNil(t *testing.T) {
	handler := LoginHandler(nil, entity.Config{})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rr.Code)
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("Internal Server Error")) {
		t.Errorf("expected error message in response")
	}
}

func TestLoginHandler_MethodNotAllowed(t *testing.T) {
	db := &mockDBConn{}
	handler := LoginHandler(db, entity.Config{})
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rr.Code)
	}
}

func TestLoginHandler_AuthenticatedRedirect(t *testing.T) {
	db := &mockDBConn{
		getSessionFunc: func(sessionID string) (*database.Session, error) {
			return &database.Session{UserID: 1, CSRFToken: "token"}, nil
		},
	}
	handler := LoginHandler(db, entity.Config{})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "abc"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect status, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/" {
		t.Errorf("expected redirect to '/', got %s", loc)
	}
}

func TestLoginHandler_TemplateParseError(t *testing.T) {
	// Temporarily rename the template file if it exists
	orig := "templates/login.html"
	bak := "templates/login.html.bak"
	_ = os.Rename(orig, bak)
	defer os.Rename(bak, orig)

	db := &mockDBConn{}
	handler := LoginHandler(db, entity.Config{})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rr.Code)
	}
}

func TestLoginHandler_Success(t *testing.T) {
	// Create a temporary template file
	os.MkdirAll("templates", 0755)
	tmplContent := `<html><body>{{.Title}} - {{.CSRFToken}}</body></html>`
	err := os.WriteFile("templates/login.html", []byte(tmplContent), 0644)
	if err != nil {
		t.Fatalf("failed to write template: %v", err)
	}
	defer os.Remove("templates/login.html")

	db := &mockDBConn{
		getSessionFunc: func(sessionID string) (*database.Session, error) {
			return nil, errors.New("not found")
		},
	}
	handler := LoginHandler(db, entity.Config{})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	if !bytes.Contains(body, []byte("Login")) {
		t.Errorf("expected 'Login' in response body")
	}
	if rr.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("expected Content-Type 'text/html; charset=utf-8', got %s", rr.Header().Get("Content-Type"))
	}
}
