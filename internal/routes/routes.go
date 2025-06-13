package routes

import (
	"net/http"

	"github.com/waldirborbajr/nfe/internal/config"
	"github.com/waldirborbajr/nfe/internal/handler"
	"github.com/waldirborbajr/nfe/internal/repository"
)

// SecureHeadersMiddleware adds security headers to all responses.
func SecureHeadersMiddleware(next http.Handler, config config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Add more headers as needed, possibly using config
		next.ServeHTTP(w, r)
	})
}

func NewRouter(db repository.DB, config config.Config) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	sqliteDB, ok := db.(*repository.SQLiteDBRepository)
	if !ok {
		panic("db is not a *repository.SQLiteDBRepository")
	}
	mux.HandleFunc("/login", handler.LoginHandler(sqliteDB, config))
	mux.HandleFunc("/login/submit", handler.LoginSubmitHandler(sqliteDB, config))
	mux.HandleFunc("/logout", handler.LogoutHandler(sqliteDB, config))
	mux.HandleFunc("/", handler.IndexHandler(sqliteDB))
	mux.HandleFunc("/upload", handler.UploadHandler(config, sqliteDB))
	return SecureHeadersMiddleware(mux, config)
}
