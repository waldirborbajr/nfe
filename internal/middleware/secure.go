package middleware

import (
	"net/http"

	"github.com/waldirborbajr/nfe/internal/config"
)

// SecureHeadersMiddleware is a middleware that sets various HTTP security headers on the response.
// In production mode, it enforces strict transport security and a restrictive Content Security Policy (CSP).
// In non-production mode, it sets a more permissive CSP to facilitate development.
// The middleware also sets headers to prevent MIME sniffing, clickjacking, and cross-site scripting (XSS) attacks.
// It takes the next http.Handler to call and a configuration struct to determine the environment.
func SecureHeadersMiddleware(next http.Handler, config config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.Production {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			csp := "default-src 'self'; script-src 'self' " +
				"https://cdn.jsdelivr.net " +
				"https://cdn.tailwindcss.com " +
				"https://unpkg.com; style-src 'self' " +
				"https://cdn.tailwindcss.com; img-src 'self' " +
				"connect-src 'self'"
			w.Header().Set("Content-Security-Policy", csp)
		} else {
			csp := "default-src 'self' 'unsafe-inline' 'unsafe-eval' " +
				"https://cdn.tailwindcss.com " +
				"https://unpkg.com " +
				"https://cdn.jsdelivr.net " +
				"https://cdnjs.cloudflare.com"
			w.Header().Set("Content-Security-Policy", csp)
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}
