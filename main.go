package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/waldirborbajr/nfe/database"
	"github.com/waldirborbajr/nfe/entity"
	"github.com/waldirborbajr/nfe/handler"
	"gopkg.in/yaml.v3"
)

const sessionCleanupInterval = time.Hour

func loadConfig() (entity.Config, error) {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		return entity.Config{}, fmt.Errorf("erro ao ler config.yaml: %w", err)
	}

	var config entity.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return entity.Config{}, fmt.Errorf("erro ao parsear config.yaml: %w", err)
	}

	return config, nil
}

func main() {
	// Load configuration
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Erro ao carregar configuração: %v", err)
	}

	// Initialize database
	db, err := database.NewDBConn("database.db")
	if err != nil {
		log.Fatalf("Erro ao inicializar banco de dados: %v", err)
	}
	defer db.Close()

	// Periodically clean up expired sessions
	go func() {
		for {
			if err := db.CleanupExpiredSessions(); err != nil {
				log.Printf("Erro ao limpar sessões expiradas: %v", err)
			}
			time.Sleep(sessionCleanupInterval)
		}
	}()

	// Configure router
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("/login", handler.LoginHandler(db, config))
	mux.HandleFunc("/login/submit", handler.LoginSubmitHandler(db, config))
	mux.HandleFunc("/logout", handler.LogoutHandler(db, config))
	mux.HandleFunc("/", handler.IndexHandler(db))
	mux.HandleFunc("/upload", handler.UploadHandler(config, db))

	// Apply secure headers middleware
	securedHandler := handler.SecureHeadersMiddleware(mux, config)

	if config.Production {
		var wg sync.WaitGroup
		wg.Add(1)
		go handler.RedirectHTTPToHTTPS(&wg)

		certPath := filepath.Join("certs", "server.crt")
		keyPath := filepath.Join("certs", "server.key")

		server := &http.Server{
			Addr:    ":4043",
			Handler: securedHandler,
		}
		log.Println("Servidor HTTPS rodando na porta 4043...")
		log.Fatalf("Erro ao iniciar servidor HTTPS: %v", server.ListenAndServeTLS(certPath, keyPath))
	} else {
		server := &http.Server{
			Addr:    ":8080",
			Handler: securedHandler,
		}
		log.Println("Servidor HTTP rodando na porta 8080 (modo desenvolvimento)...")
		log.Fatalf("Erro ao iniciar servidor HTTP: %v", server.ListenAndServe())
	}
}
