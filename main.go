package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/waldirborbajr/nfe/entity"
	"github.com/waldirborbajr/nfe/handler"
	"github.com/waldirborbajr/nfe/repository"
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

	// Initialize repository (now returns repository.DB interface)
	db, err := repository.NewDBConnSQLite("database.db")
	if err != nil {
		log.Fatalf("Erro ao inicializar banco de dados: %v", err)
	}
	defer db.Close()

	// Periodically clean up expired sessions using context
	go func() {
		ctx := context.Background()
		for {
			if err := db.CleanupExpiredSessions(ctx); err != nil {
				log.Printf("Erro ao limpar sessões expiradas: %v", err)
			}
			time.Sleep(sessionCleanupInterval)
		}
	}()

	// Configure router
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("/login", handler.LoginHandler(db.(*repository.SQLiteDBRepository), config))
	mux.HandleFunc("/login/submit", handler.LoginSubmitHandler(db.(*repository.SQLiteDBRepository), config))
	mux.HandleFunc("/logout", handler.LogoutHandler(db.(*repository.SQLiteDBRepository), config))
	mux.HandleFunc("/", handler.IndexHandler(db.(*repository.SQLiteDBRepository)))
	mux.HandleFunc("/upload", handler.UploadHandler(config, db.(*repository.SQLiteDBRepository)))
	mux.HandleFunc("/import", handler.ImportNFeHandler(db.(*repository.SQLiteDBRepository)))

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
			Addr:           ":8080",
			ReadTimeout:    60 * time.Second,
			WriteTimeout:   60 * time.Second,
			MaxHeaderBytes: 1 << 16,
			Handler:        securedHandler,
		}
		log.Println("Servidor HTTP rodando na porta 8080 (modo desenvolvimento)...")
		log.Fatalf("Erro ao iniciar servidor HTTP: %v", server.ListenAndServe())
	}
}
