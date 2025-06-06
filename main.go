package main

import (
	"context"
	"log"
	"path/filepath"
	"time"

	"github.com/waldirborbajr/nfe/config"
	"github.com/waldirborbajr/nfe/repository"
	"github.com/waldirborbajr/nfe/routes"
	"github.com/waldirborbajr/nfe/server"
)

const sessionCleanupInterval = time.Hour

func main() {
	// Load configuration
	config, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("⚠ Erro ao carregar configuração: %v", err)
	}

	// Initialize repository (now returns repository.DB interface)
	db, err := repository.NewDBConnSQLite("database.db")
	if err != nil {
		log.Fatalf("⚠ Erro ao inicializar banco de dados: %v", err)
	}
	defer db.Close()

	// Periodically clean up expired sessions using context
	go func() {
		ctx := context.Background()
		for {
			if err := db.CleanupExpiredSessions(ctx); err != nil {
				log.Printf("⚠ Erro ao limpar sessões expiradas: %v", err)
			}
			time.Sleep(sessionCleanupInterval)
		}
	}()

	// Use routes package to get the mux/router with security middleware applied
	handlerWithSecurity := routes.NewRouter(db, config)

	if config.Production {
		certPath := filepath.Join("certs", "server.crt")
		keyPath := filepath.Join("certs", "server.key")
		srv := server.CreateNFeHTTPServer(":4043", handlerWithSecurity)
		server.RunNFeServer(srv, true, certPath, keyPath)
	} else {
		srv := server.CreateNFeHTTPServer(":8080", handlerWithSecurity)
		server.RunNFeServer(srv, false, "", "")
	}
}
