package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/waldirborbajr/nfe/config"
	"github.com/waldirborbajr/nfe/repository"
	"github.com/waldirborbajr/nfe/routes"
)

const sessionCleanupInterval = time.Hour

func createHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
		ErrorLog:          log.New(os.Stderr, "http: ", log.LstdFlags),
	}
}

func runServer(server *http.Server, useTLS bool, certPath, keyPath string) {
	// Start server in goroutine
	go func() {
		log.Printf("Servidor rodando na porta %s...", server.Addr)
		var err error
		if useTLS {
			err = server.ListenAndServeTLS(certPath, keyPath)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Erro ao iniciar servidor: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	log.Println("Desligando servidor...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	log.Println("Servidor finalizado")
}

func main() {
	// Load configuration
	config, err := config.LoadConfig()
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

	// Use routes package to get the mux/router with security middleware applied
	handlerWithSecurity := routes.NewRouter(db, config)

	if config.Production {
		certPath := filepath.Join("certs", "server.crt")
		keyPath := filepath.Join("certs", "server.key")
		server := createHTTPServer(":4043", handlerWithSecurity)
		runServer(server, true, certPath, keyPath)
	} else {
		server := createHTTPServer(":8080", handlerWithSecurity)
		runServer(server, false, "", "")
	}
}
