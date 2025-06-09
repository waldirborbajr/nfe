package server

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func CreateNFeHTTPServer(addr string, handler http.Handler) *http.Server {
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

func RunNFeServer(server *http.Server, useTLS bool, certPath, keyPath string) {
	// Start server in goroutine
	go func() {
		log.Printf("🚀 Servidor rodando na porta %s...", server.Addr)
		var err error
		if useTLS {
			err = server.ListenAndServeTLS(certPath, keyPath)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("⚠ Erro ao iniciar servidor: %v", err)
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
		log.Fatalf("⚠ Server forced to shutdown: %v", err)
	}
	log.Println("Servidor finalizado")
}
