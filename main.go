package main

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/waldirborbajr/nfe/database"
	"github.com/waldirborbajr/nfe/entity"
	"github.com/waldirborbajr/nfe/handler"
)

func main() {
	config := entity.Config{
		SefazURL: "https://nfe.sefazrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx",
	}

	// Initialize database
	db, err := database.NewDBConn("database.db")
	if err != nil {
		log.Fatalf("Erro ao inicializar banco de dados: %v", err)
	}
	defer db.Close()

	// Cleanup expired sessions periodically
	go func() {
		for {
			if err := db.CleanupExpiredSessions(); err != nil {
				log.Printf("Erro ao limpar sessões expiradas: %v", err)
			}
			time.Sleep(1 * time.Hour)
		}
	}()

	// Configure router
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("/login", handler.LoginHandler(db))
	mux.HandleFunc("/login/submit", handler.LoginSubmitHandler(db))
	mux.HandleFunc("/logout", handler.LogoutHandler(db))
	mux.HandleFunc("/", handler.IndexHandler(db))
	mux.HandleFunc("/upload", handler.UploadHandler(config, db))

	// Apply secure headers middleware
	securedHandler := handler.SecureHeadersMiddleware(mux)

	// Start HTTPS server
	var wg sync.WaitGroup
	wg.Add(1)
	go handler.RedirectHTTPToHTTPS(&wg)

	server := &http.Server{
		Addr:    ":8043",
		Handler: securedHandler,
	}
	log.Println("Servidor HTTPS rodando na porta 8043...")
	if err := server.ListenAndServeTLS("certs/server.crt", "certs/server.key"); err != nil {
		log.Fatalf("Erro ao iniciar servidor HTTPS: %v", err)
	}
}
