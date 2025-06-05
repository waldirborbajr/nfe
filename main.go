package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/waldirborbajr/nfe/database"
	"github.com/waldirborbajr/nfe/entity"
	"github.com/waldirborbajr/nfe/handler"
	"gopkg.in/yaml.v3"
)

func loadConfig() (entity.Config, error) {
	data, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		return entity.Config{}, fmt.Errorf("erro ao ler config.yaml: %v", err)
	}

	var config entity.Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return entity.Config{}, fmt.Errorf("erro ao parsear config.yaml: %v", err)
	}

	return config, nil
}

func main() {
	// Load configuration
	config, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	// Initialize database
	db, err := database.NewDBConn("database.db")
	if err != nil {
		log.Fatal("Erro ao inicializar banco de dados: ", err)
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
	mux.HandleFunc("/login", handler.LoginHandler(db, config))
	mux.HandleFunc("/login/submit", handler.LoginSubmitHandler(db))
	mux.HandleFunc("/logout", handler.LogoutHandler(db))
	mux.HandleFunc("/", handler.IndexHandler(db))
	mux.HandleFunc("/upload", handler.UploadHandler(config, db))

	// Apply secure headers middleware
	securedHandler := handler.SecureHeadersMiddleware(mux, config)

	// Start server based on production mode
	if config.Production {
		var wg sync.WaitGroup
		wg.Add(1)

		server := &http.Server{
			Addr:    ":8043",
			Handler: securedHandler,
		}
		log.Println("Servidor HTTPS rodando na porta 8043...")
		if err := server.ListenAndServeTLS("certs/server.crt", "certs/server.key"); err != nil {
			log.Fatal("Erro ao iniciar servidor HTTPS: ", err)
		}
	} else {
		server := &http.Server{
			Addr:    ":8080",
			Handler: securedHandler,
		}
		log.Println("Servidor HTTP rodando na porta 8080 (modo desenvolvimento)...")
		if err := server.ListenAndServe(); err != nil {
			log.Fatal("Erro ao iniciar servidor HTTP: ", err)
		}
	}
}
