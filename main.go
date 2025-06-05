package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	// Import your database package
	database "github.com/waldirborbajr/nfe/database" // Adjust the import path as needed
)

// Config contém as configurações do sistema
type Config struct {
	SefazURL string // URL do webservice da SEFAZ (exemplo: SVRS)
}

// NFeResponse representa a resposta da API com informações da NF-e
type NFeResponse struct {
	ChaveNFe    string `json:"chave_nfe"`
	Status      string `json:"status"`
	Descricao   string `json:"descricao"`
	Emitente    string `json:"emitente,omitempty"`
	DataEmissao string `json:"data_emissao,omitempty"`
}

// TemplateData contém dados para renderizar o template HTML
type TemplateData struct {
	Title string
	JS    template.JS // Para o código JavaScript
	CSRF  string      // CSRF token for login form
}

// Session stores user session data
type Session struct {
	UserID    int
	ExpiresAt time.Time
}

// SessionStore manages in-memory sessions
type SessionStore struct {
	sessions map[string]Session
	mu       sync.RWMutex
}

// NewSessionStore initializes a new session store
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]Session),
	}
}

// CreateSession creates a new session
func (s *SessionStore) CreateSession(userID int) (string, error) {
	sessionID := generateSessionID()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = Session{
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	return sessionID, nil
}

// GetSession retrieves a session by ID
func (s *SessionStore) GetSession(sessionID string) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, exists := s.sessions[sessionID]
	if !exists || session.ExpiresAt.Before(time.Now()) {
		return Session{}, false
	}
	return session, true
}

// DeleteSession removes a session
func (s *SessionStore) DeleteSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// generateSessionID creates a random session ID
func generateSessionID() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("Erro ao gerar session ID: %v", err)
		return ""
	}
	return fmt.Sprintf("%x", b)
}

// generateCSRFToken creates a simple CSRF token
func generateCSRFToken() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("Erro ao gerar CSRF token: %v", err)
		return ""
	}
	return fmt.Sprintf("%x", b)
}

// loadCertificate carrega o certificado digital A1 do arquivo .pfx
func loadCertificate(certData []byte, certPassword string) (*tls.Certificate, error) {
	// Decodifica o arquivo .pfx
	block, _ := pem.Decode(certData)
	if block == nil {
		// Se não for PEM, assume que é um .pfx puro
		cert, err := tls.X509KeyPair(certData, []byte(certPassword))
		if err != nil {
			return nil, fmt.Errorf("erro ao decodificar o certificado .pfx: %v", err)
		}
		return &cert, nil
	}
	return nil, fmt.Errorf("formato de certificado não suportado")
}

// createTLSClient cria um cliente HTTP com o certificado digital
func createTLSClient(cert *tls.Certificate) *http.Client {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	return &http.Client{
		Transport: transport,
	}
}

// consultNFe realiza a consulta de uma NF-e no webservice da SEFAZ
func consultNFe(client *http.Client, sefazURL, chaveNFe string) (NFeResponse, error) {
	soapRequest := `<?xml version="1.0" encoding="UTF-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Header>
    <nfeCabecMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeConsultaProtocolo4">
      <cUF>35</cUF>
      <versaoDados>4.00</versaoDados>
    </nfeCabecMsg>
  </soap12:Header>
  <soap12:Body>
    <nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeConsultaProtocolo4">
      <consSitNFe versao="4.00" xmlns="http://www.portalfiscal.inf.br/nfe">
        <tpAmb>1</tpAmb>
        <xServ>CONSULTAR</xServ>
        <chNFe>` + chaveNFe + `</chNFe>
      </consSitNFe>
    </nfeDadosMsg>
  </soap12:Body>
</soap12:Envelope>`

	req, err := http.NewRequest("POST", sefazURL, strings.NewReader(soapRequest))
	if err != nil {
		return NFeResponse{}, fmt.Errorf("erro ao criar requisição: %v", err)
	}

	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	req.Header.Set("SOAPAction", "http://www.portalfiscal.inf.br/nfe/wsdl/NFeConsultaProtocolo4/nfeConsultaNF")

	resp, err := client.Do(req)
	if err != nil {
		return NFeResponse{}, fmt.Errorf("erro ao consultar NF-e: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return NFeResponse{}, fmt.Errorf("erro ao ler resposta: %v", err)
	}

	// Simulação de parsing (substitua por parsing real do XML retornado)
	nfe := NFeResponse{
		ChaveNFe:    chaveNFe,
		Status:      "Autorizada",
		Descricao:   "Nota fiscal autorizada com sucesso",
		Emitente:    "Empresa Exemplo LTDA",
		DataEmissao: "2025-06-05",
	}
	if strings.Contains(string(body), "Erro") {
		nfe.Status = "Erro"
		nfe.Descricao = "Falha na consulta da NF-e"
	}

	return nfe, nil
} // End of consultNFe

// uploadHandler handles certificate upload and NF-e consultation
func uploadHandler(config Config, sessions *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check authentication
		sessionID, err := r.Cookie("session_id")
		if err != nil || sessionID == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		_, authenticated := sessions.GetSession(sessionID.Value)
		if !authenticated {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		err = r.ParseMultipartForm(10 << 20) // 10 MB
		if err != nil {
			http.Error(w, "Erro ao parsear formulário", http.StatusBadRequest)
			return
		}

		file, _, err := r.FormFile("certificate")
		if err != nil {
			http.Error(w, "Erro ao obter certificado", http.StatusBadRequest)
			return
		}
		defer file.Close()

		certData, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, "Erro ao ler certificado", http.StatusBadRequest)
			return
		}

		certPassword := r.FormValue("password")
		if certPassword == "" {
			http.Error(w, "Senha do certificado é obrigatória", http.StatusBadRequest)
			return
		}

		cert, err := loadCertificate(certData, certPassword)
		if err != nil {
			http.Error(w, fmt.Sprintf("Erro ao carregar certificado: %v", err), http.StatusBadRequest)
			return
		}

		client := createTLSClient(cert)

		chavesNFe := []string{
			"35230612345678901234567890123456789012345678",
			"35230698765432109876543210987654321098765432",
		}

		var nfeResponses []NFeResponse
		for _, chave := range chavesNFe {
			nfe, err := consultNFe(client, config.SefazURL, chave)
			if err != nil {
				log.Printf("Erro ao consultar NF-e %s: %v", chave, err)
				continue
			}
			nfeResponses = append(nfeResponses, nfe)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(nfeResponses); err != nil {
			http.Error(w, "Erro ao codificar resposta JSON", http.StatusInternalServerError)
			return
		}
	} // End of inner function
} // End of uploadHandler

// loginHandler renders the login template
func loginHandler(sessions *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check if already authenticated
		sessionID, err := r.Cookie("session_id")
		if err == nil {
			if _, authenticated := sessions.GetSession(sessionID.Value); authenticated {
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
		}

		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			log.Printf("Erro ao parsear template: %v", err)
			http.Error(w, fmt.Sprintf("Erro ao parsear template: %v", err), http.StatusInternalServerError)
			return
		}

		jsPath := filepath.Join("templates", "login.js")
		jsContent, err := os.ReadFile(jsPath)
		if err != nil {
			log.Printf("Erro ao ler arquivo %s: %v", jsPath, err)
			http.Error(w, fmt.Sprintf("Erro ao ler arquivo JavaScript: %v", err), http.StatusInternalServerError)
			return
		}

		data := TemplateData{
			Title: "Login",
			JS:    template.JS(jsContent),
			CSRF:  generateCSRFToken(),
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("Erro ao renderizar template: %v", err)
			http.Error(w, fmt.Sprintf("Erro ao renderizar template: %v", err), http.StatusInternalServerError)
			return
		}
	} // End of inner function
} // End of loginHandler

// loginSubmitHandler processes login form submissions
func loginSubmitHandler(db *database.DBConn, sessions *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Erro ao parsear formulário", http.StatusBadRequest)
			return
		}

		usuario := r.FormValue("usuario")
		senha := r.FormValue("senha")
		csrf := r.FormValue("csrf")

		// Basic CSRF check (in production, use a more robust solution)
		if csrf == "" {
			http.Error(w, "CSRF token inválido", http.StatusBadRequest)
			return
		}

		user, err := db.ValidateUser(usuario, senha)
		if err != nil {
			http.Error(w, fmt.Sprintf("Erro de login: %v", err), http.StatusUnauthorized)
			return
		}

		// Create session
		sessionID, err := sessions.CreateSession(user.ID)
		if err != nil {
			http.Error(w, "Erro ao criar sessão", http.StatusInternalServerError)
			return
		}

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Expires:  time.Now().Add(24 * time.Hour),
		})

		// Redirect to main page
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} // End of inner function
} // End of loginSubmitHandler

// logoutHandler clears the session
func logoutHandler(sessions *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		sessionID, err := r.Cookie("session_id")
		if err == nil {
			sessions.DeleteSession(sessionID.Value)
		}

		// Clear cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
		})

		http.Redirect(w, r, "/login", http.StatusSeeOther)
	} // End of inner function
} // End of logoutHandler

// indexHandler renders the main template
func indexHandler(sessions *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check authentication
		sessionID, err := r.Cookie("session_id")
		if err != nil || sessionID == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		_, authenticated := sessions.GetSession(sessionID.Value)
		if !authenticated {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		tmpl, err := template.ParseFiles("templates/index.html")
		if err != nil {
			log.Printf("Erro ao parsear template: %v", err)
			http.Error(w, fmt.Sprintf("Erro ao parsear template: %v", err), http.StatusInternalServerError)
			return
		}

		jsPath := filepath.Join("templates", "app.js")
		jsContent, err := os.ReadFile(jsPath)
		if err != nil {
			log.Printf("Erro ao ler arquivo %s: %v", jsPath, err)
			http.Error(w, fmt.Sprintf("Erro ao ler arquivo JavaScript: %v", err), http.StatusInternalServerError)
			return
		}

		data := TemplateData{
			Title: "Consulta NF-e",
			JS:    template.JS(jsContent),
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("Erro ao renderizar template: %v", err)
			http.Error(w, fmt.Sprintf("Erro ao renderizar template: %v", err), http.StatusInternalServerError)
			return
		}
	} // End of inner function
} // End of indexHandler

func main() {
	config := Config{
		SefazURL: "https://nfe.sefazrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx",
	}

	// Initialize database
	db, err := database.NewDBConn("database.db")
	if err != nil {
		log.Fatalf("Erro ao inicializar banco de dados: %v", err)
	}
	defer db.Close()

	// Initialize session store
	sessions := NewSessionStore()

	// Serve static files (e.g., favicon.ico)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Configure endpoints
	http.HandleFunc("/login", loginHandler(sessions))
	http.HandleFunc("/login/submit", loginSubmitHandler(db, sessions))
	http.HandleFunc("/logout", logoutHandler(sessions))
	http.HandleFunc("/", indexHandler(sessions))
	http.HandleFunc("/upload", uploadHandler(config, sessions))

	log.Println("Servidor rodando na porta 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Erro ao iniciar o servidor: %v", err)
	}
} // End of main
