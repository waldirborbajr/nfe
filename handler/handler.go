package handler

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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/waldirborbajr/nfe/database"
	"github.com/waldirborbajr/nfe/entity"
)

// SecureHeadersMiddleware adiciona cabeçalhos de segurança
func SecureHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://cdn.tailwindcss.com; style-src 'self' https://cdn.tailwindcss.com; img-src 'self'; connect-src 'self'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

// validateInput sanitizes and validates input
func validateInput(input string, field string, maxLength int) (string, error) {
	input = strings.TrimSpace(input)
	if len(input) == 0 {
		return "", fmt.Errorf("%s é obrigatório", field)
	}
	if len(input) > maxLength {
		return "", fmt.Errorf("%s muito longo (máximo %d caracteres)", field, maxLength)
	}
	// Basic injection check (extend as needed)
	if regexp.MustCompile(`[<>'";]`).MatchString(input) {
		return "", fmt.Errorf("caracteres inválidos em %s", field)
	}
	return input, nil
}

// generateSessionID creates a random session ID
func generateSessionID() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatalf("Erro ao gerar session ID: %v", err)
	}
	return fmt.Sprintf("%x", b)
}

// generateCSRFToken creates a random CSRF token
func generateCSRFToken() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatalf("Erro ao gerar CSRF token: %v", err)
	}
	return fmt.Sprintf("%x", b)
}

// loadCertificate carrega o certificado digital A1
func loadCertificate(certData []byte, certPassword string) (*tls.Certificate, error) {
	// Decodifica o arquivo .pfx
	block, _ := pem.Decode(certData)
	if block == nil {
		// Assume .pfx puro
		cert, err := tls.X509KeyPair(certData, []byte(certPassword))
		if err != nil {
			return nil, fmt.Errorf("failed to decode .pfx certificate: %v", err)
		}
		return &cert, nil
	}
	return nil, fmt.Errorf("unsupported certificate format")
}

// createTLSClient cria um cliente HTTP com certificado
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

// consultNFe consulta uma NF-e no webservice da SEFAZ
func consultNFe(client *http.Client, sefazURL, chaveNFe string) (entity.NFeResponse, error) {
	// Validate chaveNFe (44 digits)
	if !regexp.MustCompile(`^\d{44}$`).MatchString(chaveNFe) {
		return entity.NFeResponse{}, fmt.Errorf("chave NF-e inválida")
	}

	soapRequest := `<?xml version="1.0" encoding="UTF-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="https://www.w3.org/2003/05/soap-envelope">
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
		return entity.NFeResponse{}, fmt.Errorf("erro ao criar requisição: %v", err)
	}

	req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	req.Header.Set("SOAPAction", "http://www.portalfiscal.inf.br/nfe/wsdl/NFeConsultaProtocolo4/nfeConsultaNF")

	resp, err := client.Do(req)
	if err != nil {
		return entity.NFeResponse{}, fmt.Errorf("erro ao consultar NF-e: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return entity.NFeResponse{}, fmt.Errorf("erro ao ler resposta: %v", err)
	}

	// Simulate parsing (replace with actual XML parsing if needed)
	nfe := entity.NFeResponse{
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
}

// UploadHandler handles certificate upload and NF-e consultation
func UploadHandler(config entity.Config, db *database.DBConn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check authentication
		sessionID, err := r.Cookie("session_id")
		if err != nil || sessionID == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		session, err := db.GetSession(sessionID.Value)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Validate CSRF token
		csrfToken := r.FormValue("csrf_token")
		if csrfToken != session.CSRFToken {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
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

		certPassword, err := validateInput(r.FormValue("password"), "senha do certificado", 50)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
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

		var nfeResponses []entity.NFeResponse
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
	}
}

// LoginHandler renders the login template
func LoginHandler(db *database.DBConn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check if already authenticated
		sessionID, err := r.Cookie("session_id")
		if err == nil {
			if _, err := db.GetSession(sessionID.Value); err == nil {
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
		}

		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			log.Printf("Erro ao parsear formulário: %v", err)
			http.Error(w, "Erro interno do servidor", http.StatusInternalServerError)
			return
		}

		jsPath := filepath.Join("templates", "login.js")
		jsContent, err := os.ReadFile(jsPath)
		if err != nil {
			log.Printf("Erro ao ler arquivo %s: %v", jsPath, err)
			http.Error(w, "Erro interno do servidor", http.StatusInternalServerError)
			return
		}

		// Generate temporary CSRF token for login page
		csrfToken := generateCSRFToken()

		data := entity.TemplateData{
			Title:     "Login",
			JS:        template.JS(jsContent),
			CSRFToken: csrfToken,
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("Erro ao renderizar template: %v", err)
			http.Error(w, "Erro interno do servidor", http.StatusInternalServerError)
			return
		}
	}
}

// LoginSubmitHandler processes login form submissions
func LoginSubmitHandler(db *database.DBConn) http.HandlerFunc {
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

		username, err := validateInput(r.FormValue("username"), "usuário", 50)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		password, err := validateInput(r.FormValue("password"), "senha", 50)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		csrfToken := r.FormValue("csrf_token")
		if csrfToken == "" {
			http.Error(w, "CSRF token inválido", http.StatusForbidden)
			return
		}

		user, err := db.ValidateUser(username, password)
		if err != nil {
			http.Error(w, "Usuário ou senha inválidos", http.StatusUnauthorized)
			return
		}

		// Create session
		sessionID := generateSessionID()
		newCSRFToken := generateCSRFToken()
		expiresAt := time.Now().Add(24 * time.Hour)
		err = db.CreateSession(user.ID, sessionID, newCSRFToken, expiresAt)
		if err != nil {
			log.Printf("Erro ao criar sessão: %v", err)
			http.Error(w, "Erro interno do servidor", http.StatusInternalServerError)
			return
		}

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Expires:  expiresAt,
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// LogoutHandler clears the session
func LogoutHandler(db *database.DBConn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		sessionID, err := r.Cookie("session_id")
		if err == nil {
			db.DeleteSession(sessionID.Value)
		}

		// Clear cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})

		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

// IndexHandler renders the main template
func IndexHandler(db *database.DBConn) http.HandlerFunc {
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
		_, err = db.GetSession(sessionID.Value)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		tmpl, err := template.ParseFiles("templates/index.html")
		if err != nil {
			log.Printf("Erro ao parsear template: %v", err)
			http.Error(w, "Erro interno do servidor", http.StatusInternalServerError)
			return
		}

		jsPath := filepath.Join("templates", "app.js")
		jsContent, err := os.ReadFile(jsPath)
		if err != nil {
			log.Printf("Erro ao ler arquivo %s: %v", jsPath, err)
			http.Error(w, "Erro interno do servidor", http.StatusInternalServerError)
			return
		}

		data := entity.TemplateData{
			Title: "Consulta NF-e",
			JS:    template.JS(jsContent),
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("Erro ao renderizar template: %v", err)
			http.Error(w, "Erro interno do servidor", http.StatusInternalServerError)
			return
		}
	}
}

// RedirectHTTPToHTTPS redirects HTTP to HTTPS
func RedirectHTTPToHTTPS(wg *sync.WaitGroup) {
	defer wg.Done()
	httpServer := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
		}),
	}
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server error: %v", err)
	}
}
