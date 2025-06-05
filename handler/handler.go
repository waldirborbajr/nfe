package handler

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/waldirborbajr/nfe/database"
	"github.com/waldirborbajr/nfe/entity"
)

// SecureHeadersMiddleware adds security headers
func SecureHeadersMiddleware(next http.Handler, config entity.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.Production {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://cdn.tailwindcss.com https://unpkg.com; style-src 'self' https://cdn.tailwindcss.com; img-src 'self'; connect-src 'self'")
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

// validateInput sanitizes and validates input
func validateInput(input string, field string, maxLength int) (string, error) {
	input = strings.TrimSpace(input)
	if len(input) == 0 {
		return "", fmt.Errorf("%s é obrigatório", field)
	}
	if len(input) > maxLength {
		return "", fmt.Errorf("%s muito longo (máximo %d caracteres)", field, maxLength)
	}
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
		log.Fatal("Erro ao gerar session ID: ", err)
	}
	return fmt.Sprintf("%x", b)
}

// generateCSRFToken creates a random CSRF token
func generateCSRFToken() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal("Erro ao gerar CSRF token: ", err)
	}
	return fmt.Sprintf("%x", b)
}

// loadCertificate loads the A1 digital certificate
func loadCertificate(certData []byte, certPassword string) (*tls.Certificate, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		cert, err := tls.X509KeyPair(certData, []byte(certPassword))
		if err != nil {
			return nil, fmt.Errorf("failed to decode .pfx certificate: %v", err)
		}
		return &cert, nil
	}
	return nil, fmt.Errorf("unsupported certificate format")
}

// createTLSClient creates an HTTP client with certificate
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

// consultNFe consults an NF-e at SEFAZ webservice
func consultNFe(client *http.Client, sefazURL, chaveNFe string) (entity.NFeResponse, error) {
	if !regexp.MustCompile(`^\d{44}$`).MatchString(chaveNFe) {
		return entity.NFeResponse{}, fmt.Errorf("chave NF-e inválida")
	}

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
		return entity.NFeResponse{}, fmt.Errorf("erro ao criar requisição: %v", err)
	}

	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
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
func LoginHandler(db *database.DBConn, config entity.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check authentication
		sessionID, err := r.Cookie("session_id")
		if err == nil {
			if _, err := db.GetSession(sessionID.Value); err == nil {
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
		}

		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			log.Printf("Erro ao parsear template: %v", err)
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
func LoginSubmitHandler(db *database.DBConn, config entity.Config) http.HandlerFunc {
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
			Secure:   config.Production,
			SameSite: http.SameSiteStrictMode,
			Expires:  expiresAt,
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// LogoutHandler clears the session
func LogoutHandler(db *database.DBConn, config entity.Config) http.HandlerFunc {
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
			Secure:   config.Production,
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
		session, err := db.GetSession(sessionID.Value)
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

		data := entity.TemplateData{
			Title:     "Consulta NF-e",
			CSRFToken: session.CSRFToken,
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("Erro ao renderizar template: %v", err)
			http.Error(w, "Erro interno do servidor", http.StatusInternalServerError)
			return
		}
	}
}

// ImportNFeHandler handles XML file listing and importing
func ImportNFeHandler(db *database.DBConn) http.HandlerFunc {
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

		downloadsDir := filepath.Join(os.Getenv("HOME"), "Downloads")
		doneDir := filepath.Join(downloadsDir, "done")

		// Create done directory
		if err := os.MkdirAll(doneDir, 0755); err != nil {
			log.Printf("Erro ao criar diretório done: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if r.Method == http.MethodGet {
			// List XML files
			files, err := os.ReadDir(downloadsDir)
			if err != nil {
				log.Printf("Erro ao listar arquivos: %v", err)
				http.Error(w, "Error reading files", http.StatusInternalServerError)
				return
			}

			var xmlFiles []entity.File
			for _, file := range files {
				if !file.IsDir() && strings.HasSuffix(file.Name(), ".xml") {
					xmlFiles = append(xmlFiles, entity.File{Name: file.Name()})
				}
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(xmlFiles); err != nil {
				log.Printf("Erro ao encodear JSON: %v", err)
				http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
				return
			}
			return
		}

		if r.Method == http.MethodPost {
			// Validate CSRF token
			if r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
				return
			}

			var req struct {
				Files     []string `json:"files"`
				CSRFToken string   `json:"csrf_token"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
				return
			}

			if req.CSRFToken != session.CSRFToken {
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}

			var results []string
			for _, fileName := range req.Files {
				// Prevent directory traversal
				fileName = filepath.Base(fileName)
				filePath := filepath.Join(downloadsDir, fileName)
				donePath := filepath.Join(doneDir, fileName)

				// Read XML
				data, err := os.ReadFile(filePath)
				if err != nil {
					log.Printf("Erro ao ler %s: %v", fileName, err)
					results = append(results, fmt.Sprintf("Erro ao ler %s", fileName))
					continue
				}

				// Parse XML
				var nfe entity.NFe
				if err := xml.Unmarshal(data, &nfe); err != nil {
					log.Printf("Erro ao parsear %s: %v", fileName, err)
					results = append(results, fmt.Sprintf("Erro ao parsear %s", fileName))
					continue
				}

				// Check for duplicate
				exists, err := db.NFeExists(nfe.InfNFe.ID)
				if err != nil {
					log.Printf("Erro ao verificar NF-e %s: %v", nfe.InfNFe.ID, err)
					results = append(results, fmt.Sprintf("Erro ao processar %s", fileName))
					continue
				}
				if exists {
					log.Printf("NF-e %s já existe", nfe.InfNFe.ID)
					results = append(results, fmt.Sprintf("%s já importado", fileName))
					continue
				}

				// Insert header
				header := &database.NFeHeader{
					ID:          nfe.InfNFe.ID,
					CUF:         nfe.InfNFe.Ide.CUF,
					CNF:         nfe.InfNFe.Ide.CNF,
					NatOp:       nfe.InfNFe.Ide.NatOp,
					IndPag:      nfe.InfNFe.Ide.IndPag,
					Mod:         nfe.InfNFe.Ide.Mod,
					Serie:       nfe.InfNFe.Ide.Serie,
					NNF:         nfe.InfNFe.Ide.NNF,
					DEmi:        nfe.InfNFe.Ide.DEmi,
					DSaiEnt:     nfe.InfNFe.Ide.DSaiEnt,
					TpNF:        nfe.InfNFe.Ide.TpNF,
					CMunFG:      nfe.InfNFe.Ide.CMunFG,
					TpImp:       nfe.InfNFe.Ide.TpImp,
					TpEmis:      nfe.InfNFe.Ide.TpEmis,
					CDV:         nfe.InfNFe.Ide.CDV,
					TpAmb:       nfe.InfNFe.Ide.TpAmb,
					FinNFe:      nfe.InfNFe.Ide.FinNFe,
					ProcEmi:     nfe.InfNFe.Ide.ProcEmi,
					VerProc:     nfe.InfNFe.Ide.VerProc,
					EmitCNPJ:    nfe.InfNFe.Emit.CNPJ,
					EmitXNome:   nfe.InfNFe.Emit.XNome,
					EmitXLgr:    nfe.InfNFe.Emit.EnderEmit.XLgr,
					EmitNro:     nfe.InfNFe.Emit.EnderEmit.Nro,
					EmitXBairro: nfe.InfNFe.Emit.EnderEmit.XBairro,
					EmitCMun:    nfe.InfNFe.Emit.EnderEmit.CMun,
					EmitXMun:    nfe.InfNFe.Emit.EnderEmit.XMun,
					EmitUF:      nfe.InfNFe.Emit.EnderEmit.UF,
					EmitCEP:     nfe.InfNFe.Emit.EnderEmit.CEP,
					DestCNPJ:    nfe.InfNFe.Dest.CNPJ,
					DestXNome:   nfe.InfNFe.Dest.XNome,
					DestXLgr:    nfe.InfNFe.Dest.EnderDest.XLgr,
					DestNro:     nfe.InfNFe.Dest.EnderDest.Nro,
					DestXBairro: nfe.InfNFe.Dest.EnderDest.XBairro,
					DestCMun:    nfe.InfNFe.Dest.EnderDest.CMun,
					DestXMun:    nfe.InfNFe.Dest.EnderDest.XMun,
					DestUF:      nfe.InfNFe.Dest.EnderDest.UF,
					DestCEP:     nfe.InfNFe.Dest.EnderDest.CEP,
					VBC:         nfe.InfNFe.Total.ICMSTot.VBC,
					VICMS:       nfe.InfNFe.Total.ICMSTot.VICMS,
					VProd:       nfe.InfNFe.Total.ICMSTot.VProd,
					VPIS:        nfe.InfNFe.Total.ICMSTot.VPIS,
					VCOFINS:     nfe.InfNFe.Total.ICMSTot.VCOFINS,
					VNF:         nfe.InfNFe.Total.ICMSTot.VNF,
				}

				if err := db.InsertNFeHeader(header); err != nil {
					log.Printf("Erro ao inserir header %s: %v", fileName, err)
					results = append(results, fmt.Sprintf("Erro ao importar %s", fileName))
					continue
				}

				// Insert items
				for _, det := range nfe.InfNFe.Det {
					nItem, _ := strconv.Atoi(det.NItem)
					item := &database.NFeItem{
						NFeID:   nfe.InfNFe.ID,
						NItem:   nItem,
						CProd:   det.Prod.CProd,
						XProd:   det.Prod.XProd,
						CFOP:    det.Prod.CFOP,
						UCom:    det.Prod.UCom,
						QCom:    det.Prod.QCom,
						VUnCom:  det.Prod.VUnCom,
						VProd:   det.Prod.VProd,
						VBC:     det.Imposto.ICMS.ICMS00.VBC,
						PICMS:   det.Imposto.ICMS.ICMS00.PICMS,
						VICMS:   det.Imposto.ICMS.ICMS00.VICMS,
						PPIS:    det.Imposto.PIS.PISAliq.PPIS,
						VPIS:    det.Imposto.PIS.PISAliq.VPIS,
						PCOFINS: det.Imposto.COFINS.COFINSAliq.PCOFINS,
						VCOFINS: det.Imposto.COFINS.COFINSAliq.VCOFINS,
					}

					if err := db.InsertNFeItem(item); err != nil {
						log.Printf("Erro ao inserir item %s: %d: %v", fileName, nItem, err)
						results = append(results, fmt.Sprintf("Erro ao importar item %s", fileName))
						continue
					}
				}

				// Move file to done
				if err := os.Rename(filePath, donePath); err != nil {
					log.Printf("Erro ao mover %s: %v", fileName, err)
					results = append(results, fmt.Sprintf("Erro ao mover %s", fileName))
					continue
				}

				results = append(results, fmt.Sprintf("%s importado com sucesso", fileName))
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"results": results,
			}); err != nil {
				log.Printf("Erro ao encodear JSON: %v", err)
				http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
				return
			}
		}
	}
}

// RedirectHTTPToHTTPS redirects HTTP to HTTPS
func RedirectHTTPToHTTPS(wg *sync.WaitGroup) {
	defer wg.Done()
	httpServer := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+":4043"+r.RequestURI, http.StatusMovedPermanently)
		}),
	}
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal("HTTP server error: ", err)
	}
}
