package main

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
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

// UploadRequest representa a requisição de upload
type UploadRequest struct {
	CertFile     io.Reader
	CertPassword string
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

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return NFeResponse{}, fmt.Errorf("erro ao ler resposta: %v", err)
	}

	// Simulação de parsing (substitua por parsing real do XML retornado)
	// Aqui, retornamos dados fictícios para demonstração
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
}

// uploadHandler lida com o upload do certificado e consulta de NF-e
func uploadHandler(config Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parseia o formulário multipart
		err := r.ParseMultipartForm(10 << 20) // 10 MB
		if err != nil {
			http.Error(w, "Erro ao parsear formulário", http.StatusBadRequest)
			return
		}

		// Obtém o arquivo do certificado
		file, _, err := r.FormFile("certificate")
		if err != nil {
			http.Error(w, "Erro ao obter certificado", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Lê o conteúdo do arquivo
		certData, err := ioutil.ReadAll(file)
		if err != nil {
			http.Error(w, "Erro ao ler certificado", http.StatusBadRequest)
			return
		}

		// Obtém a senha
		certPassword := r.FormValue("password")
		if certPassword == "" {
			http.Error(w, "Senha do certificado é obrigatória", http.StatusBadRequest)
			return
		}

		// Carrega o certificado
		cert, err := loadCertificate(certData, certPassword)
		if err != nil {
			http.Error(w, fmt.Sprintf("Erro ao carregar certificado: %v", err), http.StatusBadRequest)
			return
		}

		// Cria o cliente HTTP com o certificado
		client := createTLSClient(cert)

		// Simula consulta de múltiplas NF-e (substitua por chaves reais)
		chavesNFe := []string{
			"35230612345678901234567890123456789012345678",
			"35230698765432109876543210987654321098765432",
		}

		var AscertainableList (nfeResponses)
		for _, chave := range chavesNFe {
			nfe, err := consultNFe(client, config.SefazURL, chave)
			if err != nil {
				log.Printf("Erro ao consultar NF-e %s: %v", chave, err)
				continue
			}
			nfeResponses = append(nfeResponses, nfe)
		}

		// Retorna a resposta em JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(nfeResponses)
	}
}

func main() {
	config := Config{
		SefazURL: "https://nfe.sefazrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx",
	}

	router := mux.NewRouter()
	router.HandleFunc("/upload", uploadHandler(config)).Methods("POST")

	log.Println("Servidor rodando na porta 8080...")
	http.ListenAndServe(":8080", router)
}
