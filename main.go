package main

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
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
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseMultipartForm(10 << 20) // 10 MB
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

		certData, err := ioutil.ReadAll(file)
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
	}
}

// indexHandler renderiza o template HTML
func indexHandler() http.HandlerFunc {
	// Define o template HTML com React
	const htmlTemplate = `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{.Title}}</title>
  <script src="https://cdn.jsdelivr.net/npm/react@18.2.0/umd/react.development.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/react-dom@18.2.0/umd/react-dom.development.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/babel-standalone@6.26.0/babel.min.js"></script>
  <script src="https://cdn.tailwindcss.com/3.4.1"></script>
</head>
<body>
  <div id="root"></div>
  <script type="text/babel">
    function App() {
      const [certificate, setCertificate] = React.useState(null);
      const [password, setPassword] = React.useState('');
      const [nfeList, setNfeList] = React.useState([]);
      const [error, setError] = React.useState(null);
      const [loading, setLoading] = React.useState(false);

      const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError(null);

        const formData = new FormData();
        formData.append('certificate', certificate);
        formData.append('password', password);

        try {
          const response = await fetch('/upload', {
            method: 'POST',
            body: formData,
          });
          if (!response.ok) {
            throw new Error('Erro ao consultar NF-e');
          }
          const data = await response.json();
          setNfeList(data);
        } catch (err) {
          setError(err.message);
        } finally {
          setLoading(false);
        }
      };

      return (
        <div className="min-h-screen bg-gray-100 p-6">
          <div className="max-w-4xl mx-auto bg-white rounded-lg shadow-md p-6">
            <h1 className="text-2xl font-bold mb-6">Consulta de Notas Fiscais Eletrônicas</h1>
            
            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Certificado Digital (.pfx)
              </label>
              <input
                type="file"
                accept=".pfx"
                onChange={(e) => setCertificate(e.target.files[0])}
                className="block w-full text-sm text-gray-500
                  file:mr-4 file:py-2 file:px-4
                  file:rounded-md file:border-0
                  file:text-sm file:font-semibold
                  file:bg-blue-50 file:text-blue-700
                  hover:file:bg-blue-100"
              />
            </div>
            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Senha do Certificado
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
                placeholder="Digite a senha"
              />
            </div>
            <button
              onClick={handleSubmit}
              disabled={!certificate || !password || loading}
              className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:bg-gray-400"
            >
              {loading ? 'Consultando...' : 'Consultar NF-e'}
            </button>

            {error && (
              <div className="mt-4 p-4 bg-red-100 text-red-700 rounded-md">
                {error}
              </div>
            )}

            {nfeList.length > 0 && (
              <div className="mt-6">
                <h2 className="text-xl font-semibold mb-4">Resultados</h2>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Chave NF-e</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Descrição</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Emitente</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Data de Emissão</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {nfeList.map((nfe) => (
                        <tr key={nfe.chave_nfe}>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{nfe.chave_nfe}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{nfe.status}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{nfe.descricao}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{nfe.emitente}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{nfe.data_emissao}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      );
    }

    ReactDOM.render(<App />, document.getElementById('root'));
  </script>
</body>
</html>
`

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}

		// Parseia o template
		tmpl, err := template.New("index").Parse(htmlTemplate)
		if err != nil {
			http.Error(w, "Erro ao parsear template", http.StatusInternalServerError)
			return
		}

		// Dados para o template
		data := TemplateData{
			Title: "Consulta NF-e",
		}

		// Renderiza o template
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, "Erro ao renderizar template", http.StatusInternalServerError)
			return
		}
	}
}

func main() {
	config := Config{
		SefazURL: "https://nfe.sefazrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx",
	}

	// Configura os endpoints
	http.HandleFunc("/", indexHandler())
	http.HandleFunc("/upload", uploadHandler(config))

	log.Println("Servidor rodando na porta 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Erro ao iniciar o servidor: %v", err)
	}
}
