package entity

import "html/template"

// Config contém as configurações do sistema
type Config struct {
	SefazURL string // URL do webservice da SEFAZ
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
	Title     string
	JS        template.JS // Para o código JavaScript
	CSRFToken string      // CSRF token
}
