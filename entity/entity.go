package entity

import "html/template"

// Config contém as configurações do sistema
type Config struct {
	SefazURL   string // URL do webservice da SEFAZ
	Production bool   // Indica se o ambiente é de produção
}


// TemplateData contém dados para renderizar o template HTML
type TemplateData struct {
	Title     string
	JS        template.JS // Para o código JavaScript
	CSRFToken string      // CSRF token
}


