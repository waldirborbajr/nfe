package entity

import "html/template"

// TemplateData contém dados para renderizar o template HTML
type TemplateData struct {
	Title     string
	JS        template.JS // Para o código JavaScript
	CSRFToken string      // CSRF token
}
