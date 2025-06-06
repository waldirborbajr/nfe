package entity

// Config contém as configurações do sistema
type Config struct {
	SefazURL   string // URL do webservice da SEFAZ
	Production bool   // Indica se o ambiente é de produção
}