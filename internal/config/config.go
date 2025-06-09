package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config contém as configurações do sistema
type Config struct {
	SefazURL   string `yaml:"sefazUrl"`   // URL do SEFAZ
	Production bool   `yaml:"production"` // Indica se o sistema está em produção
	HttpPort   string `yaml:"httpPort"`   // Porta HTTP do servidor
	HttpsPort  string `yaml:"httpsPort"`  // Porta HTTPS do servidor
}

func LoadConfig() (Config, error) {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		return Config{}, fmt.Errorf("erro ao ler config.yaml: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("erro ao parsear config.yaml: %w", err)
	}

	return config, nil
}
