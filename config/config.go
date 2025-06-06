package config

import (
	"fmt"
	"os"

	"github.com/waldirborbajr/nfe/entity"
	"gopkg.in/yaml.v3"
)

func LoadConfig() (entity.Config, error) {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		return entity.Config{}, fmt.Errorf("erro ao ler config.yaml: %w", err)
	}

	var config entity.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return entity.Config{}, fmt.Errorf("erro ao parsear config.yaml: %w", err)
	}

	return config, nil
}
