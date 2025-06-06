package response

// NFeResponse representa a resposta da API com informações da NF-e
type NFeResponse struct {
	ChaveNFe    string `json:"chave_nfe"`
	Status      string `json:"status"`
	Descricao   string `json:"descricao"`
	Emitente    string `json:"emitente,omitempty"`
	DataEmissao string `json:"data_emissao,omitempty"`
}
