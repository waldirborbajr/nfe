package entity

import "html/template"

// Config contém as configurações do sistema
type Config struct {
	SefazURL   string // URL do webservice da SEFAZ
	Production bool   // Indica se o ambiente é de produção
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

// NFeResponse holds NF-e consultation response
// type NFeResponse struct {
// 	ChaveNFe    string
// 	Status      string
// 	Descrição   string
// 	Emitente    string
// 	DataEmissao string
// }

// NFe represents the root NF-e XML structure
type NFe struct {
	InfNFe InfNFe `xml:"infNFe"`
}

// InfNFe holds NF-e header information
type InfNFe struct {
	ID     string `xml:"Id,attr"`
	Versao string `xml:"versao,attr"`
	Ide    Ide    `xml:"ide"`
	Emit   Emit   `xml:"emit"`
	Dest   Dest   `xml:"dest"`
	Det    []Det  `xml:"det"`
	Total  Total  `xml:"total"`
	Transp Transp `xml:"transp"`
}

// Ide holds identification data
type Ide struct {
	CUF     string `xml:"cUF"`
	CNF     string `xml:"cNF"`
	NatOp   string `xml:"natOp"`
	IndPag  int    `xml:"indPag"`
	Mod     string `xml:"mod"`
	Serie   string `xml:"serie"`
	NNF     string `xml:"nNF"`
	DEmi    string `xml:"dEmi"`
	DSaiEnt string `xml:"dSaiEnt"`
	TpNF    int    `xml:"tpNF"`
	CMunFG  string `xml:"cMunFG"`
	TpImp   int    `xml:"tpImp"`
	TpEmis  int    `xml:"tpEmis"`
	CDV     int    `xml:"cDV"`
	TpAmb   int    `xml:"tpAmb"`
	FinNFe  int    `xml:"finNFe"`
	ProcEmi int    `xml:"procEmi"`
	VerProc string `xml:"verProc"`
}

// Emit holds emitter data
type Emit struct {
	CNPJ      string    `xml:"CNPJ"`
	XNome     string    `xml:"xNome"`
	EnderEmit EnderEmit `xml:"enderEmit"`
}

// EnderEmit holds emitter address
type EnderEmit struct {
	XLgr    string `xml:"xLgr"`
	Nro     string `xml:"nro"`
	XBairro string `xml:"xBairro"`
	CMun    string `xml:"cMun"`
	XMun    string `xml:"xMun"`
	UF      string `xml:"UF"`
	CEP     string `xml:"CEP"`
}

// Dest holds recipient data
type Dest struct {
	CNPJ      string    `xml:"CNPJ"`
	XNome     string    `xml:"xNome"`
	EnderDest EnderDest `xml:"enderDest"`
}

// EnderDest holds recipient address
type EnderDest struct {
	XLgr    string `xml:"xLgr"`
	Nro     string `xml:"nro"`
	XBairro string `xml:"xBairro"`
	CMun    string `xml:"cMun"`
	XMun    string `xml:"xMun"`
	UF      string `xml:"UF"`
	CEP     string `xml:"CEP"`
}

// Det holds item details
type Det struct {
	NItem   string  `xml:"nItem,attr"`
	Prod    Prod    `xml:"prod"`
	Imposto Imposto `xml:"imposto"`
}

// Prod holds product data
type Prod struct {
	CProd  string  `xml:"cProd"`
	XProd  string  `xml:"xProd"`
	CFOP   string  `xml:"CFOP"`
	UCom   string  `xml:"uCom"`
	QCom   float64 `xml:"qCom"`
	VUnCom float64 `xml:"vUnCom"`
	VProd  float64 `xml:"vProd"`
}

// Imposto holds tax data
type Imposto struct {
	ICMS   ICMS   `xml:"ICMS"`
	PIS    PIS    `xml:"PIS"`
	COFINS COFINS `xml:"COFINS"`
}

// ICMS holds ICMS tax data
type ICMS struct {
	ICMS00 ICMS00 `xml:"ICMS00"`
}

// ICMS00 holds ICMS details
type ICMS00 struct {
	VBC   float64 `xml:"vBC"`
	PICMS float64 `xml:"pICMS"`
	VICMS float64 `xml:"vICMS"`
}

// PIS holds PIS tax data
type PIS struct {
	PISAliq PISAliq `xml:"PISAliq"`
}

// PISAliq holds PIS details
type PISAliq struct {
	VBC  float64 `xml:"vBC"`
	PPIS float64 `xml:"pPIS"`
	VPIS float64 `xml:"vPIS"`
}

// COFINS holds COFINS tax data
type COFINS struct {
	COFINSAliq COFINSAliq `xml:"COFINSAliq"`
}

// COFINSAliq holds COFINS details
type COFINSAliq struct {
	VBC     float64 `xml:"vBC"`
	PCOFINS float64 `xml:"pCOFINS"`
	VCOFINS float64 `xml:"vCOFINS"`
}

// Total holds total values
type Total struct {
	ICMSTot ICMSTot `xml:"ICMSTot"`
}

// ICMSTot holds total tax values
type ICMSTot struct {
	VBC     float64 `xml:"vBC"`
	VICMS   float64 `xml:"vICMS"`
	VProd   float64 `xml:"vProd"`
	VPIS    float64 `xml:"vPIS"`
	VCOFINS float64 `xml:"vCOFINS"`
	VNF     float64 `xml:"vNF"`
}

// Transp holds transport data
type Transp struct {
	ModFrete string `xml:"modFrete"`
}

// File represents a file in the downloads directory
type File struct {
	Name string `json:"name"`
}
