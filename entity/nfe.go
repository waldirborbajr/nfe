package entity

type NFeHeader struct {
	ID          string
	CUF         string
	CNF         string
	NatOp       string
	IndPag      int
	Mod         string
	Serie       string
	NNF         string
	DEmi        string
	DSaiEnt     string
	TpNF        int
	CMunFG      string
	TpImp       int
	TpEmis      int
	CDV         int
	TpAmb       int
	FinNFe      int
	ProcEmi     int
	VerProc     string
	EmitCNPJ    string
	EmitXNome   string
	EmitXLgr    string
	EmitNro     string
	EmitXBairro string
	EmitCMun    string
	EmitXMun    string
	EmitUF      string
	EmitCEP     string
	DestCNPJ    string
	DestXNome   string
	DestXLgr    string
	DestNro     string
	DestXBairro string
	DestCMun    string
	DestXMun    string
	DestUF      string
	DestCEP     string
	VBC         float64
	VICMS       float64
	VProd       float64
	VPIS        float64
	VCOFINS     float64
	VNF         float64
}

type NFeItem struct {
	NFeID   string
	NItem   int
	CProd   string
	XProd   string
	CFOP    string
	UCom    string
	QCom    float64
	VUnCom  float64
	VProd   float64
	VBC     float64
	PICMS   float64
	VICMS   float64
	PPIS    float64
	VPIS    float64
	PCOFINS float64
	VCOFINS float64
}
