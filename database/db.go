package database

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

type DBConn struct {
	db *sql.DB
}

type User struct {
	ID       int
	Username string
	Password string
}

type Session struct {
	ID        string
	UserID    int
	CSRFToken string
	ExpiresAt time.Time
	CreatedAt time.Time
}

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

func NewDBConn(dbPath string) (*DBConn, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	// Create tables
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id INTEGER,
			csrf_token TEXT,
			expires_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE IF NOT EXISTS nfe_headers (
			id TEXT PRIMARY KEY,
			cuf TEXT,
			cnf TEXT,
			nat_op TEXT,
			ind_pag INTEGER,
			mod TEXT,
			serie TEXT,
			nnf TEXT,
			d_emi TEXT,
			d_sai_ent TEXT,
			tp_nf INTEGER,
			c_mun_fg TEXT,
			tp_imp INTEGER,
			tp_emis INTEGER,
			c_dv INTEGER,
			tp_amb INTEGER,
			fin_nfe INTEGER,
			proc_emi INTEGER,
			ver_proc TEXT,
			emit_cnpj TEXT,
			emit_x_nome TEXT,
			emit_x_lgr TEXT,
			emit_nro TEXT,
			emit_x_bairro TEXT,
			emit_c_mun TEXT,
			emit_x_mun TEXT,
			emit_uf TEXT,
			emit_cep TEXT,
			dest_cnpj TEXT,
			dest_x_nome TEXT,
			dest_x_lgr TEXT,
			dest_nro TEXT,
			dest_x_bairro TEXT,
			dest_c_mun TEXT,
			dest_x_mun TEXT,
			dest_uf TEXT,
			dest_cep TEXT,
			v_bc REAL,
			v_icms REAL,
			v_prod REAL,
			v_pis REAL,
			v_cofins REAL,
			v_nf REAL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS nfe_items (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			nfe_id TEXT,
			n_item INTEGER,
			c_prod TEXT,
			x_prod TEXT,
			cfop TEXT,
			u_com TEXT,
			q_com REAL,
			v_un_com REAL,
			v_prod REAL,
			v_bc REAL,
			p_icms REAL,
			v_icms REAL,
			p_pis REAL,
			v_pis REAL,
			p_cofins REAL,
			v_cofins REAL,
			FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
		);
	`)
	if err != nil {
		return nil, err
	}

	// Insert default user if not exists
	_, err = db.Exec(`
		INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)
	`, "admin", "admin123")
	if err != nil {
		return nil, err
	}

	return &DBConn{db: db}, nil
}

func (d *DBConn) Close() error {
	return d.db.Close()
}

func (d *DBConn) ValidateUser(username, password string) (*User, error) {
	var user User
	err := d.db.QueryRow(`
		SELECT id, username, password FROM users WHERE username = ?
	`, username).Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		return nil, err
	}
	if user.Password != password {
		return nil, err
	}
	return &user, nil
}

func (d *DBConn) CreateSession(userID int, sessionID, csrfToken string, expiresAt time.Time) error {
	_, err := d.db.Exec(`
		INSERT INTO sessions (id, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)
	`, sessionID, userID, csrfToken, expiresAt)
	return err
}

func (d *DBConn) GetSession(sessionID string) (*Session, error) {
	var session Session
	err := d.db.QueryRow(`
		SELECT id, user_id, csrf_token, expires_at, created_at FROM sessions WHERE id = ?
	`, sessionID).Scan(&session.ID, &session.UserID, &session.CSRFToken, &session.ExpiresAt, &session.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (d *DBConn) DeleteSession(sessionID string) error {
	_, err := d.db.Exec(`
		DELETE FROM sessions WHERE id = ?
	`, sessionID)
	return err
}

func (d *DBConn) CleanupExpiredSessions() error {
	_, err := d.db.Exec(`
		DELETE FROM sessions WHERE expires_at < datetime('now')
	`)
	return err
}

func (d *DBConn) InsertNFeHeader(header *NFeHeader) error {
	_, err := d.db.Exec(`
		INSERT INTO nfe_headers (
			id, cuf, cnf, nat_op, ind_pag, mod, serie, nnf, d_emi, d_sai_ent, tp_nf,
			c_mun_fg, tp_imp, tp_emis, c_dv, tp_amb, fin_nfe, proc_emi, ver_proc,
			emit_cnpj, emit_x_nome, emit_x_lgr, emit_nro, emit_x_bairro, emit_c_mun,
			emit_x_mun, emit_uf, emit_cep, dest_cnpj, dest_x_nome, dest_x_lgr, dest_nro,
			dest_x_bairro, dest_c_mun, dest_x_mun, dest_uf, dest_cep, v_bc, v_icms,
			v_prod, v_pis, v_cofins, v_nf
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, header.ID, header.CUF, header.CNF, header.NatOp, header.IndPag, header.Mod, header.Serie,
		header.NNF, header.DEmi, header.DSaiEnt, header.TpNF, header.CMunFG, header.TpImp,
		header.TpEmis, header.CDV, header.TpAmb, header.FinNFe, header.ProcEmi, header.VerProc,
		header.EmitCNPJ, header.EmitXNome, header.EmitXLgr, header.EmitNro, header.EmitXBairro,
		header.EmitCMun, header.EmitXMun, header.EmitUF, header.EmitCEP, header.DestCNPJ,
		header.DestXNome, header.DestXLgr, header.DestNro, header.DestXBairro, header.DestCMun,
		header.DestXMun, header.DestUF, header.DestCEP, header.VBC, header.VICMS, header.VProd,
		header.VPIS, header.VCOFINS, header.VNF)
	return err
}

func (d *DBConn) InsertNFeItem(item *NFeItem) error {
	_, err := d.db.Exec(`
		INSERT INTO nfe_items (
			nfe_id, n_item, c_prod, x_prod, cfop, u_com, q_com, v_un_com, v_prod,
			v_bc, p_icms, v_icms, p_pis, v_pis, p_cofins, v_cofins
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, item.NFeID, item.NItem, item.CProd, item.XProd, item.CFOP, item.UCom, item.QCom,
		item.VUnCom, item.VProd, item.VBC, item.PICMS, item.VICMS, item.PPIS, item.VPIS,
		item.PCOFINS, item.VCOFINS)
	return err
}

func (d *DBConn) NFeExists(id string) (bool, error) {
	var count int
	err := d.db.QueryRow(`SELECT COUNT(*) FROM nfe_headers WHERE id = ?`, id).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
