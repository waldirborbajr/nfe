package repository

import (
	"context"
	"database/sql"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/waldirborbajr/nfe/entity"
	_ "modernc.org/sqlite"
)

// DB abstracts database operations for testability.
type DB interface {
	Close() error
	CleanupExpiredSessions(ctx context.Context) error
	// Add other methods as needed
}

// DBConnSQLite implements the DB interface for SQLite.
type DBConnSQLite struct {
	db *sql.DB
}

// NewDBConnSQLite creates a new SQLite connection with best practices.
func NewDBConnSQLite(path string) (DB, error) {
	// Ensure the DB file has restricted permissions (0600)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create/open db file: %w", err)
	}
	file.Close()

	// Open SQLite database with foreign keys enabled
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_foreign_keys=on", path))
	if err != nil {
		return nil, fmt.Errorf("failed to open db: %w", err)
	}

	// Set connection pool limits
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(time.Hour)

	// Set secure pragmas
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode = WAL;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to set journal mode: %w", err)
	}

	schemeFile, err := os.Open(config.Scheme)
	if err != nil {
		panic(err)
	}
	defer schemeFile.Close()
	scheme, err := ioutil.ReadAll(schemeFile)
	if err != nil {
		panic(err)
	}

	// Create tables
	db.Exec(string(scheme))

	// Insert default user if not exists
	_, err = db.Exec(`
		INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)
	`, "admin", "admin123")
	if err != nil {
		return nil, err
	}

	return &DBConnSQLite{db: db}, nil
}

// Close closes the database connection.
func (d *DBConnSQLite) Close() error {
	return d.db.Close()
}

// CleanupExpiredSessions securely deletes expired sessions.
func (d *DBConnSQLite) CleanupExpiredSessions(ctx context.Context) error {
	stmt, err := d.db.PrepareContext(ctx, "DELETE FROM sessions WHERE expires_at < ?")
	if err != nil {
		return fmt.Errorf("prepare failed: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("exec failed: %w", err)
	}
	return nil
}

func (d *DBConnSQLite) ValidateUser(username, password string) (*entity.User, error) {
	var user entity.User
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

func (d *DBConnSQLite) CreateSession(userID int, sessionID, csrfToken string, expiresAt time.Time) error {
	_, err := d.db.Exec(`
		INSERT INTO sessions (id, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)
	`, sessionID, userID, csrfToken, expiresAt)
	return err
}

func (d *DBConnSQLite) GetSession(sessionID string) (*entity.Session, error) {
	var session entity.Session
	err := d.db.QueryRow(`
		SELECT id, user_id, csrf_token, expires_at, created_at FROM sessions WHERE id = ?
	`, sessionID).Scan(&session.ID, &session.UserID, &session.CSRFToken, &session.ExpiresAt, &session.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (d *DBConnSQLite) DeleteSession(sessionID string) error {
	_, err := d.db.Exec(`
		DELETE FROM sessions WHERE id = ?
	`, sessionID)
	return err
}

func (d *DBConnSQLite) InsertNFeHeader(header *entity.NFeHeader) error {
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

func (d *DBConnSQLite) InsertNFeItem(item *entity.NFeItem) error {
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

func (d *DBConnSQLite) NFeExists(id string) (bool, error) {
	var count int
	err := d.db.QueryRow(`SELECT COUNT(*) FROM nfe_headers WHERE id = ?`, id).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
