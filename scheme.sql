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


INSERT INTO users (username, password) VALUES ("admin", "admin123");

