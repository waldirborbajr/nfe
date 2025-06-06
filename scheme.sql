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

CREATE TABLE IF NOT EXISTS nfe_xmls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    xml_content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);

CREATE TABLE IF NOT EXISTS nfe_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    log_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);

CREATE TABLE IF NOT EXISTS nfe_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    status_code INTEGER,
    status_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);
CREATE TABLE IF NOT EXISTS nfe_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    certificate_content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);
CREATE TABLE IF NOT EXISTS nfe_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    signature_content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);
CREATE TABLE IF NOT EXISTS nfe_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);
CREATE TABLE IF NOT EXISTS nfe_audit_trail (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    action TEXT,
    user_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS nfe_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    notification_type TEXT,
    notification_content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);
CREATE TABLE IF NOT EXISTS nfe_rejections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    rejection_reason TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);
CREATE TABLE IF NOT EXISTS nfe_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    approval_status TEXT,
    approval_date DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);
CREATE TABLE IF NOT EXISTS nfe_payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    payment_method TEXT,
    payment_amount REAL,
    payment_date DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);
CREATE TABLE IF NOT EXISTS nfe_shipments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    shipment_method TEXT,
    shipment_date DATETIME,
    tracking_number TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);
CREATE TABLE IF NOT EXISTS nfe_taxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    tax_type TEXT,
    tax_amount REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);
CREATE TABLE IF NOT EXISTS nfe_custom_fields (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    field_name TEXT,
    field_value TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);
CREATE TABLE IF NOT EXISTS nfe_related_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    document_type TEXT,
    document_content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);
CREATE TABLE IF NOT EXISTS nfe_integrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    integration_type TEXT,
    integration_status TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);
CREATE TABLE IF NOT EXISTS nfe_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    action_type TEXT,
    action_description TEXT,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS nfe_document_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfe_id TEXT,
    version_number INTEGER,
    version_content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);
CREATE TABLE IF NOT EXISTS nfe_document_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_name TEXT UNIQUE NOT NULL,
    template_content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS nfe_document_templates_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id INTEGER,
    version_number INTEGER,
    version_content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (template_id) REFERENCES nfe_document_templates(id)
);
CREATE TABLE IF NOT EXISTS nfe_document_template_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id INTEGER,
    nfe_id TEXT,
    assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (template_id) REFERENCES nfe_document_templates(id),
    FOREIGN KEY (nfe_id) REFERENCES nfe_headers(id)
);              
