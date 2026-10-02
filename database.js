// Tornang v2.0.0 — banco de dados
const path = require('path');
const Database = require('better-sqlite3');
const fs = require('fs');

const DATA_DIR = process.env.DATA_DIR || __dirname;
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'tornang.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS companies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  position INTEGER DEFAULT 0,
  password_enc TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (company_id) REFERENCES companies(id)
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('manager','worker')),
  password_hash TEXT,
  password_enc TEXT,
  section_id INTEGER,
  active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (company_id) REFERENCES companies(id),
  FOREIGN KEY (section_id) REFERENCES sections(id)
);

CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  description TEXT,
  current_section_id INTEGER,
  assigned_to INTEGER,
  status TEXT DEFAULT 'in_progress',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (company_id) REFERENCES companies(id),
  FOREIGN KEY (current_section_id) REFERENCES sections(id),
  FOREIGN KEY (assigned_to) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS project_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  section_id INTEGER,
  worker_id INTEGER,
  action TEXT NOT NULL,
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (project_id) REFERENCES projects(id),
  FOREIGN KEY (section_id) REFERENCES sections(id),
  FOREIGN KEY (worker_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS password_resets (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at TEXT NOT NULL,
  used INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS email_verifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  attempts INTEGER DEFAULT 0,
  verified INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);
`);

// Migração: se o banco for de uma versão anterior, adiciona as colunas novas
function addColumn(table, column, ddl) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
  if (!cols.includes(column)) {
    try { db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`); } catch (e) {}
  }
}

addColumn('projects', 'assigned_to', 'assigned_to INTEGER');
addColumn('sections', 'password_enc', 'password_enc TEXT');
// Migração v2.1.0: perfil da empresa + colaboradores
addColumn('companies', 'nif', 'nif TEXT');
addColumn('companies', 'address', 'address TEXT');
addColumn('companies', 'phone', 'phone TEXT');
addColumn('users', 'is_owner', 'is_owner INTEGER DEFAULT 0');

// Marca como "dono" o primeiro gerente cujo e-mail é o e-mail da empresa
db.prepare(`
  UPDATE users SET is_owner = 1
  WHERE role = 'manager' AND is_owner = 0
    AND email IN (SELECT email FROM companies)
`).run();

// Migração v2.2.0: prioridade, prazo e documentos
addColumn('projects', 'priority', 'priority INTEGER DEFAULT 0');
addColumn('projects', 'due_date', 'due_date TEXT');
db.exec(`
CREATE TABLE IF NOT EXISTS project_documents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  stored_name TEXT NOT NULL,
  original_name TEXT NOT NULL,
  mime_type TEXT,
  size INTEGER,
  uploaded_by INTEGER,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (project_id) REFERENCES projects(id)
);
`);

// Migração v2.3.0: rota de produção por folha (etapas sequenciais e paralelas)
db.exec(`
CREATE TABLE IF NOT EXISTS project_route (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  section_id INTEGER NOT NULL,
  step INTEGER NOT NULL,
  status TEXT DEFAULT 'pending',
  FOREIGN KEY (project_id) REFERENCES projects(id)
);
`);

// Migração v2.3.2: nome do projeto (várias folhas para o mesmo cliente)
addColumn('projects', 'name', 'name TEXT');

// Migração v2.4.0: site e logo da empresa + telefone do usuário
addColumn('companies', 'website', 'website TEXT');
addColumn('companies', 'logo', 'logo TEXT');
addColumn('users', 'phone', 'phone TEXT');

// Migração v2.5.0: foto de perfil do usuário
addColumn('users', 'avatar', 'avatar TEXT');

// Migração v3.0.0: locais (multi-local) — uma empresa-pai, locais como filiais
db.exec(`
CREATE TABLE IF NOT EXISTS locations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  address TEXT,
  image TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (company_id) REFERENCES companies(id)
);
`);

addColumn('sections', 'location_id', 'location_id INTEGER');
addColumn('users', 'location_id', 'location_id INTEGER');
addColumn('projects', 'location_id', 'location_id INTEGER');
// Migração v4.4.0: NIF do local
addColumn('locations', 'nif', 'nif TEXT');
// Migração v4.5.0: presença online (status automático)
addColumn('users', 'last_seen', 'last_seen TEXT');

// Backfill: cria a local SEDE para cada empresa que ainda não tem nenhuma
db.prepare(`
  INSERT INTO locations (company_id, name)
  SELECT c.id, 'SEDE' FROM companies c
  WHERE NOT EXISTS (SELECT 1 FROM locations l WHERE l.company_id = c.id)
`).run();

// Aponta tudo que existe hoje para a SEDE da respectiva empresa
db.prepare(`
  UPDATE sections SET location_id = (
    SELECT l.id FROM locations l
    WHERE l.company_id = sections.company_id ORDER BY l.id LIMIT 1
  ) WHERE location_id IS NULL
`).run();

db.prepare(`
  UPDATE users SET location_id = (
    SELECT l.id FROM locations l
    WHERE l.company_id = users.company_id ORDER BY l.id LIMIT 1
  ) WHERE location_id IS NULL
`).run();

db.prepare(`
  UPDATE projects SET location_id = (
    SELECT l.id FROM locations l
    WHERE l.company_id = projects.company_id ORDER BY l.id LIMIT 1
  ) WHERE location_id IS NULL
`).run();

// Migração v3.2.0: anotações de projeto + notificações
db.exec(`
CREATE TABLE IF NOT EXISTS project_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  section_id INTEGER,
  user_id INTEGER,
  author_name TEXT,
  note TEXT NOT NULL,
  is_alert INTEGER DEFAULT 0,
  alert_type TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (project_id) REFERENCES projects(id)
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER NOT NULL,
  user_id INTEGER,
  role TEXT DEFAULT 'manager',
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT,
  project_id INTEGER,
  read INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);
`);

// Migração v3.2.1: atribuição da etapa da rota ao trabalhador
addColumn('project_route', 'assigned_to', 'assigned_to INTEGER');

// Migração v3.5.0: colaboração entre trabalhadores da mesma seção
addColumn('notifications', 'ref_id', 'ref_id INTEGER');
db.exec(`
CREATE TABLE IF NOT EXISTS project_collaborators (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(project_id, user_id),
  FOREIGN KEY (project_id) REFERENCES projects(id)
);

CREATE TABLE IF NOT EXISTS join_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  requester_id INTEGER NOT NULL,
  holder_id INTEGER NOT NULL,
  status TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT (datetime('now'))
);
`);

module.exports = db;