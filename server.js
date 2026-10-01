// Tornang v2.0.0 — servidor
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const multer = require('multer');
const db = require('./database');
const DATA_DIR = process.env.DATA_DIR || __dirname;
fs.mkdirSync(path.join(DATA_DIR, 'uploads'), { recursive: true });


const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ---------- Criptografia reversível (senhas de trabalhadores e seções) ----------
const APP_SECRET = process.env.APP_SECRET || 'tornang-secret-troque-em-producao';

function encrypt(text) {
  const key = crypto.createHash('sha256').update(APP_SECRET).digest();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let out = cipher.update(String(text), 'utf8', 'hex');
  out += cipher.final('hex');
  return iv.toString('hex') + ':' + out;
}

function decrypt(text) {
  try {
    if (!text || !text.includes(':')) return '';
    const [ivHex, data] = text.split(':');
    const key = crypto.createHash('sha256').update(APP_SECRET).digest();
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(ivHex, 'hex'));
    let out = decipher.update(data, 'hex', 'utf8');
    out += decipher.final('utf8');
    return out;
  } catch (e) { return ''; }
}

// ---------- Autenticação ----------
function auth(req, res, next) {
    const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : (req.query.token || '');
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) return res.status(401).json({ error: 'Sessão inválida. Entre novamente.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!user) return res.status(401).json({ error: 'Conta não encontrada.' });
  if (!user.active) return res.status(403).json({ error: 'Conta desativada. Fale com o gerente.' });
  req.user = user;
  next();
}

function managerOnly(req, res, next) {
  if (req.user.role !== 'manager') return res.status(403).json({ error: 'Acesso restrito ao gerente.' });
  next();
}

function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role, section_id: u.section_id, active: u.active, is_owner: !!u.is_owner, phone: u.phone || '', avatar: u.avatar || null };
}

// ---------- Cadastro: etapa 1 (credenciais + envio do código) ----------
app.post('/api/signup/start', (req, res) => {
  const { email, password, confirm } = req.body || {};
  const emailNorm = String(email || '').toLowerCase().trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNorm)) return res.status(400).json({ error: 'E-mail inválido.' });
  if (!password || String(password).length < 4) return res.status(400).json({ error: 'A senha precisa ter pelo menos 4 caracteres.' });
  if (password !== confirm) return res.status(400).json({ error: 'As senhas não coincidem.' });
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(emailNorm);
  if (exists) return res.status(400).json({ error: 'Já existe uma conta com este e-mail.' });
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const codeHash = crypto.createHash('sha256').update(code).digest('hex');
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  db.prepare('DELETE FROM email_verifications WHERE email = ?').run(emailNorm);
  db.prepare('INSERT INTO email_verifications (email, code_hash, password_hash, expires_at) VALUES (?,?,?,?)')
    .run(emailNorm, codeHash, bcrypt.hashSync(password, 10), expires);
  // TODO: quando o SMTP for configurado, este código será enviado por e-mail
  console.log('=====================================');
  console.log('Código de verificação para ' + emailNorm + ': ' + code + ' (válido por 10 minutos)');
  console.log('=====================================');
  res.json({ ok: true, message: 'Código enviado para ' + emailNorm });
});

// ---------- Cadastro: etapa 2 (verificação do código de 6 dígitos) ----------
app.post('/api/signup/verify', (req, res) => {
  const { email, code } = req.body || {};
  const emailNorm = String(email || '').toLowerCase().trim();
  const v = db.prepare('SELECT * FROM email_verifications WHERE email = ?').get(emailNorm);
  if (!v) return res.status(400).json({ error: 'Nenhuma verificação pendente. Comece novamente.' });
  if (v.verified) return res.json({ ok: true });
  if (new Date(v.expires_at) < new Date()) return res.status(400).json({ error: 'Código expirado. Solicite um novo.' });
  if (v.attempts >= 5) return res.status(400).json({ error: 'Muitas tentativas. Solicite um novo código.' });
  const codeHash = crypto.createHash('sha256').update(String(code || '').trim()).digest('hex');
  if (codeHash !== v.code_hash) {
    db.prepare('UPDATE email_verifications SET attempts = attempts + 1 WHERE id = ?').run(v.id);
    return res.status(400).json({ error: 'Código incorreto.' });
  }
  db.prepare('UPDATE email_verifications SET verified = 1 WHERE id = ?').run(v.id);
  res.json({ ok: true });
});

// ---------- Cadastro: etapa 3 (perfil — nome da empresa) ----------
app.post('/api/signup/complete', (req, res) => {
  const { email, company_name } = req.body || {};
  const emailNorm = String(email || '').toLowerCase().trim();
  const v = db.prepare('SELECT * FROM email_verifications WHERE email = ?').get(emailNorm);
  if (!v || !v.verified) return res.status(400).json({ error: 'E-mail não verificado.' });
  if (!company_name || !String(company_name).trim()) return res.status(400).json({ error: 'Informe o nome da empresa.' });
  const exists = db.prepare('SELECT id FROM companies WHERE email = ?').get(emailNorm);
  if (exists) return res.status(400).json({ error: 'Já existe uma empresa com este e-mail.' });
  const tx = db.transaction(() => {
    const ci = db.prepare('INSERT INTO companies (name, email, password_hash) VALUES (?,?,?)')
      .run(String(company_name).trim(), emailNorm, v.password_hash);
    const ui = db.prepare('INSERT INTO users (company_id, name, email, role, password_hash, is_owner) VALUES (?,?,?,?,?,1)')
  .run(ci.lastInsertRowid, 'Gerente', emailNorm, 'manager', v.password_hash);
    db.prepare('DELETE FROM email_verifications WHERE id = ?').run(v.id);
    return ui.lastInsertRowid;
  });
  const userId = tx();
  const token = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO sessions (token, user_id) VALUES (?,?)').run(token, userId);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  const company = db.prepare('SELECT * FROM companies WHERE id = ?').get(user.company_id);
  res.json({ token, user: publicUser(user), company, sections: [] });
});

// ---------- Login (com portal: worker ou company) ----------
app.post('/api/login', (req, res) => {
  const { email, password, portal } = req.body || {};
  const emailNorm = String(email || '').toLowerCase().trim();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(emailNorm);
  if (!user) return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
  let ok = false;
  if (user.role === 'manager') {
    ok = !!user.password_hash && bcrypt.compareSync(String(password || ''), user.password_hash);
  } else {
    ok = !!user.password_enc && decrypt(user.password_enc) === String(password || '');
  }
  if (!ok) return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
  if (!user.active) return res.status(403).json({ error: 'Conta desativada. Fale com o gerente.' });
  const expectedRole = portal === 'company' ? 'manager' : 'worker';
  if (user.role !== expectedRole) {
    return res.status(403).json({ error: portal === 'company'
      ? 'Esta conta não é de empresa. Use o Portal do Trabalhador.'
      : 'Esta conta não é de trabalhador. Use o Portal da Empresa.' });
  }
  const token = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO sessions (token, user_id) VALUES (?,?)').run(token, user.id);
  const company = db.prepare('SELECT * FROM companies WHERE id = ?').get(user.company_id);
  const sections = db.prepare('SELECT * FROM sections WHERE company_id = ? ORDER BY position').all(user.company_id);
  res.json({ token, user: publicUser(user), company, sections });
});

// ---------- Recuperação de senha do gerente (via e-mail) ----------
app.post('/api/forgot-password', (req, res) => {
  const { email } = req.body || {};
  const emailNorm = String(email || '').toLowerCase().trim();
  const user = db.prepare("SELECT * FROM users WHERE email = ? AND role = 'manager'").get(emailNorm);
  if (user) {
    const token = crypto.randomBytes(24).toString('hex');
    const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    db.prepare('INSERT INTO password_resets (token, user_id, expires_at) VALUES (?,?,?)').run(token, user.id, expires);
    const link = `${req.protocol}://${req.get('host')}/reset.html?token=${token}`;
    console.log('=== Link de redefinição de senha ===');
    console.log(link);
    console.log('=====================================');
    if (process.env.SMTP_HOST) {
      const nodemailer = require('nodemailer');
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: process.env.SMTP_SECURE === 'true',
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
      });
      transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: user.email,
        subject: 'Tornang — Redefinição de senha',
        text: `Use este link para redefinir sua senha (válido por 1 hora):\n\n${link}`
      }).catch(err => console.error('Falha ao enviar e-mail:', err.message));
    }
  }
  res.json({ ok: true, message: 'Se o e-mail existir, você receberá um link de redefinição (válido por 1 hora).' });
});

app.post('/api/reset-password', (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'Token e nova senha são obrigatórios.' });
  const r = db.prepare('SELECT * FROM password_resets WHERE token = ? AND used = 0').get(token);
  if (!r) return res.status(400).json({ error: 'Link inválido ou já utilizado.' });
  if (new Date(r.expires_at) < new Date()) return res.status(400).json({ error: 'Link expirado. Solicite um novo.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(r.user_id);
  if (!user || user.role !== 'manager') return res.status(400).json({ error: 'Conta inválida.' });
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(password, 10), user.id);
  db.prepare('UPDATE password_resets SET used = 1 WHERE token = ?').run(token);
  res.json({ ok: true, message: 'Senha redefinida. Entre com a nova senha.' });
});

// ---------- Empresa ----------
app.get('/api/company', auth, (req, res) => {
  const company = db.prepare('SELECT * FROM companies WHERE id = ?').get(req.user.company_id);
  res.json({ company, user: publicUser(req.user) });
  
});

// ---------- Seções ----------
app.get('/api/company/sections', auth, (req, res) => {
  const loc = Number(req.query.loc) || null;
  const sections = db.prepare(`SELECT * FROM sections WHERE company_id = ? ${loc ? 'AND location_id = ?' : ''} ORDER BY position`)
    .all(...(loc ? [req.user.company_id, loc] : [req.user.company_id]));
  res.json({ sections });
});
app.get('/api/sections', auth, managerOnly, (req, res) => {
  const loc = Number(req.query.loc) || null;
  const sections = db.prepare(`SELECT * FROM sections WHERE company_id = ? ${loc ? 'AND location_id = ?' : ''} ORDER BY position`)
    .all(...(loc ? [req.user.company_id, loc] : [req.user.company_id]));
  res.json({ sections });
});

app.post('/api/company/sections', auth, managerOnly, (req, res) => {
  const { name, location_id } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'Informe o nome da seção.' });
  const locId = Number(location_id) || null;
  const max = db.prepare('SELECT COALESCE(MAX(position),0) AS m FROM sections WHERE company_id = ?').get(req.user.company_id).m;
  const info = db.prepare('INSERT INTO sections (company_id, name, position, location_id) VALUES (?,?,?,?)')
    .run(req.user.company_id, String(name).trim(), max + 1, locId);
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.put('/api/company/sections/:id', auth, managerOnly, (req, res) => {
  const { name } = req.body || {};
  const s = db.prepare('SELECT * FROM sections WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!s) return res.status(404).json({ error: 'Seção não encontrada.' });
  if (name && String(name).trim()) db.prepare('UPDATE sections SET name = ? WHERE id = ?').run(String(name).trim(), s.id);
  res.json({ ok: true });
});

app.post('/api/company/sections/:id/reveal', auth, managerOnly, (req, res) => {
  const s = db.prepare('SELECT * FROM sections WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!s) return res.status(404).json({ error: 'Seção não encontrada.' });
  res.json({ password: s.password_enc ? decrypt(s.password_enc) : null });
});

// ---------- Trabalhadores ----------
app.get('/api/company/workers', auth, managerOnly, (req, res) => {
  const loc = Number(req.query.loc) || null;
  const workers = db.prepare(`
    SELECT u.id, u.name, u.email, u.section_id, u.active, u.created_at, s.name AS section_name
    FROM users u LEFT JOIN sections s ON s.id = u.section_id
    WHERE u.company_id = ? AND u.role = 'worker' ${loc ? 'AND s.location_id = ?' : ''}
    ORDER BY u.name`).all(...(loc ? [req.user.company_id, loc] : [req.user.company_id]));
  res.json({ workers });
});

app.post('/api/company/workers', auth, managerOnly, (req, res) => {
  const { name, email, password, section_id } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Preencha nome, e-mail e senha.' });
  const emailNorm = String(email).toLowerCase().trim();
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(emailNorm);
  if (exists) return res.status(400).json({ error: 'Já existe uma conta com este e-mail.' });
  const sec = db.prepare('SELECT id FROM sections WHERE id = ? AND company_id = ?').get(section_id, req.user.company_id);
  if (!sec) return res.status(400).json({ error: 'Seção inválida.' });
  const info = db.prepare('INSERT INTO users (company_id, name, email, role, password_enc, section_id) VALUES (?,?,?,?,?,?)')
    .run(req.user.company_id, String(name).trim(), emailNorm, 'worker', encrypt(password), sec.id);
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.put('/api/company/workers/:id', auth, managerOnly, (req, res) => {
  const w = db.prepare("SELECT * FROM users WHERE id = ? AND company_id = ? AND role = 'worker'").get(req.params.id, req.user.company_id);
  if (!w) return res.status(404).json({ error: 'Trabalhador não encontrado.' });
  const { section_id, active, password, name } = req.body || {};
  if (name && String(name).trim()) db.prepare('UPDATE users SET name = ? WHERE id = ?').run(String(name).trim(), w.id);
  if (section_id) {
    const sec = db.prepare('SELECT id FROM sections WHERE id = ? AND company_id = ?').get(section_id, req.user.company_id);
    if (sec) db.prepare('UPDATE users SET section_id = ? WHERE id = ?').run(sec.id, w.id);
  }
  if (active !== undefined) db.prepare('UPDATE users SET active = ? WHERE id = ?').run(active ? 1 : 0, w.id);
  if (password) db.prepare('UPDATE users SET password_enc = ? WHERE id = ?').run(encrypt(password), w.id);
  res.json({ ok: true });
});

app.post('/api/company/workers/:id/reveal', auth, managerOnly, (req, res) => {
  const w = db.prepare("SELECT * FROM users WHERE id = ? AND company_id = ? AND role = 'worker'").get(req.params.id, req.user.company_id);
  if (!w) return res.status(404).json({ error: 'Trabalhador não encontrado.' });
  res.json({ password: decrypt(w.password_enc) });
});

// ---------- Projetos (gerente) ----------
app.get('/api/projects', auth, managerOnly, (req, res) => {
  const loc = Number(req.query.loc) || null;
  const projects = db.prepare(`
    SELECT p.*, s.name AS section_name, u.name AS worker_name,
      (SELECT COUNT(*) FROM project_documents d WHERE d.project_id = p.id) AS doc_count
    FROM projects p
    LEFT JOIN sections s ON s.id = p.current_section_id
    LEFT JOIN users u ON u.id = p.assigned_to
    WHERE p.company_id = ? ${loc ? 'AND p.location_id = ?' : ''}
    ORDER BY p.priority DESC,
      CASE WHEN p.status = 'completed' THEN 1 ELSE 0 END,
      CASE WHEN p.due_date IS NULL OR p.due_date = '' THEN 1 ELSE 0 END,
      p.due_date ASC, p.created_at DESC`).all(...(loc ? [req.user.company_id, loc] : [req.user.company_id]));
  res.json({ projects });
});

app.post('/api/projects', auth, managerOnly, (req, res) => {
  const { client_name, name, description, due_date, route, release_now, location_id } = req.body || {};
  if (!client_name || !String(client_name).trim()) return res.status(400).json({ error: 'Informe o cliente da folha.' });
  const locId = Number(location_id) || null;
  const sections = db.prepare(`SELECT * FROM sections WHERE company_id = ? ${locId ? 'AND location_id = ?' : ''} ORDER BY position`)
    .all(...(locId ? [req.user.company_id, locId] : [req.user.company_id]));
  if (!sections.length) return res.status(400).json({ error: 'Crie pelo menos uma seção antes de abrir folhas.' });
  let steps = Array.isArray(route) && route.length
    ? route.map(st => (Array.isArray(st) ? st : [st]).map(Number).filter(id => sections.some(s => s.id === id)))
    : sections.map(s => [s.id]);
  steps = steps.filter(st => st.length);
  if (!steps.length) return res.status(400).json({ error: 'Selecione pelo menos uma seção para a rota.' });
  const status = release_now === false ? 'pending_release' : 'in_progress';
  const info = db.prepare('INSERT INTO projects (company_id, location_id, client_name, name, description, due_date, current_section_id, status) VALUES (?,?,?,?,?,?,?,?)')
    .run(req.user.company_id, locId, String(client_name).trim(), String(name || '').trim(), String(description || '').trim(), String(due_date || '').trim() || null, steps[0][0], status);
  const projectId = info.lastInsertRowid;
  const ins = db.prepare('INSERT INTO project_route (project_id, section_id, step, status) VALUES (?,?,?,?)');
  const tx = db.transaction(() => {
    steps.forEach((st, i) => {
      const stepNo = i + 1;
      for (const sid of st) ins.run(projectId, sid, stepNo, (status === 'in_progress' && stepNo === 1) ? 'active' : 'pending');
    });
    db.prepare('INSERT INTO project_history (project_id, section_id, action) VALUES (?,?,?)').run(projectId, steps[0][0], 'created');
  });
  tx();
  res.json({ ok: true, id: projectId });
});

app.get('/api/projects/:id/history', auth, (req, res) => {
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });
  const history = db.prepare(`
    SELECT h.*, s.name AS section_name, u.name AS worker_name
    FROM project_history h
    LEFT JOIN sections s ON s.id = h.section_id
    LEFT JOIN users u ON u.id = h.worker_id
    WHERE h.project_id = ?
    ORDER BY h.created_at ASC`).all(p.id);
  res.json({ project: p, history });
});

// ---------- Fila do trabalhador ----------
app.get('/api/worker/queue', auth, (req, res) => {
  if (req.user.role !== 'worker') return res.status(403).json({ error: 'Acesso restrito.' });
  const routed = db.prepare(`
    SELECT p.*, s.name AS section_name, r.id AS route_id, r.step, r.assigned_to AS route_assigned,
      (SELECT GROUP_CONCAT(s2.name, ' + ') FROM project_route r2 JOIN sections s2 ON s2.id = r2.section_id
       WHERE r2.project_id = p.id AND r2.step = r.step AND r2.section_id != r.section_id) AS parallel_with
    FROM project_route r
    JOIN projects p ON p.id = r.project_id
    JOIN sections s ON s.id = r.section_id
    WHERE p.company_id = ? AND p.status = 'in_progress' AND r.section_id = ? AND r.status = 'active'
    ORDER BY p.priority DESC, p.due_date ASC, p.created_at DESC`).all(req.user.company_id, req.user.section_id);
  const collabIds = db.prepare('SELECT project_id FROM project_collaborators WHERE user_id = ?').all(req.user.id).map(r => r.project_id);
  const available = [];
  const mine = [];
  for (const row of routed) {
    const item = { ...row };
    delete item.route_assigned;
    if (row.route_assigned === req.user.id || collabIds.includes(row.project_id)) mine.push(item);
    else if (!row.route_assigned) available.push(item);
  }
  res.json({ available, mine });
});

app.post('/api/projects/:id/accept', auth, (req, res) => {
  if (req.user.role !== 'worker') return res.status(403).json({ error: 'Acesso restrito.' });
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });
  if (p.status !== 'in_progress') return res.status(400).json({ error: 'Esta folha não está disponível.' });
  const hasRoute = db.prepare('SELECT 1 FROM project_route WHERE project_id = ?').get(p.id);
  if (hasRoute) {
    const row = db.prepare("SELECT * FROM project_route WHERE project_id = ? AND section_id = ? AND status = 'active'").get(p.id, req.user.section_id);
    if (!row) return res.status(400).json({ error: 'Esta folha não está disponível na sua seção.' });
    if (row.assigned_to) return res.status(400).json({ error: 'Esta folha já foi assumida por outro trabalhador.' });
    db.prepare('UPDATE project_route SET assigned_to = ? WHERE id = ?').run(req.user.id, row.id);
    if (!p.assigned_to) db.prepare("UPDATE projects SET assigned_to = ?, updated_at = datetime('now') WHERE id = ?").run(req.user.id, p.id);
    db.prepare('INSERT INTO project_history (project_id, section_id, worker_id, action) VALUES (?,?,?,?)').run(p.id, req.user.section_id, req.user.id, 'accepted');
    return res.json({ ok: true });
  }
  // Folha antiga (sem rota): comportamento original
  if (p.current_section_id !== req.user.section_id) return res.status(400).json({ error: 'Esta folha não está disponível na sua seção.' });
  if (p.assigned_to) return res.status(400).json({ error: 'Esta folha já foi assumida por outro trabalhador.' });
  db.prepare("UPDATE projects SET assigned_to = ?, updated_at = datetime('now') WHERE id = ?").run(req.user.id, p.id);
  db.prepare('INSERT INTO project_history (project_id, section_id, worker_id, action) VALUES (?,?,?,?)').run(p.id, p.current_section_id, req.user.id, 'accepted');
  res.json({ ok: true });
});

app.post('/api/projects/:id/finish', auth, (req, res) => {
  if (req.user.role !== 'worker') return res.status(403).json({ error: 'Acesso restrito.' });
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });
  const hasRoute = db.prepare('SELECT 1 FROM project_route WHERE project_id = ?').get(p.id);
  if (hasRoute) {
    const row = db.prepare("SELECT * FROM project_route WHERE project_id = ? AND section_id = ? AND status = 'active'").get(p.id, req.user.section_id);
    if (!row) return res.status(400).json({ error: 'Esta folha não está na sua seção agora.' });
    const isHolder = row.assigned_to === req.user.id;
    const isCollab = !!db.prepare('SELECT 1 FROM project_collaborators WHERE project_id = ? AND user_id = ?').get(p.id, req.user.id);
    if (!isHolder && !isCollab) return res.status(400).json({ error: 'Você não participa desta folha.' });
    const tx = db.transaction(() => {
      db.prepare("UPDATE project_route SET status = 'done' WHERE id = ?").run(row.id);
      db.prepare('INSERT INTO project_history (project_id, section_id, worker_id, action) VALUES (?,?,?,?)').run(p.id, row.section_id, req.user.id, 'finished');
      const pendingSameStep = db.prepare("SELECT COUNT(*) AS n FROM project_route WHERE project_id = ? AND step = ? AND status != 'done'").get(p.id, row.step).n;
      if (pendingSameStep > 0) return; // aguardando seções em paralelo concluírem
      const nextStep = db.prepare("SELECT MIN(step) AS s FROM project_route WHERE project_id = ? AND status = 'pending'").get(p.id).s;
      if (nextStep == null) {
        db.prepare("UPDATE projects SET status = 'completed', assigned_to = NULL, current_section_id = NULL, updated_at = datetime('now') WHERE id = ?").run(p.id);
      } else {
        db.prepare("UPDATE project_route SET status = 'active' WHERE project_id = ? AND step = ?").run(p.id, nextStep);
        const first = db.prepare('SELECT section_id FROM project_route WHERE project_id = ? AND step = ? ORDER BY id LIMIT 1').get(p.id, nextStep);
        db.prepare("UPDATE projects SET current_section_id = ?, assigned_to = NULL, updated_at = datetime('now') WHERE id = ?").run(first.section_id, p.id);
        db.prepare('INSERT INTO project_history (project_id, section_id, worker_id, action) VALUES (?,?,?,?)').run(p.id, first.section_id, req.user.id, 'passed');
      }
    });
    tx();
    const waitingFor = db.prepare("SELECT GROUP_CONCAT(s.name, ' + ') AS n FROM project_route r JOIN sections s ON s.id = r.section_id WHERE r.project_id = ? AND r.step = ? AND r.status != 'done'").get(p.id, row.step).n;
    const proj = db.prepare('SELECT status FROM projects WHERE id = ?').get(p.id);
    let next = null;
    if (proj.status === 'in_progress' && !waitingFor) {
      const nx = db.prepare("SELECT s.name FROM project_route r JOIN sections s ON s.id = r.section_id WHERE r.project_id = ? AND r.status = 'active' ORDER BY r.id LIMIT 1").get(p.id);
      next = nx ? nx.name : null;
    }
    return res.json({ ok: true, waiting: !!waitingFor, waiting_for: waitingFor, next, completed: proj.status === 'completed' });
  }
  // Folha antiga (sem rota): comportamento original
  const isCollabOld = !!db.prepare('SELECT 1 FROM project_collaborators WHERE project_id = ? AND user_id = ?').get(p.id, req.user.id);
  if (p.assigned_to !== req.user.id && !isCollabOld) return res.status(400).json({ error: 'Você não é o responsável por esta folha.' });
  const cur = p.current_section_id ? db.prepare('SELECT * FROM sections WHERE id = ?').get(p.current_section_id) : null;
  const next = cur ? db.prepare('SELECT * FROM sections WHERE company_id = ? AND position > ? ORDER BY position LIMIT 1').get(req.user.company_id, cur.position) : null;
  const tx = db.transaction(() => {
    if (next) {
      db.prepare("UPDATE projects SET current_section_id = ?, assigned_to = NULL, updated_at = datetime('now') WHERE id = ?").run(next.id, p.id);
      db.prepare('INSERT INTO project_history (project_id, section_id, worker_id, action) VALUES (?,?,?,?)').run(p.id, p.current_section_id, req.user.id, 'finished');
      db.prepare('INSERT INTO project_history (project_id, section_id, worker_id, action) VALUES (?,?,?,?)').run(p.id, next.id, req.user.id, 'passed');
    } else {
      db.prepare("UPDATE projects SET status = 'completed', assigned_to = NULL, updated_at = datetime('now') WHERE id = ?").run(p.id);
      db.prepare('INSERT INTO project_history (project_id, section_id, worker_id, action) VALUES (?,?,?,?)').run(p.id, p.current_section_id, req.user.id, 'finished');
    }
  });
  tx();
  res.json({ ok: true, next: next ? next.name : null, completed: !next });
});

app.get('/api/worker/history', auth, (req, res) => {
  if (req.user.role !== 'worker') return res.status(403).json({ error: 'Acesso restrito.' });
  const history = db.prepare(`
    SELECT h.*, p.client_name, p.name AS project_name, s.name AS section_name
    FROM project_history h
    JOIN projects p ON p.id = h.project_id
    LEFT JOIN sections s ON s.id = h.section_id
    WHERE h.worker_id = ?
    ORDER BY h.created_at DESC LIMIT 100`).all(req.user.id);
  res.json({ history });
});

// ---------- Perfil da empresa ----------
app.put('/api/company/profile', auth, managerOnly, (req, res) => {
  const { company_name, nif, address, phone, website } = req.body || {};
  if (!company_name || !String(company_name).trim()) return res.status(400).json({ error: 'O nome da empresa é obrigatório.' });
  db.prepare('UPDATE companies SET name = ?, nif = ?, address = ?, phone = ?, website = ? WHERE id = ?')
    .run(String(company_name).trim(), String(nif || '').trim(), String(address || '').trim(), String(phone || '').trim(), String(website || '').trim(), req.user.company_id);
  const company = db.prepare('SELECT * FROM companies WHERE id = ?').get(req.user.company_id);
  res.json({ ok: true, company });
});
// ---------- E-mail da conta da empresa (protegido por senha) ----------
app.post('/api/company/email', auth, managerOnly, (req, res) => {
  const { email, current_password } = req.body || {};
  const emailNorm = String(email || '').toLowerCase().trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNorm)) return res.status(400).json({ error: 'E-mail inválido.' });
  if (!bcrypt.compareSync(String(current_password || ''), req.user.password_hash || '')) {
    return res.status(400).json({ error: 'Senha atual incorreta.' });
  }
  const exists = db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(emailNorm, req.user.id);
  if (exists) return res.status(400).json({ error: 'Já existe uma conta com este e-mail.' });
  const tx = db.transaction(() => {
    db.prepare('UPDATE companies SET email = ? WHERE id = ?').run(emailNorm, req.user.company_id);
    db.prepare('UPDATE users SET email = ? WHERE id = ?').run(emailNorm, req.user.id);
  });
  tx();
  const company = db.prepare('SELECT * FROM companies WHERE id = ?').get(req.user.company_id);
  res.json({ ok: true, company });
});
// ---------- Perfil do gerente (nome, telefone e e-mail) ----------
app.put('/api/manager/profile', auth, managerOnly, (req, res) => {
  const { name, email, phone, current_password } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'O nome é obrigatório.' });
  const emailNorm = String(email || '').toLowerCase().trim();
  const emailChanged = emailNorm && emailNorm !== req.user.email;
  if (emailChanged) {
    if (!bcrypt.compareSync(String(current_password || ''), req.user.password_hash || '')) {
      return res.status(400).json({ error: 'Informe a senha atual correta para alterar o e-mail.' });
    }
    const exists = db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(emailNorm, req.user.id);
    if (exists) return res.status(400).json({ error: 'Já existe uma conta com este e-mail.' });
  }
  db.prepare('UPDATE users SET name = ?, phone = ? WHERE id = ?')
    .run(String(name).trim(), String(phone || '').trim(), req.user.id);
  if (emailChanged) db.prepare('UPDATE users SET email = ? WHERE id = ?').run(emailNorm, req.user.id);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  res.json({ ok: true, user: publicUser(user) });
});

// ---------- Colaboradores (gerentes adicionais) ----------
app.get('/api/company/collaborators', auth, managerOnly, (req, res) => {
  const collaborators = db.prepare(`
    SELECT id, name, email, is_owner, active, created_at
    FROM users WHERE company_id = ? AND role = 'manager'
    ORDER BY is_owner DESC, name`).all(req.user.company_id);
  res.json({ collaborators });
});

app.post('/api/company/collaborators', auth, managerOnly, (req, res) => {
  const { name, email } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'Informe o nome do colaborador.' });
  const emailNorm = String(email || '').toLowerCase().trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNorm)) return res.status(400).json({ error: 'E-mail inválido.' });
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(emailNorm);
  if (exists) return res.status(400).json({ error: 'Já existe uma conta com este e-mail.' });
  const password = crypto.randomBytes(4).toString('hex');
  const info = db.prepare("INSERT INTO users (company_id, name, email, role, password_hash) VALUES (?,?,?,'manager',?)")
    .run(req.user.company_id, String(name).trim(), emailNorm, bcrypt.hashSync(password, 10));
  console.log('=====================================');
  console.log('Colaborador criado: ' + emailNorm + ' | senha inicial: ' + password);
  console.log('=====================================');
  // TODO: enviar esta senha por e-mail quando o SMTP for configurado
  res.json({ ok: true, id: info.lastInsertRowid, password });
});

app.put('/api/company/collaborators/:id', auth, managerOnly, (req, res) => {
  const c = db.prepare("SELECT * FROM users WHERE id = ? AND company_id = ? AND role = 'manager'").get(req.params.id, req.user.company_id);
  if (!c) return res.status(404).json({ error: 'Colaborador não encontrado.' });
  const { active } = req.body || {};
  if (c.is_owner && active === false) return res.status(400).json({ error: 'A conta principal não pode ser desativada.' });
  if (active !== undefined) db.prepare('UPDATE users SET active = ? WHERE id = ?').run(active ? 1 : 0, c.id);
  res.json({ ok: true });
});

app.post('/api/company/collaborators/:id/reset', auth, managerOnly, (req, res) => {
  const c = db.prepare("SELECT * FROM users WHERE id = ? AND company_id = ? AND role = 'manager'").get(req.params.id, req.user.company_id);
  if (!c) return res.status(404).json({ error: 'Colaborador não encontrado.' });
  if (c.is_owner) return res.status(400).json({ error: 'A senha da conta principal só pode ser alterada pelo próprio dono ou via e-mail.' });
  const password = crypto.randomBytes(4).toString('hex');
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(password, 10), c.id);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(c.id);
  console.log('=====================================');
  console.log('Senha redefinida para ' + c.email + ': ' + password);
  console.log('=====================================');
  res.json({ ok: true, password });
});

app.delete('/api/company/collaborators/:id', auth, managerOnly, (req, res) => {
  const c = db.prepare("SELECT * FROM users WHERE id = ? AND company_id = ? AND role = 'manager'").get(req.params.id, req.user.company_id);
  if (!c) return res.status(404).json({ error: 'Colaborador não encontrado.' });
  if (c.is_owner) return res.status(400).json({ error: 'A conta principal não pode ser removida.' });
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(c.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(c.id);
  res.json({ ok: true });
});

// ---------- Alterar a própria senha (gerente) ----------
app.post('/api/manager/change-password', auth, managerOnly, (req, res) => {
  const { current, password } = req.body || {};
  if (!bcrypt.compareSync(String(current || ''), req.user.password_hash || '')) {
    return res.status(400).json({ error: 'Senha atual incorreta.' });
  }
  if (!password || String(password).length < 4) return res.status(400).json({ error: 'A nova senha precisa ter pelo menos 4 caracteres.' });
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(password, 10), req.user.id);
  res.json({ ok: true });
});

// ---------- Prioridade ----------
app.post('/api/projects/:id/priority', auth, managerOnly, (req, res) => {
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });
  const priority = p.priority ? 0 : 1;
  db.prepare('UPDATE projects SET priority = ? WHERE id = ?').run(priority, p.id);
  res.json({ ok: true, priority });
});

// ---------- Liberação manual da folha ----------
app.post('/api/projects/:id/release', auth, managerOnly, (req, res) => {
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });
  if (p.status !== 'pending_release') return res.status(400).json({ error: 'Esta folha já foi liberada.' });
  const first = db.prepare('SELECT section_id FROM project_route WHERE project_id = ? ORDER BY step, id LIMIT 1').get(p.id);
  const tx = db.transaction(() => {
    db.prepare("UPDATE project_route SET status = 'active' WHERE project_id = ? AND step = (SELECT MIN(step) FROM project_route WHERE project_id = ?)").run(p.id, p.id);
    db.prepare("UPDATE projects SET status = 'in_progress', current_section_id = ? WHERE id = ?").run(first ? first.section_id : null, p.id);
    db.prepare('INSERT INTO project_history (project_id, section_id, action) VALUES (?,?,?)').run(p.id, first ? first.section_id : null, 'released');
  });
  tx();
  res.json({ ok: true });
});

// ---------- Editar a rota durante a produção ----------
app.put('/api/projects/:id/route', auth, managerOnly, (req, res) => {
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });
  if (p.status === 'completed') return res.status(400).json({ error: 'Esta folha já está concluída.' });
  const { route } = req.body || {};
  const sections = db.prepare('SELECT * FROM sections WHERE company_id = ? ORDER BY position').all(req.user.company_id);
  let steps = Array.isArray(route) && route.length
    ? route.map(st => (Array.isArray(st) ? st : [st]).map(Number).filter(id => sections.some(s => s.id === id)))
    : [];
  steps = steps.filter(st => st.length);
  if (!steps.length) return res.status(400).json({ error: 'A rota precisa de pelo menos uma seção.' });
  const doneRows = db.prepare("SELECT section_id FROM project_route WHERE project_id = ? AND status = 'done'").all(p.id);
  const activateFirst = p.status === 'in_progress';
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM project_route WHERE project_id = ? AND status != 'done'").run(p.id);
    const ins = db.prepare('INSERT INTO project_route (project_id, section_id, step, status) VALUES (?,?,?,?)');
    steps.forEach((st, i) => {
      const stepNo = i + 1;
      for (const sid of st) {
        const wasDone = doneRows.some(d => d.section_id === sid);
        ins.run(p.id, sid, stepNo, wasDone ? 'done' : (activateFirst && stepNo === 1 ? 'active' : 'pending'));
      }
    });
    const cur = db.prepare("SELECT section_id FROM project_route WHERE project_id = ? AND status = 'active' ORDER BY id LIMIT 1").get(p.id);
    db.prepare('UPDATE projects SET current_section_id = ? WHERE id = ?').run(cur ? cur.section_id : null, p.id);
    db.prepare('INSERT INTO project_history (project_id, section_id, action) VALUES (?,?,?)').run(p.id, cur ? cur.section_id : null, 'route_updated');
  });
  tx();
  res.json({ ok: true });
});

// ---------- Documentos ----------
const uploadDir = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(DATA_DIR, 'uploads')),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + crypto.randomBytes(4).toString('hex') + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 25 * 1024 * 1024 } });

// ---------- Logo da empresa ----------
app.post('/api/company/logo', auth, managerOnly, upload.single('logo'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Envie uma imagem.' });
  if (!(req.file.mimetype || '').startsWith('image/')) {
    try { fs.unlinkSync(path.join(uploadDir, req.file.filename)); } catch (e) {}
    return res.status(400).json({ error: 'O arquivo precisa ser uma imagem.' });
  }
  const company = db.prepare('SELECT * FROM companies WHERE id = ?').get(req.user.company_id);
  if (company && company.logo) {
    try { fs.unlinkSync(path.join(uploadDir, company.logo.replace(/^\/?uploads\//, ''))); } catch (e) {}
  }
  db.prepare('UPDATE companies SET logo = ? WHERE id = ?').run('uploads/' + req.file.filename, req.user.company_id);
  const updated = db.prepare('SELECT * FROM companies WHERE id = ?').get(req.user.company_id);
  res.json({ ok: true, company: updated });
});

app.get('/api/projects/:id/detail', auth, (req, res) => {
  const p = db.prepare(`
    SELECT p.*, s.name AS section_name, u.name AS worker_name
    FROM projects p
    LEFT JOIN sections s ON s.id = p.current_section_id
    LEFT JOIN users u ON u.id = p.assigned_to
    WHERE p.id = ? AND p.company_id = ?`).get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });
  const documents = db.prepare('SELECT id, original_name, mime_type, size, created_at FROM project_documents WHERE project_id = ? ORDER BY created_at DESC').all(p.id);
  const sections = p.location_id
    ? db.prepare('SELECT id, name, position FROM sections WHERE company_id = ? AND location_id = ? ORDER BY position').all(req.user.company_id, p.location_id)
    : db.prepare('SELECT id, name, position FROM sections WHERE company_id = ? ORDER BY position').all(req.user.company_id);
    const route = db.prepare('SELECT r.section_id, r.step, r.status, s.name FROM project_route r JOIN sections s ON s.id = r.section_id WHERE r.project_id = ? ORDER BY r.step, s.name').all(p.id);
   res.json({ project: p, documents, sections, route });
});

app.post('/api/projects/:id/documents', auth, upload.array('files', 20), (req, res) => {
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });
  const me = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (me.role !== 'manager') {
    if (!me.section_id) return res.status(403).json({ error: 'Você não pertence a uma seção.' });
    const active = db.prepare("SELECT 1 FROM project_route WHERE project_id = ? AND section_id = ? AND status = 'active'").get(p.id, me.section_id);
    if (!active) return res.status(403).json({ error: 'Este projeto não está na sua seção agora.' });
  }
  for (const f of req.files || []) {
    db.prepare('INSERT INTO project_documents (project_id, stored_name, original_name, mime_type, size, uploaded_by) VALUES (?,?,?,?,?,?)')
      .run(p.id, f.filename, f.originalname, f.mimetype, f.size, req.user.id);
  }
  res.json({ ok: true, count: (req.files || []).length });
});

app.get('/api/projects/:id/documents', auth, (req, res) => {
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });
  const docs = db.prepare(`
    SELECT d.*, u.name AS uploader_name FROM project_documents d
    LEFT JOIN users u ON u.id = d.uploaded_by
    WHERE d.project_id = ? ORDER BY d.id DESC`).all(p.id);
  res.json({ documents: docs });
});

app.delete('/api/documents/:id', auth, managerOnly, (req, res) => {
  const d = db.prepare('SELECT d.*, p.company_id FROM project_documents d JOIN projects p ON p.id = d.project_id WHERE d.id = ?').get(req.params.id);
  if (!d || d.company_id !== req.user.company_id) return res.status(404).json({ error: 'Arquivo não encontrado.' });
  try { fs.unlinkSync(path.join(uploadDir, d.stored_name)); } catch (e) {}
  db.prepare('DELETE FROM project_documents WHERE id = ?').run(d.id);
  res.json({ ok: true });
});

app.get('/api/documents/:id/file', auth, (req, res) => {
  const d = db.prepare('SELECT d.*, p.company_id FROM project_documents d JOIN projects p ON p.id = d.project_id WHERE d.id = ?').get(req.params.id);
  if (!d || d.company_id !== req.user.company_id) return res.status(404).json({ error: 'Arquivo não encontrado.' });
  const filePath = path.join(uploadDir, d.stored_name);
  if (req.query.dl === '1') res.download(filePath, d.original_name);
  else res.sendFile(filePath);
});

// ==================== v2.5.0 — foto de perfil do usuário ====================
// INTEGRAÇÃO:
// - `auth`  → troque pelo nome do seu middleware de rotas protegidas
//             (o mesmo que /api/manager/profile usa)
// - `req.user.id` → ajuste se o seu middleware guardar o usuário de outra forma
// - caminho salvo no banco → confira o formato que o /api/company/logo usa
//   ('/uploads/...' ou 'uploads/...') e mantenha o mesmo padrão

const AVATAR_MIMES = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp' };
const AVATAR_MAX_BYTES = 2 * 1024 * 1024; // 2 MB

function deleteAvatarFile(relPath) {
  if (!relPath) return;
  try { fs.unlinkSync(path.join(__dirname, relPath)); } catch (e) {}
}

// POST /api/user/avatar — recebe { image: "data:image/png;base64,..." }
app.post('/api/user/avatar', auth, (req, res) => {
  try {
    const m = String(req.body.image || '').match(/^data:(image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$/);
    if (!m) return res.status(400).json({ error: 'Envie uma imagem PNG, JPG ou WEBP.' });
    const buf = Buffer.from(m[2], 'base64');
    if (buf.length > AVATAR_MAX_BYTES) return res.status(400).json({ error: 'Imagem muito grande (máximo 2 MB).' });
    const old = db.prepare('SELECT avatar FROM users WHERE id = ?').get(req.user.id);
    deleteAvatarFile(old && old.avatar);
    const stored = `avatar-${req.user.id}-${Date.now()}.${AVATAR_MIMES[m[1]]}`;
    fs.writeFileSync(path.join(__dirname, 'uploads', stored), buf);
    db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run('/uploads/' + stored, req.user.id);
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    res.json({ user: publicUser(u) });
  } catch (e) {
    res.status(500).json({ error: 'Erro ao salvar a foto.' });
  }
});

// DELETE /api/user/avatar — remove a foto (volta a mostrar a inicial)
app.delete('/api/user/avatar', auth, (req, res) => {
  try {
    const old = db.prepare('SELECT avatar FROM users WHERE id = ?').get(req.user.id);
    deleteAvatarFile(old && old.avatar);
    db.prepare('UPDATE users SET avatar = NULL WHERE id = ?').run(req.user.id);
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    res.json({ user: publicUser(u) });
  } catch (e) {
    res.status(500).json({ error: 'Erro ao remover a foto.' });
  }
});

// ==================== v3.0.0 — Locais e Dashboard ====================
// INTEGRAÇÃO: usa o mesmo middleware `auth` dos endpoints anteriores.
// Se o seu middleware tiver outro nome, troque abaixo.

function getMe(req) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
}

app.get('/api/locations', auth, (req, res) => {
  const me = getMe(req);
  const locs = db.prepare('SELECT * FROM locations WHERE company_id = ? ORDER BY id').all(me.company_id);
  res.json({ locations: locs });
});

app.post('/api/locations', auth, (req, res) => {
  const me = getMe(req);
  if (me.role !== 'manager') return res.status(403).json({ error: 'Apenas o gestor pode criar locais.' });
  const name = String(req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'O nome do local é obrigatório.' });
  const info = db.prepare('INSERT INTO locations (company_id, name, address) VALUES (?, ?, ?)')
    .run(me.company_id, name, String(req.body.address || '').trim() || null);
  res.json({ location: db.prepare('SELECT * FROM locations WHERE id = ?').get(info.lastInsertRowid) });
});

app.put('/api/locations/:id', auth, (req, res) => {
  const me = getMe(req);
  if (me.role !== 'manager') return res.status(403).json({ error: 'Apenas o gestor pode editar locais.' });
  const loc = db.prepare('SELECT * FROM locations WHERE id = ? AND company_id = ?').get(req.params.id, me.company_id);
  if (!loc) return res.status(404).json({ error: 'Local não encontrado.' });
  const name = String(req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'O nome do local é obrigatório.' });
  db.prepare('UPDATE locations SET name = ?, address = ? WHERE id = ?')
    .run(name, String(req.body.address || '').trim() || null, loc.id);
  res.json({ location: db.prepare('SELECT * FROM locations WHERE id = ?').get(loc.id) });
});

app.post('/api/locations/:id/image', auth, (req, res) => {
  const me = getMe(req);
  if (me.role !== 'manager') return res.status(403).json({ error: 'Apenas o gestor pode alterar a imagem.' });
  const loc = db.prepare('SELECT * FROM locations WHERE id = ? AND company_id = ?').get(req.params.id, me.company_id);
  if (!loc) return res.status(404).json({ error: 'Local não encontrado.' });
  const m = String(req.body.image || '').match(/^data:(image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$/);
  if (!m) return res.status(400).json({ error: 'Envie uma imagem PNG, JPG ou WEBP.' });
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length > 2 * 1024 * 1024) return res.status(400).json({ error: 'Imagem muito grande (máximo 2 MB).' });
  if (loc.image) { try { fs.unlinkSync(path.join(__dirname, loc.image)); } catch (e) {} }
  const ext = m[1].split('/')[1] === 'jpeg' ? 'jpg' : m[1].split('/')[1];
  const stored = `location-${loc.id}-${Date.now()}.${ext}`;
  fs.writeFileSync(path.join(__dirname, 'uploads', stored), buf);
  db.prepare('UPDATE locations SET image = ? WHERE id = ?').run('/uploads/' + stored, loc.id);
  res.json({ location: db.prepare('SELECT * FROM locations WHERE id = ?').get(loc.id) });
});

// DELETE /api/locations/:id — exclui um local (se não estiver em uso)
app.delete('/api/locations/:id', auth, (req, res) => {
  const me = getMe(req);
  if (me.role !== 'manager') return res.status(403).json({ error: 'Apenas o gestor pode remover locais.' });
  const loc = db.prepare('SELECT * FROM locations WHERE id = ? AND company_id = ?').get(req.params.id, me.company_id);
  if (!loc) return res.status(404).json({ error: 'Local não encontrado.' });
  const total = db.prepare('SELECT COUNT(*) c FROM locations WHERE company_id = ?').get(me.company_id).c;
  if (total <= 1) return res.status(400).json({ error: 'A empresa precisa de pelo menos um local.' });
  const inUse = {
    sections: db.prepare('SELECT COUNT(*) c FROM sections WHERE location_id = ?').get(loc.id).c,
    users: db.prepare('SELECT COUNT(*) c FROM users WHERE location_id = ?').get(loc.id).c,
    projects: db.prepare('SELECT COUNT(*) c FROM projects WHERE location_id = ?').get(loc.id).c
  };
  if (inUse.sections || inUse.users || inUse.projects) {
    return res.status(400).json({ error: `Este local está em uso: ${inUse.sections} seções, ${inUse.users} usuários, ${inUse.projects} projetos. Mova ou remova esses itens antes de excluir.` });
  }
  if (loc.image) { try { fs.unlinkSync(path.join(__dirname, loc.image)); } catch (e) {} }
  db.prepare('DELETE FROM locations WHERE id = ?').run(loc.id);
  res.json({ ok: true });
});

app.get('/api/dashboard', auth, (req, res) => {
  const me = getMe(req);
  let locs = db.prepare('SELECT * FROM locations WHERE company_id = ? ORDER BY id').all(me.company_id);
  if (me.role !== 'manager') {
    // Trabalhador vê apenas o local da sua seção
    const sec = me.section_id ? db.prepare('SELECT location_id FROM sections WHERE id = ?').get(me.section_id) : null;
    locs = sec ? locs.filter(l => l.id === sec.location_id) : [];
  }
  const data = locs.map(l => {
    const active = db.prepare("SELECT COUNT(*) c FROM projects WHERE location_id = ? AND status = 'in_progress'").get(l.id).c;
    const urgent = db.prepare("SELECT COUNT(*) c FROM projects WHERE location_id = ? AND status = 'in_progress' AND priority > 0").get(l.id).c;
    const overdue = db.prepare("SELECT COUNT(*) c FROM projects WHERE location_id = ? AND status = 'in_progress' AND due_date IS NOT NULL AND due_date < date('now')").get(l.id).c;
    const urgentList = db.prepare(`
      SELECT p.id, p.name, p.client_name, p.priority, p.due_date, s.name AS section_name
      FROM projects p LEFT JOIN sections s ON s.id = p.current_section_id
      WHERE p.location_id = ? AND p.status = 'in_progress'
      ORDER BY p.priority DESC, (p.due_date IS NULL), p.due_date ASC
      LIMIT 3`).all(l.id);
    return { ...l, active_projects: active, urgent, overdue, urgent_list: urgentList };
  });
    const recent = db.prepare(`
    SELECT h.action, h.notes, h.created_at, p.name AS project_name, p.client_name, u.name AS user_name
    FROM project_history h
    JOIN projects p ON p.id = h.project_id
    LEFT JOIN users u ON u.id = h.worker_id
    WHERE p.company_id = ?
    ORDER BY h.id DESC LIMIT 6
  `).all(me.company_id);
  res.json({ locations: data, recent });
});

// ==================== v3.2.0 — Anotações e alertas rápidos ====================
app.get('/api/projects/:id/notes', auth, (req, res) => {
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const notes = db.prepare(`
    SELECT n.*, s.name AS section_name
    FROM project_notes n LEFT JOIN sections s ON s.id = n.section_id
    WHERE n.project_id = ? ORDER BY n.id DESC LIMIT 100`).all(p.id);
  res.json({ notes });
});

app.post('/api/projects/:id/notes', auth, (req, res) => {
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const me = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const note = String(req.body.note || '').trim();
  const isAlert = req.body.is_alert ? 1 : 0;
  const alertType = String(req.body.alert_type || '').trim() || null;
  if (!note && !isAlert) return res.status(400).json({ error: 'Escreva a anotação.' });
  if (me.role !== 'manager') {
    if (!me.section_id) return res.status(403).json({ error: 'Você não pertence a uma seção.' });
    const active = db.prepare("SELECT 1 FROM project_route WHERE project_id = ? AND section_id = ? AND status = 'active'").get(p.id, me.section_id);
    if (!active) return res.status(403).json({ error: 'Este projeto não está na sua seção agora.' });
  }
  const info = db.prepare('INSERT INTO project_notes (project_id, section_id, user_id, author_name, note, is_alert, alert_type) VALUES (?,?,?,?,?,?,?)')
    .run(p.id, me.section_id || null, me.id, me.name, note || alertType || 'Alerta', isAlert, alertType);
  if (isAlert) {
    const isEmergency = /emergência|incêndio/i.test(alertType || '');
    db.prepare(`INSERT INTO notifications (company_id, role, type, title, body, project_id) VALUES (?, 'manager', ?, ?, ?, ?)`)
      .run(me.company_id, isEmergency ? 'emergency' : 'alert', (isEmergency ? '🚨 ' : '⚠️ ') + (alertType || 'Alerta'), (me.name + ' — ' + (p.name || p.client_name) + (note ? ': ' + note : '')).trim(), p.id);
  }
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.get('/api/notifications', auth, (req, res) => {
  const me = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const nots = db.prepare(`SELECT * FROM notifications WHERE company_id = ? AND (user_id = ? OR (user_id IS NULL AND role = ?)) ORDER BY id DESC LIMIT 30`)
    .all(me.company_id, me.id, me.role);
  const unread = db.prepare(`SELECT COUNT(*) c FROM notifications WHERE company_id = ? AND read = 0 AND (user_id = ? OR (user_id IS NULL AND role = ?))`)
    .get(me.company_id, me.id, me.role).c;
  res.json({ notifications: nots, unread });
});

app.post('/api/notifications/read', auth, (req, res) => {
  const me = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  db.prepare(`UPDATE notifications SET read = 1 WHERE company_id = ? AND read = 0 AND (user_id = ? OR (user_id IS NULL AND role = ?))`)
    .run(me.company_id, me.id, me.role);
  res.json({ ok: true });
});

// ==================== v3.6.0 — Emergência flutuante ====================
app.post('/api/emergency', auth, (req, res) => {
  const type = String(req.body.type || '').trim();
  if (!/emergência médica|incêndio/i.test(type)) return res.status(400).json({ error: 'Tipo de emergência inválido.' });
  const me = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const sec = me.section_id ? db.prepare('SELECT name FROM sections WHERE id = ?').get(me.section_id) : null;
  let context = me.name + (sec ? ' — Seção: ' + sec.name : '');
  let projectId = null;
  if (req.body.project_id) {
    const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.body.project_id, me.company_id);
    if (p) { projectId = p.id; context += ' — Folha: ' + (p.name || p.client_name); }
  }
  db.prepare(`INSERT INTO notifications (company_id, role, type, title, body, project_id) VALUES (?, 'manager', 'emergency', ?, ?, ?)`)
    .run(me.company_id, '🚨 ' + type, context, projectId);
  res.json({ ok: true });
});

// ==================== v3.5.0 — Colaboração na seção ====================
app.get('/api/worker/section-queue', auth, (req, res) => {
  if (req.user.role !== 'worker') return res.status(403).json({ error: 'Acesso restrito.' });
  const others = db.prepare(`
    SELECT p.*, s.name AS section_name, u.name AS holder_name,
      (SELECT GROUP_CONCAT(s2.name, ' + ') FROM project_route r2 JOIN sections s2 ON s2.id = r2.section_id
       WHERE r2.project_id = p.id AND r2.step = r.step AND r2.section_id != r.section_id) AS parallel_with
    FROM project_route r
    JOIN projects p ON p.id = r.project_id
    JOIN sections s ON s.id = r.section_id
    JOIN users u ON u.id = r.assigned_to
    WHERE p.company_id = ? AND p.status = 'in_progress' AND r.section_id = ? AND r.status = 'active'
      AND r.assigned_to IS NOT NULL AND r.assigned_to != ?
    ORDER BY p.priority DESC, p.due_date ASC, p.created_at DESC`).all(req.user.company_id, req.user.section_id, req.user.id);
  res.json({ others });
});

app.post('/api/projects/:id/join-request', auth, (req, res) => {
  if (req.user.role !== 'worker') return res.status(403).json({ error: 'Acesso restrito.' });
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });
  const me = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!me.section_id) return res.status(403).json({ error: 'Você não pertence a uma seção.' });
  const route = db.prepare("SELECT * FROM project_route WHERE project_id = ? AND section_id = ? AND status = 'active'").get(p.id, me.section_id);
  if (!route) return res.status(403).json({ error: 'Este projeto não está na sua seção agora.' });
  if (route.assigned_to === me.id) return res.status(400).json({ error: 'Esta folha já é sua.' });
  if (!route.assigned_to) return res.status(400).json({ error: 'Esta folha está livre — assuma em vez de pedir.' });
  if (db.prepare('SELECT 1 FROM project_collaborators WHERE project_id = ? AND user_id = ?').get(p.id, me.id))
    return res.status(400).json({ error: 'Você já participa desta folha.' });
  if (db.prepare("SELECT 1 FROM join_requests WHERE project_id = ? AND requester_id = ? AND status = 'pending'").get(p.id, me.id))
    return res.status(400).json({ error: 'Você já tem um pedido pendente nesta folha.' });
  const jri = db.prepare('INSERT INTO join_requests (project_id, requester_id, holder_id) VALUES (?,?,?)').run(p.id, me.id, route.assigned_to);
  db.prepare(`INSERT INTO notifications (company_id, user_id, type, title, body, project_id, ref_id) VALUES (?, ?, 'join_request', '🤝 Pedido de participação', ?, ?, ?)`)
    .run(me.company_id, route.assigned_to, me.name + ' quer participar da folha ' + (p.name || p.client_name) + '.', p.id, jri.lastInsertRowid);
  res.json({ ok: true });
});

app.post('/api/join-requests/:id/accept', auth, (req, res) => {
  const jr = db.prepare('SELECT * FROM join_requests WHERE id = ?').get(req.params.id);
  if (!jr || jr.status !== 'pending') return res.status(404).json({ error: 'Pedido não encontrado.' });
  if (jr.holder_id !== req.user.id) return res.status(403).json({ error: 'Apenas quem tem a folha pode aceitar.' });
  const p = db.prepare('SELECT * FROM projects WHERE id = ?').get(jr.project_id);
  db.prepare('INSERT OR IGNORE INTO project_collaborators (project_id, user_id) VALUES (?,?)').run(jr.project_id, jr.requester_id);
  db.prepare("UPDATE join_requests SET status = 'accepted' WHERE id = ?").run(jr.id);
  db.prepare(`INSERT INTO notifications (company_id, user_id, type, title, body, project_id) VALUES (?, ?, 'join_ok', '✅ Pedido aceito', ?, ?)`)
    .run(req.user.company_id, jr.requester_id, (req.user.name || 'Seu colega') + ' aceitou sua participação na folha ' + (p.name || p.client_name) + '.', jr.project_id);
  res.json({ ok: true });
});

app.post('/api/join-requests/:id/refuse', auth, (req, res) => {
  const jr = db.prepare('SELECT * FROM join_requests WHERE id = ?').get(req.params.id);
  if (!jr || jr.status !== 'pending') return res.status(404).json({ error: 'Pedido não encontrado.' });
  if (jr.holder_id !== req.user.id) return res.status(403).json({ error: 'Apenas quem tem a folha pode recusar.' });
  const p = db.prepare('SELECT * FROM projects WHERE id = ?').get(jr.project_id);
  db.prepare("UPDATE join_requests SET status = 'refused' WHERE id = ?").run(jr.id);
  db.prepare(`INSERT INTO notifications (company_id, user_id, type, title, body, project_id) VALUES (?, ?, 'join_no', '❌ Pedido recusado', ?, ?)`)
    .run(req.user.company_id, jr.requester_id, (req.user.name || 'Seu colega') + ' recusou sua participação na folha ' + (p.name || p.client_name) + '.', jr.project_id);
  res.json({ ok: true });
});

// ---------- Logout ----------
app.post('/api/logout', auth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.user.id);
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(process.env.PORT || 3000, () => console.log(`Tornang rodando em http://localhost:${process.env.PORT || 3000}`));