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
async function sendEmail(to, subject, text) {
  if (process.env.BREVO_API_KEY) {
    try {
      const resp = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: {
          'api-key': process.env.BREVO_API_KEY,
          'content-type': 'application/json',
          'accept': 'application/json'
        },
        body: JSON.stringify({
          sender: { email: process.env.SMTP_FROM || process.env.SMTP_USER },
          to: [{ email: to }],
          subject,
          textContent: text
        })
      });
      if (!resp.ok) console.error('Falha ao enviar e-mail (API):', resp.status, await resp.text());
      return;
    } catch (err) {
      console.error('Falha ao enviar e-mail (API):', err.message);
    }
  }
}
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
  db.prepare("UPDATE users SET last_seen = datetime('now') WHERE id = ?").run(user.id);
  next();
}
function managerOnly(req, res, next) {
  if (req.user.role !== 'manager') return res.status(403).json({ error: 'Acesso restrito ao gerente.' });
  next();
}
function ownerOnly(req, res, next) {
  if (!req.user.is_owner) return res.status(403).json({ error: 'Apenas o dono da conta pode fazer isso.' });
  next();
}
function manageCollabOnly(req, res, next) {
  if (!req.user.is_owner && !req.user.can_manage_collaborators) return res.status(403).json({ error: 'Apenas o dono ou um colaborador autorizado pode gerenciar colaboradores.' });
  next();
}
// null = acesso a todos os locais (dono); array = apenas os locais vinculados
function allowedLocationIds(user) {
  if (user.is_owner) return null;
  return db.prepare('SELECT location_id FROM user_locations WHERE user_id = ?').all(user.id).map(r => r.location_id);
}
function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role, section_id: u.section_id, active: u.active, is_owner: !!u.is_owner, can_manage_collaborators: !!u.can_manage_collaborators, phone: u.phone || '', avatar: u.avatar || null };
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
  console.log('Código de verificação para ' + emailNorm + ': ' + code + ' (válido por 10 minutos)');
  sendEmail(emailNorm, 'Flex — Código de verificação', `Seu código de verificação é: ${code}\n\nVálido por 10 minutos.`);
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
    sendEmail(user.email, 'Flex — Redefinição de senha', `Use este link para redefinir sua senha (válido por 1 hora):\n\n${link}`);
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
  const allowed = allowedLocationIds(req.user);
  if (allowed && loc && !allowed.includes(loc)) return res.status(403).json({ error: 'Você não tem acesso a este local.' });
  const sections = db.prepare(`SELECT * FROM sections WHERE company_id = ? ${loc ? 'AND location_id = ?' : ''} ORDER BY position`)
    .all(...(loc ? [req.user.company_id, loc] : [req.user.company_id]));
  res.json({ sections });
});
app.get('/api/sections', auth, managerOnly, (req, res) => {
  const loc = Number(req.query.loc) || null;
  const allowed = allowedLocationIds(req.user);
  if (allowed && loc && !allowed.includes(loc)) return res.status(403).json({ error: 'Você não tem acesso a este local.' });
  const sections = db.prepare(`SELECT * FROM sections WHERE company_id = ? ${loc ? 'AND location_id = ?' : ''} ORDER BY position`)
    .all(...(loc ? [req.user.company_id, loc] : [req.user.company_id]));
  res.json({ sections });
});
app.post('/api/company/sections', auth, managerOnly, (req, res) => {
  const { name, location_id } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'Informe o nome da seção.' });
  const locId = Number(location_id) || null;
  const allowedS = allowedLocationIds(req.user);
  if (allowedS && locId && !allowedS.includes(locId)) return res.status(403).json({ error: 'Você não tem acesso a este local.' });
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
app.get('/api/company/sections/:id/usage', auth, managerOnly, (req, res) => {
  const s = db.prepare('SELECT * FROM sections WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!s) return res.status(404).json({ error: 'Seção não encontrada.' });
  const workers = db.prepare('SELECT COUNT(*) c FROM users WHERE section_id = ?').get(s.id).c;
  const activeRoutes = db.prepare(`
    SELECT COUNT(DISTINCT r.project_id) c FROM project_route r
    JOIN projects p ON p.id = r.project_id
    WHERE r.section_id = ? AND p.status != 'completed'`).get(s.id).c;
  res.json({ workers, activeRoutes });
});
app.delete('/api/company/sections/:id', auth, managerOnly, (req, res) => {
  const s = db.prepare('SELECT * FROM sections WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!s) return res.status(404).json({ error: 'Seção não encontrada.' });
  const workers = db.prepare('SELECT COUNT(*) c FROM users WHERE section_id = ?').get(s.id).c;
  const activeRoutes = db.prepare(`
    SELECT COUNT(DISTINCT r.project_id) c FROM project_route r
    JOIN projects p ON p.id = r.project_id
    WHERE r.section_id = ? AND p.status != 'completed'`).get(s.id).c;
  if (activeRoutes > 0) {
    return res.status(400).json({ error: `Esta seção é etapa de ${activeRoutes} folha(s) em andamento. Conclua as folhas ou edite as rotas antes de excluir.` });
  }
  const tx = db.transaction(() => {
    db.prepare('UPDATE users SET section_id = NULL WHERE section_id = ?').run(s.id);
    db.prepare('DELETE FROM sections WHERE id = ?').run(s.id);
  });
  tx();
  res.json({ ok: true, detached: workers });
});
app.post('/api/company/sections/:id/reveal', auth, managerOnly, (req, res) => {
  const s = db.prepare('SELECT * FROM sections WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!s) return res.status(404).json({ error: 'Seção não encontrada.' });
  res.json({ password: s.password_enc ? decrypt(s.password_enc) : null });
});
// ---------- Trabalhadores ----------
app.get('/api/company/workers', auth, managerOnly, (req, res) => {
  const loc = Number(req.query.loc) || null;
  const allowedW = allowedLocationIds(req.user);
  if (allowedW && loc && !allowedW.includes(loc)) return res.status(403).json({ error: 'Você não tem acesso a este local.' });
  const workers = db.prepare(`
    SELECT u.id, u.name, u.email, u.section_id, u.active, u.created_at, u.last_seen, s.name AS section_name,
      CASE WHEN u.last_seen IS NOT NULL AND u.last_seen >= datetime('now', '-2 minutes') THEN 1 ELSE 0 END AS online
    FROM users u LEFT JOIN sections s ON s.id = u.section_id
    WHERE u.company_id = ? AND u.role = 'worker' ${loc ? 'AND s.location_id = ?' : ''}
    ORDER BY CASE WHEN s.id IS NULL THEN 0 ELSE 1 END, u.name`).all(...(loc ? [req.user.company_id, loc] : [req.user.company_id]));
  res.json({ workers });
});
app.post('/api/company/workers', auth, managerOnly, (req, res) => {
  const { name, username, password, section_id } = req.body || {};
  if (!name || !username || !password) return res.status(400).json({ error: 'Preencha nome, usuário e senha.' });
  const userNorm = String(username).toLowerCase().trim();
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(userNorm);
  if (exists) return res.status(400).json({ error: 'Já existe uma conta com este usuário.' });
  const sec = db.prepare('SELECT * FROM sections WHERE id = ? AND company_id = ?').get(Number(section_id), req.user.company_id);
  if (!sec) return res.status(400).json({ error: 'Seção inválida.' });
  const info = db.prepare("INSERT INTO users (company_id, name, email, role, password_enc, section_id) VALUES (?,?,?,?,?,?)")
    .run(req.user.company_id, String(name).trim(), userNorm, 'worker', encrypt(password), sec.id);
  res.json({ ok: true, id: info.lastInsertRowid });
});
app.put('/api/company/workers/:id', auth, managerOnly, (req, res) => {
  const w = db.prepare("SELECT * FROM users WHERE id = ? AND company_id = ? AND role = 'worker'").get(req.params.id, req.user.company_id);
  if (!w) return res.status(404).json({ error: 'Trabalhador não encontrado.' });
  const { name, username, section_id, active, password } = req.body || {};
  const newName = name !== undefined ? String(name).trim() : w.name;
  if (!newName) return res.status(400).json({ error: 'O nome é obrigatório.' });
  let newEmail = w.email;
  if (username !== undefined) {
    newEmail = String(username).toLowerCase().trim();
    if (!newEmail) return res.status(400).json({ error: 'O usuário é obrigatório.' });
    const dup = db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(newEmail, w.id);
    if (dup) return res.status(400).json({ error: 'Já existe uma conta com este usuário.' });
  }
  const newSection = section_id !== undefined ? (Number(section_id) || null) : w.section_id;
  const newActive = active !== undefined ? (active ? 1 : 0) : w.active;
  db.prepare('UPDATE users SET name = ?, email = ?, section_id = ?, active = ? WHERE id = ?')
    .run(newName, newEmail, newSection, newActive, w.id);
  if (password) db.prepare('UPDATE users SET password_enc = ? WHERE id = ?').run(encrypt(password), w.id);
  res.json({ ok: true });
});
app.delete('/api/company/workers/:id', auth, managerOnly, (req, res) => {
  const w = db.prepare("SELECT * FROM users WHERE id = ? AND company_id = ? AND role = 'worker'").get(req.params.id, req.user.company_id);
  if (!w) return res.status(404).json({ error: 'Trabalhador não encontrado.' });
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(w.id);
  db.prepare('DELETE FROM project_collaborators WHERE user_id = ?').run(w.id);
  db.prepare('UPDATE project_route SET assigned_to = NULL WHERE assigned_to = ?').run(w.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(w.id);
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
  const allowed = allowedLocationIds(req.user);
  if (allowed && loc && !allowed.includes(loc)) return res.status(403).json({ error: 'Você não tem acesso a este local.' });
  const projects = db.prepare(`
    SELECT p.*, s.name AS section_name, u.name AS worker_name,
      (SELECT COUNT(*) FROM project_documents d WHERE d.project_id = p.id) AS doc_count,
      (SELECT GROUP_CONCAT(r.section_id) FROM project_route r WHERE r.project_id = p.id) AS route_ids,
      (SELECT COUNT(*) FROM project_route r WHERE r.project_id = p.id AND r.status = 'active' AND r.assigned_to IS NULL) AS awaiting,
      (SELECT COUNT(*) FROM project_tasks t JOIN project_items i ON i.id = t.item_id WHERE i.project_id = p.id) AS total_tasks,
      (SELECT COUNT(*) FROM project_tasks t JOIN project_items i ON i.id = t.item_id WHERE i.project_id = p.id AND t.status = 'done') AS done_tasks
    FROM projects p
    LEFT JOIN sections s ON s.id = p.current_section_id
    LEFT JOIN users u ON u.id = p.assigned_to
    WHERE p.company_id = ? AND p.archived = ? ${loc ? 'AND p.location_id = ?' : ''}
    ORDER BY p.priority DESC,
      CASE WHEN p.status = 'completed' THEN 1 ELSE 0 END,
      CASE WHEN p.due_date IS NULL OR p.due_date = '' THEN 1 ELSE 0 END,
      p.due_date ASC, p.created_at DESC`).all(...(loc ? [req.user.company_id, req.query.archived === '1' ? 1 : 0, loc] : [req.user.company_id, req.query.archived === '1' ? 1 : 0]));
  res.json({ projects });
});
app.post('/api/projects', auth, managerOnly, (req, res) => {
  const { client_name, name, description, due_date, location_id, section_ids, items } = req.body || {};
  if (!client_name || !String(client_name).trim()) return res.status(400).json({ error: 'Informe o cliente da folha.' });
  const locId = Number(location_id) || null;
  const allowedP = allowedLocationIds(req.user);
  if (allowedP && locId && !allowedP.includes(locId)) return res.status(403).json({ error: 'Você não tem acesso a este local.' });

  // ---------- Modo v5.0: projeto com itens e tarefas ----------
  if (Array.isArray(items)) {
    const validSections = db.prepare(`SELECT * FROM sections WHERE company_id = ? ${locId ? 'AND location_id = ?' : ''}`)
      .all(...(locId ? [req.user.company_id, locId] : [req.user.company_id]));
    const validIds = validSections.map(s => s.id);
    // valida e normaliza os itens
    const cleanItems = [];
    for (const it of items) {
      const iname = String(it.name || '').trim();
      if (!iname) return res.status(400).json({ error: 'Todo item precisa de um nome.' });
      const ordered = it.ordered ? 1 : 0;
      const tasks = (Array.isArray(it.tasks) ? it.tasks : [])
        .map(t => ({ name: String(t.name || '').trim(), section_id: Number(t.section_id) }))
        .filter(t => t.name && validIds.includes(t.section_id));
      if (!tasks.length) return res.status(400).json({ error: `O item "${iname}" precisa de pelo menos uma tarefa.` });
      cleanItems.push({ name: iname, quantity: Math.max(1, Number(it.quantity) || 1), ordered, tasks });
    }
    // pool = união das seções das tarefas (+ section_ids explícitos)
    const pool = new Set(cleanItems.flatMap(i => i.tasks.map(t => t.section_id)));
    for (const sid of (Array.isArray(section_ids) ? section_ids : [])) if (validIds.includes(Number(sid))) pool.add(Number(sid));
    const status = 'in_progress';
    let projectId = null;
    const tx = db.transaction(() => {
      const pi = db.prepare('INSERT INTO projects (company_id, location_id, client_name, name, description, due_date, status) VALUES (?,?,?,?,?,?,?)')
        .run(req.user.company_id, locId, String(client_name).trim(), String(name || '').trim(), String(description || '').trim(), String(due_date || '').trim() || null, status);
      projectId = pi.lastInsertRowid;
      const insPool = db.prepare('INSERT OR IGNORE INTO project_sections (project_id, section_id) VALUES (?,?)');
      for (const sid of pool) insPool.run(projectId, sid);
      const insItem = db.prepare('INSERT INTO project_items (project_id, name, quantity, ordered, status, position) VALUES (?,?,?,?,?,?)');
      const insTask = db.prepare('INSERT INTO project_tasks (item_id, section_id, name, task_order, status) VALUES (?,?,?,?,?)');
      cleanItems.forEach((it, idx) => {
        const ii = insItem.run(projectId, it.name, it.quantity, it.ordered, 'in_progress', idx);
        it.tasks.forEach((t, ti) => {
          const st = it.ordered ? (ti === 0 ? 'active' : 'pending') : 'active';
          insTask.run(ii.lastInsertRowid, t.section_id, t.name, it.ordered ? ti + 1 : null, st);
        });
      });
      const first = db.prepare(`SELECT t.section_id FROM project_tasks t JOIN project_items i ON i.id = t.item_id
        WHERE i.project_id = ? AND t.status = 'active' ORDER BY i.position, t.task_order LIMIT 1`).get(projectId);
      db.prepare('UPDATE projects SET current_section_id = ? WHERE id = ?').run(first ? first.section_id : null, projectId);
      db.prepare('INSERT INTO project_history (project_id, action) VALUES (?,?)').run(projectId, 'created');
    });
    tx();
    return res.json({ ok: true, id: projectId });
  }

  // ---------- Modo clássico: folha simples por rota de seções (inalterado) ----------
  const sections = db.prepare(`SELECT * FROM sections WHERE company_id = ? ${locId ? 'AND location_id = ?' : ''} ORDER BY position`)
    .all(...(locId ? [req.user.company_id, locId] : [req.user.company_id]));
  if (!sections.length) return res.status(400).json({ error: 'Crie pelo menos uma seção antes de abrir folhas.' });
  let steps = Array.isArray(route) && route.length
    ? route.map(st => (Array.isArray(st) ? st : [st]).map(Number).filter(id => sections.some(s => s.id === id)))
    : sections.map(s => [s.id]);
  steps = steps.filter(st => st.length);
  if (!steps.length) return res.status(400).json({ error: 'Selecione pelo menos uma seção para a rota.' });
  const status = 'in_progress';
  const info = db.prepare('INSERT INTO projects (company_id, location_id, client_name, name, description, due_date, current_section_id, status) VALUES (?,?,?,?,?,?,?,?)')
    .run(req.user.company_id, locId, String(client_name).trim(), String(name || '').trim(), String(description || '').trim(), String(due_date || '').trim() || null, steps[0][0], status);
  const projectId = info.lastInsertRowid;
  const ins = db.prepare('INSERT INTO project_route (project_id, section_id, step, status) VALUES (?,?,?,?)');
  const tx = db.transaction(() => {
    steps.forEach((st, i) => {
      const stepNo = i + 1;
      for (const sid of st) ins.run(projectId, sid, stepNo, stepNo === 1 ? 'active' : 'pending');
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

app.get('/api/projects/:id/history/download', auth, (req, res) => {
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });

  const events = db.prepare(`
    SELECT h.created_at, h.action, h.notes, s.name AS section_name, u.name AS worker_name
    FROM project_history h
    LEFT JOIN sections s ON s.id = h.section_id
    LEFT JOIN users u ON u.id = h.worker_id
    WHERE h.project_id = ? ORDER BY h.created_at`).all(p.id);

  const notes = db.prepare(`
    SELECT n.created_at, n.note, n.is_alert, n.alert_type, n.author_name, s.name AS section_name
    FROM project_notes n LEFT JOIN sections s ON s.id = n.section_id
    WHERE n.project_id = ? ORDER BY n.created_at`).all(p.id);

  const tasks = db.prepare(`
    SELECT i.name AS item_name, i.quantity, t.name AS task_name, s.name AS section_name, t.status, t.task_order,
      u.name AS assigned_name, dw.name AS done_by_name, t.done_at
    FROM project_tasks t
    JOIN project_items i ON i.id = t.item_id
    JOIN sections s ON s.id = t.section_id
    LEFT JOIN users u ON u.id = t.assigned_to
    LEFT JOIN users dw ON dw.id = t.done_by
    WHERE i.project_id = ? ORDER BY i.position, t.task_order IS NULL, t.task_order, t.id`).all(p.id);

  const q = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
  const labels = { created: 'Folha criada', accepted: 'Assumida', finished: 'Concluída', passed: 'Passada para', released: 'Liberada', route_updated: 'Rota atualizada', task_accepted: 'Tarefa assumida', task_done: 'Tarefa concluída', archived: 'Arquivada', unarchived: 'Desarquivada', items_added: 'Itens adicionados' };
  let csv = '\uFEFF'; // BOM: Excel abre com acentos corretos
  csv += 'HISTORICO — ' + (p.name ? p.client_name + ' — ' + p.name : p.client_name) + '\n';
  csv += 'Status atual:,' + q(p.status) + '\n\n';
  csv += '=== EVENTOS ===\nData,Evento,Seção,Quem,Detalhes\n';
  for (const h of events) csv += [h.created_at, labels[h.action] || h.action, h.section_name || '', h.worker_name || '', h.notes || ''].map(q).join(',') + '\n';
  csv += '\n=== ITENS E TAREFAS ===\nItem,Qtd,Tarefa,Seção,Ordem,Status,Atribuída a,Concluída por,Concluída em\n';
  for (const t of tasks) csv += [t.item_name, t.quantity, t.task_name, t.section_name, t.task_order ?? '', t.status, t.assigned_name || '', t.done_by_name || '', t.done_at || ''].map(q).join(',') + '\n';
  csv += '\n=== ANOTAÇÕES E PROBLEMAS ===\nData,Autor,Seção,Tipo,Texto\n';
  for (const n of notes) csv += [n.created_at, n.author_name || '', n.section_name || '', n.is_alert ? (n.alert_type || 'Alerta') : 'Anotação', n.note].map(q).join(',') + '\n';

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="historico-' + p.id + '.csv"');
  res.send(csv);
});

// ---------- Fila do trabalhador ----------
app.get('/api/worker/queue', auth, (req, res) => {
  if (req.user.role !== 'worker') return res.status(403).json({ error: 'Acesso restrito.' });
  const routed = db.prepare(`
    SELECT p.*, s.name AS section_name, r.id AS route_id, r.step, r.assigned_to AS route_assigned,
      (SELECT GROUP_CONCAT(s2.name, ' + ') FROM project_route r2 JOIN sections s2 ON s2.id = r2.section_id
       WHERE r2.project_id = p.id AND r2.step = r.step AND r2.section_id != r.section_id) AS parallel_with,
      (SELECT MAX(step) FROM project_route WHERE project_id = p.id) AS max_step
    FROM project_route r
    JOIN projects p ON p.id = r.project_id
    JOIN sections s ON s.id = r.section_id
    WHERE p.company_id = ? AND p.status = 'in_progress' AND p.archived = 0 AND r.section_id = ? AND r.status = 'active'
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
    // ---------- v5.0: tarefas da seção ----------
  const taskRows = db.prepare(`
    SELECT t.id AS task_id, t.name AS task_name, t.status AS task_status, t.task_order, t.assigned_to AS task_assigned,
      i.id AS item_id, i.name AS item_name, i.quantity, i.ordered, i.status AS item_status,
      p.id, p.client_name, p.name AS project_name, p.description, p.priority, p.due_date,
      s.name AS section_name
    FROM project_tasks t
    JOIN project_items i ON i.id = t.item_id
    JOIN projects p ON p.id = i.project_id
    JOIN sections s ON s.id = t.section_id
    WHERE p.company_id = ? AND p.status = 'in_progress' AND t.section_id = ? AND t.status = 'active' AND p.archived = 0
    ORDER BY p.priority DESC, p.due_date ASC, p.created_at DESC`).all(req.user.company_id, req.user.section_id);
  for (const row of taskRows) {
    const item = { ...row, type: 'task', is_ordered: !!row.ordered };
    delete item.task_assigned;
    if (row.task_assigned === req.user.id || collabIds.includes(row.project_id)) mine.push(item);
    else if (!row.task_assigned) available.push(item);
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
  const destination = (req.body && req.body.destination === 'client') ? 'delivered' : 'at_warehouse';
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
        db.prepare("UPDATE projects SET status = ?, assigned_to = NULL, current_section_id = NULL, updated_at = datetime('now') WHERE id = ?").run(destination, p.id);
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
    return res.json({ ok: true, waiting: !!waitingFor, waiting_for: waitingFor, next, completed: proj.status === 'completed', destination });
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
      db.prepare("UPDATE projects SET status = ?, assigned_to = NULL, updated_at = datetime('now') WHERE id = ?").run(destination, p.id);
      db.prepare('INSERT INTO project_history (project_id, section_id, worker_id, action) VALUES (?,?,?,?)').run(p.id, p.current_section_id, req.user.id, 'finished');
    }
  });
  tx();
  res.json({ ok: true, next: next ? next.name : null, completed: !next, destination });
});

// ---------- v5.0: motor de tarefas ----------
app.post('/api/tasks/:id/accept', auth, (req, res) => {
  if (req.user.role !== 'worker') return res.status(403).json({ error: 'Acesso restrito.' });
  const t = db.prepare(`
    SELECT t.*, p.company_id, p.status AS project_status FROM project_tasks t
    JOIN project_items i ON i.id = t.item_id
    JOIN projects p ON p.id = i.project_id
    WHERE t.id = ?`).get(req.params.id);
  if (!t || t.company_id !== req.user.company_id) return res.status(404).json({ error: 'Tarefa não encontrada.' });
  if (t.project_status !== 'in_progress') return res.status(400).json({ error: 'Este projeto não está em produção.' });
  if (t.section_id !== req.user.section_id) return res.status(400).json({ error: 'Esta tarefa não é da sua seção.' });
  if (t.status !== 'active') return res.status(400).json({ error: 'Esta tarefa ainda não está liberada.' });
  if (t.assigned_to && t.assigned_to !== req.user.id) return res.status(400).json({ error: 'Esta tarefa já foi assumida.' });
  db.prepare('UPDATE project_tasks SET assigned_to = ? WHERE id = ?').run(req.user.id, t.id);
  db.prepare('INSERT INTO project_history (project_id, section_id, worker_id, action, notes) VALUES (?,?,?,?,?)')
    .run((db.prepare('SELECT project_id FROM project_items WHERE id = ?').get(t.item_id)).project_id, t.section_id, req.user.id, 'task_accepted', t.name);
  res.json({ ok: true });
});

app.post('/api/tasks/:id/finish', auth, (req, res) => {
  if (req.user.role !== 'worker') return res.status(403).json({ error: 'Acesso restrito.' });
  const destination = (req.body && req.body.destination === 'client') ? 'delivered' : 'at_warehouse';
  const nextWorkerId = Number((req.body || {}).next_worker_id) || null;
  const t = db.prepare(`
    SELECT t.*, i.project_id, i.ordered, i.name AS item_name, p.company_id, p.status AS project_status
    FROM project_tasks t
    JOIN project_items i ON i.id = t.item_id
    JOIN projects p ON p.id = i.project_id
    WHERE t.id = ?`).get(req.params.id);
  if (!t || t.company_id !== req.user.company_id) return res.status(404).json({ error: 'Tarefa não encontrada.' });
  if (t.project_status !== 'in_progress') return res.status(400).json({ error: 'Este projeto não está em produção.' });
  if (t.status !== 'active') return res.status(400).json({ error: 'Esta tarefa não está ativa.' });
  const isCollab = !!db.prepare('SELECT 1 FROM project_collaborators WHERE project_id = ? AND user_id = ?').get(t.project_id, req.user.id);
  if (t.assigned_to && t.assigned_to !== req.user.id && !isCollab) return res.status(400).json({ error: 'Você não é o responsável por esta tarefa.' });

  let nextTask = null, itemDone = false, projectDone = false;
  const tx = db.transaction(() => {
    db.prepare('UPDATE project_tasks SET status = ?, done_by = ?, done_at = datetime(\'now\') WHERE id = ?').run('done', req.user.id, t.id);
    db.prepare('INSERT INTO project_history (project_id, section_id, worker_id, action, notes) VALUES (?,?,?,?,?)')
      .run(t.project_id, t.section_id, req.user.id, 'task_done', t.name);
    // ordenada: ativa a próxima tarefa do item
    if (t.ordered) {
      nextTask = db.prepare('SELECT * FROM project_tasks WHERE item_id = ? AND status = \'pending\' ORDER BY task_order LIMIT 1').get(t.item_id);
      if (nextTask) {
        db.prepare('UPDATE project_tasks SET status = \'active\' WHERE id = ?').run(nextTask.id);
        if (nextWorkerId) {
          const nw = db.prepare('SELECT * FROM users WHERE id = ? AND section_id = ? AND role = \'worker\'').get(nextWorkerId, nextTask.section_id);
          if (nw) {
            db.prepare('UPDATE project_tasks SET assigned_to = ? WHERE id = ?').run(nw.id, nextTask.id);
            db.prepare('INSERT INTO notifications (company_id, user_id, type, title, body, project_id) VALUES (?,?,?,?,?,?)')
              .run(t.company_id, nw.id, 'task_assigned', '📋 Tarefa atribuída a você', req.user.name + ' te passou a tarefa "' + nextTask.name + '" (' + t.item_name + ').', t.project_id);
          }
        }
      }
    }
    // item concluído?
    const pending = db.prepare('SELECT COUNT(*) c FROM project_tasks WHERE item_id = ? AND status != \'done\'').get(t.item_id).c;
    if (pending === 0) {
      db.prepare('UPDATE project_items SET status = \'done\' WHERE id = ?').run(t.item_id);
      itemDone = true;
      // projeto concluído?
      const itemsLeft = db.prepare('SELECT COUNT(*) c FROM project_items WHERE project_id = ? AND status != \'done\'').get(t.project_id).c;
      if (itemsLeft === 0) {
        db.prepare('UPDATE projects SET status = ?, assigned_to = NULL, current_section_id = NULL, updated_at = datetime(\'now\') WHERE id = ?').run(destination, t.project_id);
        db.prepare('INSERT INTO project_history (project_id, action) VALUES (?,?)').run(t.project_id, 'finished');
        projectDone = true;
      }
    }
  });
  tx();
  res.json({ ok: true, next_task: nextTask ? nextTask.name : null, next_section_id: nextTask ? nextTask.section_id : null, item_done: itemDone, project_done: projectDone, destination });
});

app.get('/api/tasks/:id/next', auth, (req, res) => {
  if (req.user.role !== 'worker') return res.status(403).json({ error: 'Acesso restrito.' });
  const t = db.prepare(`
    SELECT t.*, i.project_id, i.ordered FROM project_tasks t
    JOIN project_items i ON i.id = t.item_id WHERE t.id = ?`).get(req.params.id);
  if (!t) return res.status(404).json({ error: 'Tarefa não encontrada.' });
  const p = db.prepare('SELECT company_id FROM projects WHERE id = ?').get(t.project_id);
  if (!p || p.company_id !== req.user.company_id) return res.status(404).json({ error: 'Tarefa não encontrada.' });
  const pendingInItem = db.prepare("SELECT COUNT(*) c FROM project_tasks WHERE item_id = ? AND status != 'done'").get(t.item_id).c;
  const itemsLeft = db.prepare("SELECT COUNT(*) c FROM project_items WHERE project_id = ? AND status != 'done'").get(t.project_id).c;
  const completes = pendingInItem === 1 && itemsLeft === 1;
  let next = null;
  if (t.ordered) {
    const nt = db.prepare(`
      SELECT t2.id, t2.name, s.name AS section_name FROM project_tasks t2
      JOIN sections s ON s.id = t2.section_id
      WHERE t2.item_id = ? AND t2.status = 'pending' ORDER BY t2.task_order LIMIT 1`).get(t.item_id);
    if (nt) {
      const workers = db.prepare(`
        SELECT id, name FROM users WHERE section_id = (SELECT section_id FROM project_tasks WHERE id = ?)
        AND role = 'worker' AND active = 1 ORDER BY name`).all(nt.id);
      next = { id: nt.id, name: nt.name, section_name: nt.section_name, workers };
    }
  }
  res.json({ next, completes_project: completes });
});

// ---------- v4.6: destino final da folha (gerente corrige) ----------
app.put('/api/projects/:id/destination', auth, managerOnly, (req, res) => {
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });
  const d = String((req.body || {}).destination || '');
  if (!['at_warehouse', 'delivered'].includes(d)) return res.status(400).json({ error: 'Destino inválido.' });
  if (!['completed', 'at_warehouse', 'delivered'].includes(p.status)) return res.status(400).json({ error: 'A folha ainda está em produção.' });
  db.prepare("UPDATE projects SET status = ?, updated_at = datetime('now') WHERE id = ?").run(d, p.id);
  res.json({ ok: true });
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
app.put('/api/company/profile', auth, managerOnly, ownerOnly, (req, res) => {
  const { company_name, nif, address, phone, website } = req.body || {};
  if (!company_name || !String(company_name).trim()) return res.status(400).json({ error: 'O nome da empresa é obrigatório.' });
  db.prepare('UPDATE companies SET name = ?, nif = ?, address = ?, phone = ?, website = ? WHERE id = ?')
    .run(String(company_name).trim(), String(nif || '').trim(), String(address || '').trim(), String(phone || '').trim(), String(website || '').trim(), req.user.company_id);
  const company = db.prepare('SELECT * FROM companies WHERE id = ?').get(req.user.company_id);
  res.json({ ok: true, company });
});
// ---------- E-mail da conta da empresa (protegido por senha) ----------
app.post('/api/company/email', auth, managerOnly, ownerOnly, (req, res) => {
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
    SELECT id, name, email, is_owner, active, can_manage_collaborators, created_at
    FROM users WHERE company_id = ? AND role = 'manager'
    ORDER BY is_owner DESC, name`).all(req.user.company_id).map(c => ({
    ...c,
    location_ids: db.prepare('SELECT location_id FROM user_locations WHERE user_id = ?').all(c.id).map(r => r.location_id)
  }));
  res.json({ collaborators });
});
app.post('/api/company/collaborators', auth, managerOnly, manageCollabOnly, (req, res) => {
  const { name, email } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'Informe o nome do colaborador.' });
  const emailNorm = String(email || '').toLowerCase().trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNorm)) return res.status(400).json({ error: 'E-mail inválido.' });
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(emailNorm);
  if (exists) return res.status(400).json({ error: 'Já existe uma conta com este e-mail.' });
  const location_ids = Array.isArray(req.body.location_ids) ? req.body.location_ids.map(Number).filter(Boolean) : [];
  if (!location_ids.length) return res.status(400).json({ error: 'Marque pelo menos um local.' });
  const validLocs = db.prepare('SELECT id FROM locations WHERE company_id = ?').all(req.user.company_id).map(l => l.id);
  if (location_ids.some(id => !validLocs.includes(id))) return res.status(400).json({ error: 'Local inválido.' });
  const password = crypto.randomBytes(4).toString('hex');
  let newId = null;
  const tx = db.transaction(() => {
    const info = db.prepare("INSERT INTO users (company_id, name, email, role, password_hash) VALUES (?,?,?,'manager',?)")
      .run(req.user.company_id, String(name).trim(), emailNorm, bcrypt.hashSync(password, 10));
    newId = info.lastInsertRowid;
    for (const id of location_ids) db.prepare('INSERT OR IGNORE INTO user_locations (user_id, location_id) VALUES (?,?)').run(newId, id);
  });
  tx();
  console.log('=====================================');
  console.log('Colaborador criado: ' + emailNorm + ' | senha inicial: ' + password);
  console.log('=====================================');
  // TODO: enviar esta senha por e-mail quando o SMTP for configurado
  res.json({ ok: true, id: newId, password });
});
app.put('/api/company/collaborators/:id', auth, managerOnly, manageCollabOnly, (req, res) => {
  const c = db.prepare("SELECT * FROM users WHERE id = ? AND company_id = ? AND role = 'manager'").get(req.params.id, req.user.company_id);
  if (!c) return res.status(404).json({ error: 'Colaborador não encontrado.' });
  const { name, active, location_ids, can_manage_collaborators } = req.body || {};
  if (c.is_owner && active === false) return res.status(400).json({ error: 'A conta principal não pode ser desativada.' });
  if (name !== undefined) {
    const newName = String(name).trim();
    if (!newName) return res.status(400).json({ error: 'O nome é obrigatório.' });
    db.prepare('UPDATE users SET name = ? WHERE id = ?').run(newName, c.id);
  }
  if (active !== undefined) db.prepare('UPDATE users SET active = ? WHERE id = ?').run(active ? 1 : 0, c.id);
  if (can_manage_collaborators !== undefined && !c.is_owner) {
    db.prepare('UPDATE users SET can_manage_collaborators = ? WHERE id = ?').run(can_manage_collaborators ? 1 : 0, c.id);
  }
  if (location_ids !== undefined) {
    const ids = Array.isArray(location_ids) ? location_ids.map(Number).filter(Boolean) : [];
    if (!ids.length) return res.status(400).json({ error: 'Marque pelo menos um local.' });
    db.prepare('DELETE FROM user_locations WHERE user_id = ?').run(c.id);
    for (const id of ids) db.prepare('INSERT OR IGNORE INTO user_locations (user_id, location_id) VALUES (?,?)').run(c.id, id);
  }
  res.json({ ok: true });
});
app.post('/api/company/collaborators/:id/reset', auth, managerOnly, manageCollabOnly, (req, res) => {
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
app.delete('/api/company/collaborators/:id', auth, managerOnly, manageCollabOnly, (req, res) => {
  const c = db.prepare("SELECT * FROM users WHERE id = ? AND company_id = ? AND role = 'manager'").get(req.params.id, req.user.company_id);
  if (!c) return res.status(404).json({ error: 'Colaborador não encontrado.' });
  if (c.is_owner) return res.status(400).json({ error: 'A conta principal não pode ser removida.' });
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(c.id);
  db.prepare('DELETE FROM user_locations WHERE user_id = ?').run(c.id);
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

// ---------- Arquivar / desarquivar folha (registra quem fez) ----------
app.post('/api/projects/:id/archive', auth, managerOnly, (req, res) => {
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });
  db.prepare('UPDATE projects SET archived = 1 WHERE id = ?').run(p.id);
  db.prepare('INSERT INTO project_history (project_id, section_id, action, worker_id) VALUES (?,?,?,?)')
    .run(p.id, p.current_section_id, 'archived', req.user.id);
  res.json({ ok: true });
});

app.post('/api/projects/:id/unarchive', auth, managerOnly, (req, res) => {
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });
  db.prepare('UPDATE projects SET archived = 0 WHERE id = ?').run(p.id);
  db.prepare('INSERT INTO project_history (project_id, section_id, action, worker_id) VALUES (?,?,?,?)')
    .run(p.id, p.current_section_id, 'unarchived', req.user.id);
  res.json({ ok: true });
});

// ---------- Excluir folha (arquivos vão para uploads/deleted/) ----------
app.delete('/api/projects/:id', auth, managerOnly, (req, res) => {
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });

  const trashDir = path.join(uploadDir, 'deleted');
  try { fs.mkdirSync(trashDir, { recursive: true }); } catch (e) {}
  const docs = db.prepare('SELECT * FROM project_documents WHERE project_id = ?').all(p.id);
  for (const d of docs) {
    const from = path.join(uploadDir, d.stored_name);
    if (fs.existsSync(from)) {
      let dest = path.join(trashDir, d.stored_name);
      if (fs.existsSync(dest)) dest = path.join(trashDir, Date.now() + '-' + d.stored_name);
      try { fs.renameSync(from, dest); }
      catch (e) { try { fs.copyFileSync(from, dest); fs.unlinkSync(from); } catch (e2) {} }
    }
  }

  const tx = db.transaction(() => {
    db.prepare('DELETE FROM project_tasks WHERE item_id IN (SELECT id FROM project_items WHERE project_id = ?)').run(p.id);
    db.prepare('DELETE FROM project_items WHERE project_id = ?').run(p.id);
    db.prepare('DELETE FROM project_route WHERE project_id = ?').run(p.id);
    db.prepare('DELETE FROM project_notes WHERE project_id = ?').run(p.id);
    db.prepare('DELETE FROM project_history WHERE project_id = ?').run(p.id);
    db.prepare('DELETE FROM project_collaborators WHERE project_id = ?').run(p.id);
    db.prepare('DELETE FROM join_requests WHERE project_id = ?').run(p.id);
    db.prepare('DELETE FROM project_documents WHERE project_id = ?').run(p.id);
    db.prepare('DELETE FROM projects WHERE id = ?').run(p.id);
  });
  tx();
  res.json({ ok: true });
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
app.post('/api/company/logo', auth, managerOnly, ownerOnly, upload.single('logo'), (req, res) => {
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

// ---------- v5.3: Adicionar itens a uma folha existente ----------
app.post('/api/projects/:id/items', auth, managerOnly, (req, res) => {
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, req.user.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });
  if (['completed', 'at_warehouse', 'delivered'].includes(p.status)) return res.status(400).json({ error: 'Esta folha já está concluída.' });
  const raw = Array.isArray(req.body && req.body.items) ? req.body.items : [];
  const cleanItems = raw.map(it => ({
    name: String(it.name || '').trim(),
    quantity: Math.max(1, Number(it.quantity) || 1),
    ordered: !!it.ordered,
    tasks: (Array.isArray(it.tasks) ? it.tasks : [])
      .map(t => ({ name: String(t.name || '').trim(), section_id: Number(t.section_id) || null }))
      .filter(t => t.name && t.section_id)
  })).filter(it => it.name && it.tasks.length);
  if (!cleanItems.length) return res.status(400).json({ error: 'Adicione pelo menos um item com tarefas.' });
  const validIds = new Set(db.prepare('SELECT id FROM sections WHERE company_id = ?').all(req.user.company_id).map(s => s.id));
  for (const it of cleanItems) for (const t of it.tasks) {
    if (!validIds.has(t.section_id)) return res.status(400).json({ error: 'Seção inválida em uma das tarefas.' });
  }

  const tx = db.transaction(() => {
    const start = db.prepare('SELECT COALESCE(MAX(position),0) m FROM project_items WHERE project_id = ?').get(p.id).m;
    const insItem = db.prepare('INSERT INTO project_items (project_id, name, quantity, ordered, status, position) VALUES (?,?,?,?,?,?)');
    const insTask = db.prepare('INSERT INTO project_tasks (item_id, section_id, name, task_order, status) VALUES (?,?,?,?,?)');
    cleanItems.forEach((it, idx) => {
      const info = insItem.run(p.id, it.name, it.quantity, it.ordered ? 1 : 0, 'in_progress', start + idx + 1);
      const itemId = info.lastInsertRowid;
      it.tasks.forEach((t, ti) => insTask.run(itemId, t.section_id, t.name, ti + 1, it.ordered ? (ti === 0 ? 'active' : 'pending') : 'active'));
    });
    // Folha criada sem itens: aponta para a primeira tarefa ativa
    if (!p.current_section_id) {
      const first = db.prepare(`SELECT t.section_id FROM project_tasks t JOIN project_items i ON i.id = t.item_id
        WHERE i.project_id = ? AND t.status = 'active' ORDER BY i.position, t.task_order LIMIT 1`).get(p.id);
      db.prepare('UPDATE projects SET current_section_id = ? WHERE id = ?').run(first ? first.section_id : null, p.id);
    }
    db.prepare('INSERT INTO project_history (project_id, action, notes) VALUES (?,?,?)')
      .run(p.id, 'items_added', cleanItems.map(i => i.name).join(', '));
  });
  tx();
  res.json({ ok: true });
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
    const items = db.prepare('SELECT * FROM project_items WHERE project_id = ? ORDER BY position, id').all(p.id);
  const tasks = db.prepare(`
    SELECT t.*, s.name AS section_name, u.name AS assigned_name, dw.name AS done_by_name
    FROM project_tasks t
    JOIN sections s ON s.id = t.section_id
    LEFT JOIN users u ON u.id = t.assigned_to
    LEFT JOIN users dw ON dw.id = t.done_by
    WHERE t.item_id IN (SELECT id FROM project_items WHERE project_id = ?)
    ORDER BY t.task_order IS NULL, t.task_order, t.id`).all(p.id);
  const itemsTree = items.map(it => ({ ...it, tasks: tasks.filter(t => t.item_id === it.id) }));
  res.json({ project: p, documents, sections, route, items: itemsTree });
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
function getMe(req) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
}
app.get('/api/locations', auth, (req, res) => {
  const me = getMe(req);
  let locs = db.prepare('SELECT * FROM locations WHERE company_id = ? ORDER BY id').all(me.company_id);
  const allowed = allowedLocationIds(me);
  if (allowed) locs = locs.filter(l => allowed.includes(l.id));
  res.json({ locations: locs });
});
app.post('/api/locations', auth, (req, res) => {
  const me = getMe(req);
  if (me.role !== 'manager') return res.status(403).json({ error: 'Apenas o gestor pode criar locais.' });
  const name = String(req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'O nome do local é obrigatório.' });
  const info = db.prepare('INSERT INTO locations (company_id, name, address, nif) VALUES (?, ?, ?, ?)')
  .run(me.company_id, name, String(req.body.address || '').trim() || null, String(req.body.nif || '').trim() || null);
  res.json({ location: db.prepare('SELECT * FROM locations WHERE id = ?').get(info.lastInsertRowid) });
});
app.put('/api/locations/:id', auth, (req, res) => {
  const me = getMe(req);
  if (me.role !== 'manager') return res.status(403).json({ error: 'Apenas o gestor pode editar locais.' });
  const loc = db.prepare('SELECT * FROM locations WHERE id = ? AND company_id = ?').get(req.params.id, me.company_id);
  if (!loc) return res.status(404).json({ error: 'Local não encontrado.' });
  const name = String(req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'O nome do local é obrigatório.' });
  db.prepare('UPDATE locations SET name = ?, address = ?, nif = ? WHERE id = ?')
  .run(name, String(req.body.address || '').trim() || null, String(req.body.nif || '').trim() || null, loc.id);
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

app.delete('/api/locations/:id', auth, (req, res) => {
  const me = getMe(req);
  if (me.role !== 'manager') return res.status(403).json({ error: 'Apenas o gestor pode excluir locais.' });
  const loc = db.prepare('SELECT * FROM locations WHERE id = ? AND company_id = ?').get(req.params.id, me.company_id);
  if (!loc) return res.status(404).json({ error: 'Local não encontrado.' });
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
    const sec = db.prepare('SELECT * FROM sections WHERE id = ?').get(me.section_id);
    locs = sec ? locs.filter(l => l.id === sec.location_id) : [];
  }
  // v4.7: colaborador vê apenas os locais vinculados
  if (me.role === 'manager') {
    const allowed = allowedLocationIds(me);
    if (allowed) locs = locs.filter(l => allowed.includes(l.id));
  }
  const data = locs.map(l => {
    const active = db.prepare("SELECT COUNT(*) c FROM projects WHERE location_id = ? AND status = 'in_progress'").get(l.id).c;
    const urgent = db.prepare("SELECT COUNT(*) c FROM projects WHERE location_id = ? AND status = 'in_progress' AND priority > 0").get(l.id).c;
    const overdue = db.prepare("SELECT COUNT(*) c FROM projects WHERE location_id = ? AND status = 'in_progress' AND due_date IS NOT NULL AND due_date < date('now')").get(l.id).c;
    const urgentList = db.prepare(`
      SELECT p.id, p.name, p.client_name, p.priority, p.due_date, s.name AS section_name
      FROM projects p
      LEFT JOIN sections s ON s.id = p.current_section_id
      WHERE p.location_id = ? AND p.status = 'in_progress' AND p.priority > 0
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
  const today = db.prepare(`
    SELECT h.action, h.notes, h.created_at, p.name AS project_name, p.client_name, u.name AS user_name
    FROM project_history h
    JOIN projects p ON p.id = h.project_id
    LEFT JOIN users u ON u.id = h.worker_id
    WHERE p.company_id = ? AND date(h.created_at) = date('now')
    ORDER BY h.id DESC LIMIT 20
  `).all(me.company_id);
  res.json({ locations: data, recent, today });
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
app.post('/api/projects/:id/alert', auth, (req, res) => {
  const me = getMe(req);
  const p = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.params.id, me.company_id);
  if (!p) return res.status(404).json({ error: 'Folha não encontrada.' });
  const note = String(req.body.note || '').trim();
  const alertType = String(req.body.type || '').trim();
  const isEmergency = alertType === 'emergency';
  if (!isEmergency) {
    if (me.role !== 'worker') return res.status(403).json({ error: 'Acesso restrito.' });
    if (!me.section_id) return res.status(403).json({ error: 'Você não pertence a uma seção.' });
    const active = db.prepare("SELECT 1 FROM project_route WHERE project_id = ? AND section_id = ? AND status = 'active'").get(p.id, me.section_id);
    if (!active) return res.status(403).json({ error: 'Este projeto não está na sua seção agora.' });
  }
  const sec = me.section_id ? db.prepare('SELECT * FROM sections WHERE id = ?').get(me.section_id) : null;
  let context = me.name + (sec ? ' — Seção: ' + sec.name : '');
  let projectId = null;
  if (req.body.project_id) {
    const p2 = db.prepare('SELECT * FROM projects WHERE id = ? AND company_id = ?').get(req.body.project_id, me.company_id);
    if (p2) { projectId = p2.id; context += ' — Folha: ' + (p2.name || p2.client_name); }
  }
  const info = db.prepare('INSERT INTO notifications (company_id, user_id, type, title, body, project_id) VALUES (?,?,?,?,?,?)')
    .run(me.company_id, null, isEmergency ? 'emergency' : 'alert', (isEmergency ? '🚨 ' : '⚠️ ') + (alertType || 'Alerta'), (me.name + ' — ' + (p.name || p.client_name) + (note ? ': ' + note : '')).trim(), p.id);
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.get('/api/notifications', auth, (req, res) => {
  const me = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const nots = db.prepare(`SELECT * FROM notifications WHERE company_id = ? AND (user_id = ? OR (user_id IS NULL AND role = ?)) ORDER BY id DESC LIMIT 30`).all(me.company_id, me.id, me.role);
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

app.get('/api/worker/section-queue', auth, (req, res) => {
  if (req.user.role !== 'worker') return res.status(403).json({ error: 'Acesso restrito.' });
  const others = db.prepare(`
    SELECT p.*, s.name AS section_name, u.name AS holder_name,
      (SELECT GROUP_CONCAT(s2.name, ' + ') FROM project_route r2 JOIN sections s2 ON s2.id = r2.section_id
       WHERE r2.project_id = p.id AND r2.step = r.step AND r2.section_id != r.section_id) AS parallel_with
    FROM project_route r
    JOIN projects p ON p.id = r.project_id
    JOIN sections s ON s.id = r.section_id
    LEFT JOIN users u ON u.id = r.assigned_to
    WHERE p.company_id = ? AND p.status = 'in_progress' AND r.section_id = ?
      AND r.status = 'active'
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

// ---------- Logout ----------
app.post('/api/logout', auth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.user.id);
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(process.env.PORT || 3000, () => console.log(`Tornang rodando em http://localhost:${process.env.PORT || 3000}`));