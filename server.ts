import express, { Request, Response, NextFunction } from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import { db, initDatabase } from './server/db.ts';

dotenv.config();

// Initialize Database & seed if necessary
initDatabase();

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Helper to log audit
function recordAudit(userId: string | null, userName: string | null, action: string, details: string, req: Request) {
  try {
    const ip = req.headers['x-forwarded-for']?.toString() || req.socket.remoteAddress || '127.0.0.1';
    const now = new Date().toISOString();
    const id = `audit-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    db.prepare(`
      INSERT INTO audit_logs (id, user_id, user_name, action, details, ip, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, userId, userName, action, details, ip, now);
  } catch (err) {
    console.error('Audit log error:', err);
  }
}

// Simple tokenless header/bearer or session simulation:
// We verify user by x-user-id header or auth token for lightweight reliability in dev iframe
function getAuthUser(req: Request) {
  const userId = req.headers['x-user-id'] as string;
  if (!userId) return null;
  const user = db.prepare('SELECT id, name, username, role, allowed_sectors, is_active FROM users WHERE id = ?').get(userId) as any;
  if (!user || user.is_active === 0) return null;
  return user;
}

// -----------------------------------------------------------------------------
// AUTH ROUTES
// -----------------------------------------------------------------------------

// POST /api/auth/login
app.post('/api/auth/login', (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.status(400).json({ error: 'Informe usuário e senha.' });
    return;
  }

  const cleanUser = username.trim();
  const now = new Date();

  // Check login lock
  const attempt = db.prepare('SELECT * FROM login_attempts WHERE LOWER(username) = LOWER(?)').get(cleanUser) as any;
  if (attempt && attempt.locked_until) {
    const lockTime = new Date(attempt.locked_until);
    if (lockTime > now) {
      const waitMinutes = Math.ceil((lockTime.getTime() - now.getTime()) / 60000);
      res.status(429).json({
        error: `Muitas tentativas incorretas. Conta bloqueada temporariamente. Tente novamente em ${waitMinutes} minuto(s).`
      });
      return;
    }
  }

  // Lookup user (case-insensitive)
  const user = db.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(cleanUser) as any;

  if (!user || user.is_active === 0) {
    // Record failed attempt
    const newCount = (attempt ? attempt.attempts_count : 0) + 1;
    let lockedUntil: string | null = null;
    if (newCount >= 5) {
      const lockDate = new Date(now.getTime() + 5 * 60000); // 5 minutes lock
      lockedUntil = lockDate.toISOString();
    }
    db.prepare(`
      INSERT INTO login_attempts (username, attempts_count, last_attempt_at, locked_until)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(username) DO UPDATE SET
        attempts_count = excluded.attempts_count,
        last_attempt_at = excluded.last_attempt_at,
        locked_until = excluded.locked_until
    `).run(cleanUser, newCount, now.toISOString(), lockedUntil);

    res.status(401).json({ error: 'Usuário ou senha incorretos.' });
    return;
  }

  const isValid = bcrypt.compareSync(password, user.password_hash);
  if (!isValid) {
    const newCount = (attempt ? attempt.attempts_count : 0) + 1;
    let lockedUntil: string | null = null;
    let errorMsg = 'Usuário ou senha incorretos.';
    if (newCount >= 5) {
      const lockDate = new Date(now.getTime() + 5 * 60000);
      lockedUntil = lockDate.toISOString();
      errorMsg = 'Limite de tentativas excedido. Conta bloqueada por 5 minutos.';
    } else {
      errorMsg = `Usuário ou senha incorretos. Tentativa ${newCount} de 5.`;
    }

    db.prepare(`
      INSERT INTO login_attempts (username, attempts_count, last_attempt_at, locked_until)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(username) DO UPDATE SET
        attempts_count = excluded.attempts_count,
        last_attempt_at = excluded.last_attempt_at,
        locked_until = excluded.locked_until
    `).run(cleanUser, newCount, now.toISOString(), lockedUntil);

    res.status(401).json({ error: errorMsg });
    return;
  }

  // Reset login attempts on success
  db.prepare('DELETE FROM login_attempts WHERE LOWER(username) = LOWER(?)').run(cleanUser);

  // Update last login
  db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(now.toISOString(), user.id);

  // Audit
  recordAudit(user.id, user.name, 'LOGIN', `Login com sucesso no sistema (Perfil: ${user.role})`, req);

  let allowedSectors = '*';
  try {
    allowedSectors = user.allowed_sectors === '*' ? '*' : JSON.parse(user.allowed_sectors);
  } catch {
    allowedSectors = user.allowed_sectors;
  }

  res.json({
    user: {
      id: user.id,
      name: user.name,
      username: user.username,
      role: user.role,
      allowed_sectors: allowedSectors,
      last_login_at: now.toISOString()
    }
  });
});

// POST /api/auth/change-password
app.post('/api/auth/change-password', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  if (!user) {
    res.status(401).json({ error: 'Não autenticado.' });
    return;
  }

  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword || newPassword.length < 4) {
    res.status(400).json({ error: 'A nova senha deve ter no mínimo 4 caracteres.' });
    return;
  }

  const fullUser = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(user.id) as any;
  if (!bcrypt.compareSync(currentPassword, fullUser.password_hash)) {
    res.status(400).json({ error: 'Senha atual incorreta.' });
    return;
  }

  const salt = bcrypt.genSaltSync(10);
  const newHash = bcrypt.hashSync(newPassword, salt);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, user.id);

  recordAudit(user.id, user.name, 'ALTEROU_SENHA', 'Usuário alterou a própria senha', req);

  res.json({ success: true, message: 'Senha atualizada com sucesso!' });
});

// GET /api/auth/me
app.get('/api/auth/me', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  if (!user) {
    res.status(401).json({ error: 'Não autenticado.' });
    return;
  }
  res.json({ user });
});

// -----------------------------------------------------------------------------
// USERS MANAGEMENT (Admin only)
// -----------------------------------------------------------------------------

app.get('/api/users', (req: Request, res: Response) => {
  const currentUser = getAuthUser(req);
  if (!currentUser || currentUser.role !== 'admin') {
    res.status(403).json({ error: 'Acesso restrito a administradores.' });
    return;
  }

  const users = db.prepare(`
    SELECT id, name, username, role, allowed_sectors, is_active, created_at, last_login_at
    FROM users
    ORDER BY created_at ASC
  `).all().map((u: any) => {
    try {
      u.allowed_sectors = u.allowed_sectors === '*' ? '*' : JSON.parse(u.allowed_sectors);
    } catch {
      // keep as is
    }
    return u;
  });

  res.json(users);
});

app.post('/api/users', (req: Request, res: Response) => {
  const currentUser = getAuthUser(req);
  if (!currentUser || currentUser.role !== 'admin') {
    res.status(403).json({ error: 'Acesso restrito a administradores.' });
    return;
  }

  const { name, username, password, role, allowed_sectors } = req.body;
  if (!name || !username || !password || !role) {
    res.status(400).json({ error: 'Preencha todos os campos obrigatórios.' });
    return;
  }

  // Check unique username
  const existing = db.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?)').get(username.trim());
  if (existing) {
    res.status(400).json({ error: 'Já existe um usuário com este login.' });
    return;
  }

  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);
  const id = `user-${Date.now()}`;
  const now = new Date().toISOString();
  const sectorsJson = Array.isArray(allowed_sectors) ? JSON.stringify(allowed_sectors) : '*';

  db.prepare(`
    INSERT INTO users (id, name, username, password_hash, role, allowed_sectors, is_active, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
  `).run(id, name.trim(), username.trim(), hash, role, sectorsJson, now);

  recordAudit(currentUser.id, currentUser.name, 'CRIOU_USUARIO', `Criou o usuário ${username} (${role})`, req);

  res.status(201).json({ id, name, username, role });
});

app.put('/api/users/:id', (req: Request, res: Response) => {
  const currentUser = getAuthUser(req);
  if (!currentUser || currentUser.role !== 'admin') {
    res.status(403).json({ error: 'Acesso restrito a administradores.' });
    return;
  }

  const { id } = req.params;
  const { name, username, role, allowed_sectors, is_active } = req.body;

  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as any;
  if (!target) {
    res.status(404).json({ error: 'Usuário não encontrado.' });
    return;
  }

  // Protect primary admin from disabling themselves
  if (target.username.toLowerCase() === 'vitor silva' && is_active === 0) {
    res.status(400).json({ error: 'O usuário Vitor Silva não pode ser inativado.' });
    return;
  }

  const sectorsJson = Array.isArray(allowed_sectors) ? JSON.stringify(allowed_sectors) : (allowed_sectors || '*');

  db.prepare(`
    UPDATE users
    SET name = COALESCE(?, name),
        username = COALESCE(?, username),
        role = COALESCE(?, role),
        allowed_sectors = COALESCE(?, allowed_sectors),
        is_active = COALESCE(?, is_active)
    WHERE id = ?
  `).run(name?.trim(), username?.trim(), role, sectorsJson, is_active !== undefined ? (is_active ? 1 : 0) : null, id);

  recordAudit(currentUser.id, currentUser.name, 'EDITOU_USUARIO', `Editou dados do usuário ${target.username}`, req);

  res.json({ success: true });
});

app.put('/api/users/:id/reset-password', (req: Request, res: Response) => {
  const currentUser = getAuthUser(req);
  if (!currentUser || currentUser.role !== 'admin') {
    res.status(403).json({ error: 'Acesso restrito a administradores.' });
    return;
  }

  const { id } = req.params;
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) {
    res.status(400).json({ error: 'A nova senha deve ter no mínimo 4 dígitos.' });
    return;
  }

  const target = db.prepare('SELECT username FROM users WHERE id = ?').get(id) as any;
  if (!target) {
    res.status(404).json({ error: 'Usuário não encontrado.' });
    return;
  }

  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(newPassword, salt);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, id);

  recordAudit(currentUser.id, currentUser.name, 'REDEFINIU_SENHA', `Redefiniu a senha do usuário ${target.username}`, req);

  res.json({ success: true, message: `Senha de ${target.username} redefinida com sucesso!` });
});

app.delete('/api/users/:id', (req: Request, res: Response) => {
  const currentUser = getAuthUser(req);
  if (!currentUser || currentUser.role !== 'admin') {
    res.status(403).json({ error: 'Acesso restrito a administradores.' });
    return;
  }

  const { id } = req.params;
  const target = db.prepare('SELECT username FROM users WHERE id = ?').get(id) as any;
  if (!target) {
    res.status(404).json({ error: 'Usuário não encontrado.' });
    return;
  }

  if (target.username.toLowerCase() === 'vitor silva' || id === currentUser.id) {
    res.status(400).json({ error: 'Não é permitido excluir o usuário principal ou sua própria conta.' });
    return;
  }

  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  recordAudit(currentUser.id, currentUser.name, 'EXCLUIU_USUARIO', `Excluiu o usuário ${target.username}`, req);

  res.json({ success: true });
});

// GET /api/audit-logs
app.get('/api/audit-logs', (req: Request, res: Response) => {
  const currentUser = getAuthUser(req);
  if (!currentUser || currentUser.role !== 'admin') {
    res.status(403).json({ error: 'Acesso restrito.' });
    return;
  }

  const logs = db.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200').all();
  res.json(logs);
});

// -----------------------------------------------------------------------------
// SECTORS ROUTES (Including adding custom sectors!)
// -----------------------------------------------------------------------------

app.get('/api/sectors', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  let sectors = db.prepare('SELECT * FROM sectors WHERE is_active = 1 ORDER BY sort_order ASC, name ASC').all() as any[];

  // If user is operator, filter to allowed sectors
  if (user && user.role === 'operator' && user.allowed_sectors !== '*') {
    let allowed: string[] = [];
    try {
      allowed = typeof user.allowed_sectors === 'string' ? JSON.parse(user.allowed_sectors) : user.allowed_sectors;
    } catch {
      allowed = [];
    }
    sectors = sectors.filter(s => allowed.includes(s.id));
  }

  res.json(sectors);
});

app.post('/api/sectors', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  if (!user || (user.role !== 'admin' && user.role !== 'manager')) {
    res.status(403).json({ error: 'Apenas Administradores e Gestores podem cadastrar setores.' });
    return;
  }

  const { name, description, varies_by_day, default_schedules } = req.body;
  if (!name || !name.trim()) {
    res.status(400).json({ error: 'Nome do setor é obrigatório.' });
    return;
  }

  const maxOrder = db.prepare('SELECT MAX(sort_order) as m FROM sectors').get() as { m: number | null };
  const sortOrder = (maxOrder?.m || 0) + 1;
  const id = `sec-${Date.now()}`;
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO sectors (id, name, description, varies_by_day, sort_order, is_active, created_at)
    VALUES (?, ?, ?, ?, ?, 1, ?)
  `).run(id, name.trim(), description?.trim() || '', varies_by_day ? 1 : 0, sortOrder, now);

  // Add default schedules if provided or standard times
  const times = Array.isArray(default_schedules) && default_schedules.length > 0
    ? default_schedules
    : ['08:00', '11:00', '14:00', '17:00'];

  const insertSched = db.prepare(`
    INSERT INTO check_schedules (id, sector_id, time_slot, is_active, sort_order)
    VALUES (?, ?, ?, 1, ?)
  `);

  times.forEach((t: string, idx: number) => {
    insertSched.run(`sched-${Date.now()}-${idx}`, id, t.trim(), idx + 1);
  });

  recordAudit(user.id, user.name, 'CRIOU_SETOR', `Cadastrou o setor ${name}`, req);

  res.status(201).json({ id, name, description, varies_by_day: varies_by_day ? 1 : 0, sort_order: sortOrder });
});

app.put('/api/sectors/:id', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  if (!user || (user.role !== 'admin' && user.role !== 'manager')) {
    res.status(403).json({ error: 'Permissão negada.' });
    return;
  }

  const { id } = req.params;
  const { name, description, varies_by_day, is_active, sort_order } = req.body;

  db.prepare(`
    UPDATE sectors
    SET name = COALESCE(?, name),
        description = COALESCE(?, description),
        varies_by_day = COALESCE(?, varies_by_day),
        is_active = COALESCE(?, is_active),
        sort_order = COALESCE(?, sort_order)
    WHERE id = ?
  `).run(
    name?.trim(),
    description !== undefined ? description.trim() : null,
    varies_by_day !== undefined ? (varies_by_day ? 1 : 0) : null,
    is_active !== undefined ? (is_active ? 1 : 0) : null,
    sort_order !== undefined ? sort_order : null,
    id
  );

  recordAudit(user.id, user.name, 'EDITOU_SETOR', `Atualizou o setor ID ${id}`, req);

  res.json({ success: true });
});

app.delete('/api/sectors/:id', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  if (!user || user.role !== 'admin') {
    res.status(403).json({ error: 'Apenas Administradores podem excluir setores.' });
    return;
  }

  const { id } = req.params;
  db.prepare('DELETE FROM sectors WHERE id = ?').run(id);
  recordAudit(user.id, user.name, 'EXCLUIU_SETOR', `Excluiu o setor ID ${id}`, req);
  res.json({ success: true });
});

// -----------------------------------------------------------------------------
// CHECK SCHEDULES PER SECTOR
// -----------------------------------------------------------------------------

app.get('/api/schedules', (req: Request, res: Response) => {
  const { sector_id } = req.query;
  let query = 'SELECT * FROM check_schedules WHERE is_active = 1';
  const params: any[] = [];
  if (sector_id) {
    query += ' AND sector_id = ?';
    params.push(sector_id);
  }
  query += ' ORDER BY time_slot ASC';
  const schedules = db.prepare(query).all(...params);
  res.json(schedules);
});

app.post('/api/schedules', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  if (!user || (user.role !== 'admin' && user.role !== 'manager')) {
    res.status(403).json({ error: 'Permissão negada.' });
    return;
  }

  const { sector_id, time_slot } = req.body;
  if (!sector_id || !time_slot) {
    res.status(400).json({ error: 'Setor e horário são obrigatórios (ex: 08:00).' });
    return;
  }

  // Format time HH:MM
  const cleanTime = time_slot.trim();
  const id = `sched-${Date.now()}`;
  db.prepare(`
    INSERT INTO check_schedules (id, sector_id, time_slot, is_active, sort_order)
    VALUES (?, ?, ?, 1, 0)
  `).run(id, sector_id, cleanTime);

  recordAudit(user.id, user.name, 'CRIOU_HORARIO', `Adicionou horário ${cleanTime} no setor ${sector_id}`, req);

  res.status(201).json({ id, sector_id, time_slot: cleanTime });
});

app.delete('/api/schedules/:id', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  if (!user || (user.role !== 'admin' && user.role !== 'manager')) {
    res.status(403).json({ error: 'Permissão negada.' });
    return;
  }

  const { id } = req.params;
  db.prepare('DELETE FROM check_schedules WHERE id = ?').run(id);
  res.json({ success: true });
});

// -----------------------------------------------------------------------------
// PRODUCTS MANAGEMENT
// -----------------------------------------------------------------------------

app.get('/api/products', (req: Request, res: Response) => {
  const { sector_id, day_of_week } = req.query;
  let query = 'SELECT * FROM products WHERE is_active = 1';
  const params: any[] = [];

  if (sector_id) {
    query += ' AND sector_id = ?';
    params.push(sector_id);
  }

  query += ' ORDER BY sales_rank ASC, name ASC';
  let products = db.prepare(query).all(...params) as any[];

  // Filter products by day of week if requested (crucial for Cozinha)
  if (day_of_week) {
    const dow = day_of_week.toString().toLowerCase();
    products = products.filter(p => {
      if (!p.days_of_week) return true;
      try {
        const days = JSON.parse(p.days_of_week);
        return days.length === 0 || days.includes(dow);
      } catch {
        return true;
      }
    });
  }

  res.json(products);
});

app.post('/api/products', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  if (!user || (user.role !== 'admin' && user.role !== 'manager')) {
    res.status(403).json({ error: 'Permissão negada.' });
    return;
  }

  const { code, name, sector_id, sales_quantity, days_of_week } = req.body;
  if (!code || !name || !sector_id) {
    res.status(400).json({ error: 'Código, nome e setor são obrigatórios.' });
    return;
  }

  // Calculate new rank
  const maxRank = db.prepare('SELECT MAX(sales_rank) as m FROM products WHERE sector_id = ?').get(sector_id) as { m: number | null };
  const salesRank = (maxRank?.m || 0) + 1;
  const id = `prod-${Date.now()}`;
  const now = new Date().toISOString();
  const daysJson = JSON.stringify(days_of_week || ['seg', 'ter', 'qua', 'qui', 'sex', 'sab', 'dom']);

  db.prepare(`
    INSERT INTO products (id, code, name, sector_id, sales_quantity, sales_rank, days_of_week, is_active, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
  `).run(id, code.trim(), name.trim(), sector_id, Number(sales_quantity) || 0, salesRank, daysJson, now, now);

  // Recalculate ranking based on sales_quantity if specified
  if (sales_quantity > 0) {
    recalculateSectorRanks(sector_id);
  }

  recordAudit(user.id, user.name, 'CRIOU_PRODUTO', `Cadastrou o produto ${name} (${code})`, req);

  res.status(201).json({ id, code, name, sector_id, sales_rank: salesRank });
});

app.put('/api/products/:id', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  if (!user || (user.role !== 'admin' && user.role !== 'manager')) {
    res.status(403).json({ error: 'Permissão negada.' });
    return;
  }

  const { id } = req.params;
  const { code, name, sector_id, sales_quantity, sales_rank, days_of_week, is_active } = req.body;

  const existing = db.prepare('SELECT * FROM products WHERE id = ?').get(id) as any;
  if (!existing) {
    res.status(404).json({ error: 'Produto não encontrado.' });
    return;
  }

  const now = new Date().toISOString();
  const daysJson = days_of_week !== undefined ? JSON.stringify(days_of_week) : null;

  db.prepare(`
    UPDATE products
    SET code = COALESCE(?, code),
        name = COALESCE(?, name),
        sector_id = COALESCE(?, sector_id),
        sales_quantity = COALESCE(?, sales_quantity),
        sales_rank = COALESCE(?, sales_rank),
        days_of_week = COALESCE(?, days_of_week),
        is_active = COALESCE(?, is_active),
        updated_at = ?
    WHERE id = ?
  `).run(
    code?.trim(),
    name?.trim(),
    sector_id,
    sales_quantity !== undefined ? Number(sales_quantity) : null,
    sales_rank !== undefined ? Number(sales_rank) : null,
    daysJson,
    is_active !== undefined ? (is_active ? 1 : 0) : null,
    now,
    id
  );

  if (sales_quantity !== undefined && sector_id) {
    recalculateSectorRanks(sector_id || existing.sector_id);
  }

  res.json({ success: true });
});

function recalculateSectorRanks(sectorId: string) {
  const prods = db.prepare('SELECT id, sales_quantity FROM products WHERE sector_id = ? AND is_active = 1 ORDER BY sales_quantity DESC').all(sectorId) as any[];
  const updateRank = db.prepare('UPDATE products SET sales_rank = ? WHERE id = ?');
  prods.forEach((p, idx) => {
    updateRank.run(idx + 1, p.id);
  });
}

// Reorder manual products in sector
app.post('/api/products/reorder', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  if (!user || (user.role !== 'admin' && user.role !== 'manager')) {
    res.status(403).json({ error: 'Permissão negada.' });
    return;
  }

  const { ordered_ids } = req.body; // array of product ids in desired order
  if (!Array.isArray(ordered_ids)) {
    res.status(400).json({ error: 'ordered_ids inválido' });
    return;
  }

  const updateRank = db.prepare('UPDATE products SET sales_rank = ? WHERE id = ?');
  const runTransaction = db.transaction(() => {
    ordered_ids.forEach((id: string, idx: number) => {
      updateRank.run(idx + 1, id);
    });
  });

  runTransaction();
  res.json({ success: true });
});

// Mass import products from CSV/Excel
app.post('/api/products/import-mass', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  if (!user || (user.role !== 'admin' && user.role !== 'manager')) {
    res.status(403).json({ error: 'Permissão negada.' });
    return;
  }

  const { products, sector_id } = req.body;
  if (!Array.isArray(products) || products.length === 0) {
    res.status(400).json({ error: 'Nenhum produto enviado para importação.' });
    return;
  }

  const now = new Date().toISOString();
  const insertProd = db.prepare(`
    INSERT INTO products (id, code, name, sector_id, sales_quantity, sales_rank, days_of_week, is_active, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
  `);

  let count = 0;
  const runTx = db.transaction(() => {
    products.forEach((p: any, idx: number) => {
      const code = p.code || p.codigo || `IMP-${Date.now()}-${idx}`;
      const name = p.name || p.nome;
      const targetSec = p.sector_id || p.setor_id || sector_id;
      const qty = Number(p.sales_quantity || p.quantidade || p.vendas || 0);

      if (name && targetSec) {
        insertProd.run(
          `prod-imp-${Date.now()}-${idx}`,
          code.toString().trim(),
          name.toString().trim(),
          targetSec,
          qty,
          idx + 1000, // temporary rank
          JSON.stringify(['seg', 'ter', 'qua', 'qui', 'sex', 'sab', 'dom']),
          now,
          now
        );
        count++;
      }
    });
  });

  runTx();

  // Recalculate ranks for target sectors
  const distinctSectors = Array.from(new Set(products.map((p: any) => p.sector_id || p.setor_id || sector_id).filter(Boolean)));
  for (const sId of distinctSectors) {
    recalculateSectorRanks(sId as string);
  }

  recordAudit(user.id, user.name, 'IMPORTACAO_PRODUTOS', `Importou ${count} produtos em massa via planilha`, req);

  res.json({ success: true, count });
});

app.delete('/api/products/:id', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  if (!user || (user.role !== 'admin' && user.role !== 'manager')) {
    res.status(403).json({ error: 'Permissão negada.' });
    return;
  }

  const { id } = req.params;
  db.prepare('DELETE FROM products WHERE id = ?').run(id);
  res.json({ success: true });
});

// -----------------------------------------------------------------------------
// RUPTURE LAUNCH GRID (Preenchimento)
// -----------------------------------------------------------------------------

app.get('/api/ruptures', (req: Request, res: Response) => {
  const { date, sector_id } = req.query;
  if (!date || !sector_id) {
    res.status(400).json({ error: 'Data e setor são obrigatórios.' });
    return;
  }

  const records = db.prepare(`
    SELECT r.*, p.name as product_name, p.code as product_code, p.sales_rank
    FROM rupture_records r
    JOIN products p ON r.product_id = p.id
    WHERE r.date = ? AND r.sector_id = ?
  `).all(date, sector_id);

  res.json(records);
});

// Batch save grid launches with audit and offline sync support
app.post('/api/ruptures/batch', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  if (!user) {
    res.status(401).json({ error: 'Não autenticado.' });
    return;
  }

  const { updates, date, sector_id } = req.body;
  // updates is array of { product_id, time_slot, status (0 | 1 | null) }
  if (!Array.isArray(updates) || !date || !sector_id) {
    res.status(400).json({ error: 'Parâmetros de lançamento inválidos.' });
    return;
  }

  const now = new Date().toISOString();
  const upsertRecord = db.prepare(`
    INSERT INTO rupture_records (id, date, sector_id, product_id, time_slot, status, user_id, user_name, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(date, product_id, time_slot) DO UPDATE SET
      status = excluded.status,
      user_id = excluded.user_id,
      user_name = excluded.user_name,
      updated_at = excluded.updated_at
  `);

  const deleteRecord = db.prepare(`
    DELETE FROM rupture_records
    WHERE date = ? AND product_id = ? AND time_slot = ?
  `);

  let savedCount = 0;
  const runTx = db.transaction(() => {
    for (const item of updates) {
      if (item.status === null || item.status === undefined) {
        deleteRecord.run(date, item.product_id, item.time_slot);
      } else {
        const id = `rec-${date}-${item.product_id}-${item.time_slot}`;
        upsertRecord.run(
          id,
          date,
          sector_id,
          item.product_id,
          item.time_slot,
          item.status === 1 ? 1 : 0,
          user.id,
          user.name,
          now,
          now
        );
        savedCount++;
      }
    }
  });

  runTx();

  recordAudit(user.id, user.name, 'LANCAMENTO_RUPTURA', `Lançou/atualizou ${savedCount} registros para setor ${sector_id} em ${date}`, req);

  res.json({ success: true, saved: savedCount });
});

// Mark all products in a given time_slot as 1 (Tem produto)
app.post('/api/ruptures/mark-all-ones', (req: Request, res: Response) => {
  const user = getAuthUser(req);
  if (!user) {
    res.status(401).json({ error: 'Não autenticado.' });
    return;
  }

  const { date, sector_id, time_slot, product_ids } = req.body;
  if (!date || !sector_id || !time_slot || !Array.isArray(product_ids)) {
    res.status(400).json({ error: 'Parâmetros inválidos.' });
    return;
  }

  const now = new Date().toISOString();
  const upsertRecord = db.prepare(`
    INSERT INTO rupture_records (id, date, sector_id, product_id, time_slot, status, user_id, user_name, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
    ON CONFLICT(date, product_id, time_slot) DO UPDATE SET
      status = 1,
      user_id = excluded.user_id,
      user_name = excluded.user_name,
      updated_at = excluded.updated_at
  `);

  const runTx = db.transaction(() => {
    for (const pid of product_ids) {
      const id = `rec-${date}-${pid}-${time_slot}`;
      upsertRecord.run(id, date, sector_id, pid, time_slot, user.id, user.name, now, now);
    }
  });

  runTx();

  res.json({ success: true, count: product_ids.length });
});

// -----------------------------------------------------------------------------
// ANALYTICS & DASHBOARD REPORTS
// -----------------------------------------------------------------------------

// GET /api/reports/summary
app.get('/api/reports/summary', (req: Request, res: Response) => {
  const { start_date, end_date, sector_id } = req.query;

  let whereClause = 'WHERE 1=1';
  const params: any[] = [];

  if (start_date) {
    whereClause += ' AND r.date >= ?';
    params.push(start_date);
  }
  if (end_date) {
    whereClause += ' AND r.date <= ?';
    params.push(end_date);
  }
  if (sector_id) {
    whereClause += ' AND r.sector_id = ?';
    params.push(sector_id);
  }

  // 1. Overall rupture stats
  const overall = db.prepare(`
    SELECT
      COUNT(*) as total_checks,
      SUM(CASE WHEN r.status = 0 THEN 1 ELSE 0 END) as total_ruptures,
      SUM(CASE WHEN r.status = 1 THEN 1 ELSE 0 END) as total_available
    FROM rupture_records r
    ${whereClause}
  `).get(...params) as any;

  const totalChecks = overall?.total_checks || 0;
  const totalRuptures = overall?.total_ruptures || 0;
  const overallRate = totalChecks > 0 ? (totalRuptures / totalChecks) * 100 : 0;

  // 2. Rupture by Sector
  const bySector = db.prepare(`
    SELECT
      s.id as sector_id,
      s.name as sector_name,
      COUNT(r.id) as total_checks,
      SUM(CASE WHEN r.status = 0 THEN 1 ELSE 0 END) as ruptures,
      ROUND((CAST(SUM(CASE WHEN r.status = 0 THEN 1 ELSE 0 END) AS REAL) / COUNT(r.id)) * 100, 1) as rupture_rate
    FROM sectors s
    LEFT JOIN rupture_records r ON s.id = r.sector_id ${start_date ? 'AND r.date >= ?' : ''} ${end_date ? 'AND r.date <= ?' : ''}
    WHERE s.is_active = 1
    GROUP BY s.id, s.name
    ORDER BY rupture_rate DESC
  `).all(...[...(start_date ? [start_date] : []), ...(end_date ? [end_date] : [])]) as any[];

  // 3. Rupture by Time Slot (Critical Time)
  const byTimeSlot = db.prepare(`
    SELECT
      r.time_slot,
      COUNT(r.id) as total_checks,
      SUM(CASE WHEN r.status = 0 THEN 1 ELSE 0 END) as ruptures,
      ROUND((CAST(SUM(CASE WHEN r.status = 0 THEN 1 ELSE 0 END) AS REAL) / COUNT(r.id)) * 100, 1) as rupture_rate
    FROM rupture_records r
    ${whereClause}
    GROUP BY r.time_slot
    ORDER BY rupture_rate DESC
  `).all(...params) as any[];

  // 4. Most Missing Products
  const topMissing = db.prepare(`
    SELECT
      p.id,
      p.name,
      p.code,
      p.sales_rank,
      s.name as sector_name,
      COUNT(r.id) as total_checks,
      SUM(CASE WHEN r.status = 0 THEN 1 ELSE 0 END) as ruptures,
      ROUND((CAST(SUM(CASE WHEN r.status = 0 THEN 1 ELSE 0 END) AS REAL) / COUNT(r.id)) * 100, 1) as rupture_rate
    FROM rupture_records r
    JOIN products p ON r.product_id = p.id
    JOIN sectors s ON p.sector_id = s.id
    ${whereClause}
    GROUP BY p.id, p.name, p.code, p.sales_rank, s.name
    HAVING total_checks >= 3
    ORDER BY rupture_rate DESC, ruptures DESC
    LIMIT 10
  `).all(...params) as any[];

  // 5. High Turnover Products at Risk (Top 3 sales rank with rupture > 10%)
  const highTurnoverAlerts = db.prepare(`
    SELECT
      p.id,
      p.name,
      p.code,
      p.sales_rank,
      p.sales_quantity,
      s.name as sector_name,
      COUNT(r.id) as total_checks,
      SUM(CASE WHEN r.status = 0 THEN 1 ELSE 0 END) as ruptures,
      ROUND((CAST(SUM(CASE WHEN r.status = 0 THEN 1 ELSE 0 END) AS REAL) / COUNT(r.id)) * 100, 1) as rupture_rate
    FROM rupture_records r
    JOIN products p ON r.product_id = p.id
    JOIN sectors s ON p.sector_id = s.id
    ${whereClause} AND p.sales_rank <= 3
    GROUP BY p.id, p.name, p.code, p.sales_rank, p.sales_quantity, s.name
    HAVING rupture_rate >= 5
    ORDER BY p.sales_rank ASC, rupture_rate DESC
  `).all(...params) as any[];

  res.json({
    totalChecks,
    totalRuptures,
    overallRate: Number(overallRate.toFixed(1)),
    worstSector: bySector[0] || null,
    criticalTime: byTimeSlot[0] || null,
    sectorsList: bySector,
    timeSlotsList: byTimeSlot,
    topMissing,
    highTurnoverAlerts
  });
});

// GET /api/reports/heatmap (Product x Time Slot matrix)
app.get('/api/reports/heatmap', (req: Request, res: Response) => {
  const { sector_id, start_date, end_date } = req.query;
  if (!sector_id) {
    res.status(400).json({ error: 'sector_id é obrigatório.' });
    return;
  }

  let where = 'WHERE r.sector_id = ?';
  const params: any[] = [sector_id];
  if (start_date) {
    where += ' AND r.date >= ?';
    params.push(start_date);
  }
  if (end_date) {
    where += ' AND r.date <= ?';
    params.push(end_date);
  }

  const cells = db.prepare(`
    SELECT
      r.product_id,
      p.name as product_name,
      p.code as product_code,
      p.sales_rank,
      r.time_slot,
      COUNT(r.id) as total_checks,
      SUM(CASE WHEN r.status = 0 THEN 1 ELSE 0 END) as ruptures,
      ROUND((CAST(SUM(CASE WHEN r.status = 0 THEN 1 ELSE 0 END) AS REAL) / COUNT(r.id)) * 100, 1) as rupture_rate
    FROM rupture_records r
    JOIN products p ON r.product_id = p.id
    ${where}
    GROUP BY r.product_id, p.name, p.code, p.sales_rank, r.time_slot
    ORDER BY p.sales_rank ASC, r.time_slot ASC
  `).all(...params) as any[];

  // Get all active time slots for this sector
  const timeSlots = db.prepare('SELECT time_slot FROM check_schedules WHERE sector_id = ? AND is_active = 1 ORDER BY time_slot ASC').all(sector_id).map((s: any) => s.time_slot);

  // Get all active products for this sector
  const products = db.prepare('SELECT id, code, name, sales_rank FROM products WHERE sector_id = ? AND is_active = 1 ORDER BY sales_rank ASC').all(sector_id);

  res.json({
    timeSlots,
    products,
    cells
  });
});

// GET /api/reports/weekly-sheet (Acompanhamento Semanal formato folha de conferência)
app.get('/api/reports/weekly-sheet', (req: Request, res: Response) => {
  const { sector_id, week_start_date } = req.query; // e.g. 2026-10-19 (Monday)
  if (!sector_id || !week_start_date) {
    res.status(400).json({ error: 'sector_id e week_start_date são obrigatórios.' });
    return;
  }

  // Calculate 7 days from week_start_date
  const startDate = new Date(week_start_date as string);
  const dates: string[] = [];
  const dayNames = ['Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta', 'Sábado', 'Domingo'];

  for (let i = 0; i < 7; i++) {
    const d = new Date(startDate);
    d.setDate(startDate.getDate() + i);
    dates.push(d.toISOString().split('T')[0]);
  }

  const minDate = dates[0];
  const maxDate = dates[6];

  const products = db.prepare('SELECT id, code, name, sales_rank FROM products WHERE sector_id = ? AND is_active = 1 ORDER BY sales_rank ASC').all(sector_id);
  const timeSlots = db.prepare('SELECT time_slot FROM check_schedules WHERE sector_id = ? AND is_active = 1 ORDER BY time_slot ASC').all(sector_id).map((s: any) => s.time_slot);

  const records = db.prepare(`
    SELECT product_id, date, time_slot, status, user_name, updated_at
    FROM rupture_records
    WHERE sector_id = ? AND date >= ? AND date <= ?
  `).all(sector_id, minDate, maxDate);

  res.json({
    dates,
    dayNames,
    products,
    timeSlots,
    records
  });
});

// -----------------------------------------------------------------------------
// VITE MIDDLEWARE (DEV) OR STATIC SERVE (PROD)
// -----------------------------------------------------------------------------

async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(process.cwd(), 'dist')));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.resolve(process.cwd(), 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Gapless Server running at http://0.0.0.0:${PORT}`);
  });
}

startServer();
