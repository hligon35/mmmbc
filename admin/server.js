/* eslint-disable no-console */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');
const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const mime = require('mime-types');
const sharp = require('sharp');

require('dotenv').config({ path: path.join(__dirname, '.env') });

const ROOT_DIR = path.resolve(__dirname, '..');
const ADMIN_DIR = path.resolve(__dirname);
const DATA_DIR = path.join(ADMIN_DIR, 'data');
const UPLOADS_DIR = path.join(ADMIN_DIR, 'uploads');
const DOCS_UPLOADS_DIR = path.join(UPLOADS_DIR, 'docs');
const BULLETINS_UPLOADS_DIR = path.join(UPLOADS_DIR, 'bulletins');
const ROOT_BULLETINS_DIR = path.join(ROOT_DIR, 'bulletins');
const GALLERY_DIR = path.join(ROOT_DIR, 'ConImg', 'gallery');
const PORT = Number(process.env.PORT || 8787);
const ENABLE_EXPORTS = String(process.env.ENABLE_EXPORTS || 'true').toLowerCase() === 'true';
const SESSIONS_DIR = process.env.SESSIONS_DIR
  ? path.resolve(process.env.SESSIONS_DIR)
  : path.join(os.tmpdir(), 'mmmbc-admin-sessions');

function mustGetEnv(name) {
  const val = process.env[name];
  if (!val) throw new Error(`Missing required env var: ${name}`);
  return String(val);
}

function readJson(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJsonAtomic(filePath, data) {
  const tmp = `${filePath}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, filePath);
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function newId() {
  return typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : crypto.randomBytes(16).toString('hex');
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(String(input)).digest('hex');
}

function randomToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function getBaseUrl(req) {
  // Prefer explicit base URL for invite links (useful if accessed on LAN)
  const configured = String(process.env.PUBLIC_BASE_URL || '').trim();
  if (configured) return configured.replace(/\/$/, '');
  return `${req.protocol}://${req.get('host')}`;
}

function findUserByInviteToken(users, token) {
  const hash = sha256Hex(token);
  return users.find((u) => u.inviteTokenHash === hash);
}

function isInviteValid(user) {
  if (!user?.inviteTokenHash) return false;
  if (!user?.inviteExpiresAt) return false;
  const exp = Date.parse(user.inviteExpiresAt);
  if (!Number.isFinite(exp)) return false;
  return Date.now() < exp;
}

function normalizeTotp(code) {
  return String(code || '').replace(/\s+/g, '');
}

function sanitizeSegment(input) {
  return String(input || '')
    .trim()
    .replace(/[^a-zA-Z0-9-_ ]/g, '')
    .replace(/\s+/g, ' ')
    .slice(0, 80);
}

function requireAuth(req, res, next) {
  if (req.session && req.session.user && req.session.user.role === 'admin') return next();
  res.status(401).json({ error: 'Unauthorized' });
}

function isAllowedImage(mimeType) {
  return ['image/jpeg', 'image/png', 'image/webp', 'image/gif'].includes(mimeType);
}

const app = express();
app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(rateLimit({ windowMs: 60 * 1000, limit: 120 }));

// Store sessions outside OneDrive-backed folders to avoid EPERM rename issues on Windows.
ensureDir(SESSIONS_DIR);

app.use(
  session({
    name: 'mmmbc_admin',
    secret: mustGetEnv('SESSION_SECRET'),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: false
    },
    store: new FileStore({ path: SESSIONS_DIR })
  })
);

// Serve theme.css dynamically so an authenticated admin can preview theme changes
// without writing the real theme.css file.
// NOTE: This MUST be registered before the root static middleware.
app.get('/theme.css', (req, res) => {
  const preview = req.session?.themePreview;
  if (preview) {
    res.setHeader('Content-Type', 'text/css; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    return res.send(buildThemeCss(preview));
  }

  // If an exported theme.css exists, serve it. Otherwise, build from saved settings.
  const themePath = path.join(ROOT_DIR, 'theme.css');
  res.setHeader('Content-Type', 'text/css; charset=utf-8');
  if (fs.existsSync(themePath)) {
    res.setHeader('Cache-Control', 'no-cache');
    return res.send(fs.readFileSync(themePath, 'utf8'));
  }

  const settings = loadSettings();
  res.setHeader('Cache-Control', 'no-cache');
  return res.send(buildThemeCss(settings.theme));
});

// Serve the existing site (repo root)
app.use('/', express.static(ROOT_DIR, { extensions: ['html'] }));
// Serve admin UI under /admin/
app.use('/admin', express.static(path.join(ADMIN_DIR, 'public'), { extensions: ['html'] }));

// Expose gallery images and uploaded docs
app.use('/ConImg/gallery', express.static(GALLERY_DIR));
app.use('/admin-uploads/docs', express.static(DOCS_UPLOADS_DIR));
app.use('/admin-uploads/bulletins', express.static(BULLETINS_UPLOADS_DIR));

const USERS_PATH = path.join(DATA_DIR, 'users.json');
const GALLERY_DATA_PATH = path.join(DATA_DIR, 'gallery.json');
const EVENTS_DATA_PATH = path.join(DATA_DIR, 'events.json');
const ANNOUNCEMENTS_DATA_PATH = path.join(DATA_DIR, 'announcements.json');
const DOCUMENTS_DATA_PATH = path.join(DATA_DIR, 'documents.json');
const BULLETINS_DATA_PATH = path.join(DATA_DIR, 'bulletins.json');
const LIVESTREAM_DATA_PATH = path.join(DATA_DIR, 'livestream.json');
const SETTINGS_DATA_PATH = path.join(DATA_DIR, 'settings.json');

function loadUsers() {
  return readJson(USERS_PATH, { users: [] });
}
function saveUsers(data) {
  writeJsonAtomic(USERS_PATH, data);
}

function passwordPolicyError(password) {
  const p = String(password || '');
  if (p.length < 8) return 'Password must be at least 8 characters.';
  if (!/[A-Z]/.test(p)) return 'Password must include at least 1 capital letter.';
  if (!/[^A-Za-z0-9]/.test(p)) return 'Password must include at least 1 special character.';
  return '';
}

function requireStrongPassword(password) {
  const err = passwordPolicyError(password);
  if (err) {
    const e = new Error(err);
    e.statusCode = 400;
    throw e;
  }
}

async function ensureMasterAdmin() {
  const email = mustGetEnv('ADMIN_EMAIL').toLowerCase();
  const password = mustGetEnv('ADMIN_PASSWORD');

  const policyErr = passwordPolicyError(password);
  if (policyErr) {
    console.warn(`[MMMBC Admin] WARNING: ADMIN_PASSWORD does not meet policy: ${policyErr}`);
  }

  const usersData = loadUsers();
  const users = Array.isArray(usersData.users) ? usersData.users : [];

  let user = users.find((u) => String(u.email).toLowerCase() === email);
  const passwordHash = await bcrypt.hash(password, 12);

  if (!user) {
    user = {
      id: newId(),
      email,
      passwordHash,
      role: 'admin',
      createdAt: new Date().toISOString(),
      isMaster: true,
      name: 'Master Admin',
      mustOnboard: false,
      onboardedAt: new Date().toISOString(),
      twoFactorEnabled: false,
      twoFactorSecret: ''
    };
    users.push(user);
  } else {
    // Keep env vars as source of truth for master password.
    user.passwordHash = passwordHash;
    user.role = 'admin';
    user.isMaster = true;
    if (!user.name) user.name = 'Master Admin';
    if (typeof user.mustOnboard !== 'boolean') user.mustOnboard = false;
    if (typeof user.twoFactorEnabled !== 'boolean') user.twoFactorEnabled = false;
    if (!user.twoFactorSecret) user.twoFactorSecret = '';
  }

  saveUsers({ users });
}

// ----------------- AUTH -----------------
app.get('/api/me', (req, res) => {
  const sessionUser = req.session?.user;
  if (!sessionUser?.id) return res.json({ user: null });

  const usersData = loadUsers();
  const user = (usersData.users || []).find((u) => u.id === sessionUser.id);
  if (!user) return res.json({ user: null });

  // Keep session in sync with stored user.
  req.session.user = {
    id: user.id,
    email: user.email,
    role: user.role,
    name: user.name || '',
    isMaster: !!user.isMaster,
    mustOnboard: !!user.mustOnboard,
    twoFactorEnabled: !!user.twoFactorEnabled
  };
  res.json({ user: req.session.user });
});

app.post('/api/auth/login', async (req, res) => {
  const email = String(req.body.email || '').toLowerCase().trim();
  const password = String(req.body.password || '');
  const twoFactorCode = normalizeTotp(req.body.twoFactorCode || '');
  const usersData = loadUsers();
  const user = (usersData.users || []).find((u) => String(u.email).toLowerCase() === email);
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  if (user.mustOnboard) {
    return res.status(403).json({ error: 'Account setup required. Use your invite link to finish setup.' });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

  if (user.twoFactorEnabled) {
    if (!twoFactorCode) return res.status(401).json({ error: '2FA code required' });
    const verified = speakeasy.totp.verify({
      secret: String(user.twoFactorSecret || ''),
      encoding: 'base32',
      token: twoFactorCode,
      window: 1
    });
    if (!verified) return res.status(401).json({ error: 'Invalid 2FA code' });
  }

  req.session.user = {
    id: user.id,
    email: user.email,
    role: user.role,
    name: user.name || '',
    isMaster: !!user.isMaster,
    mustOnboard: !!user.mustOnboard,
    twoFactorEnabled: !!user.twoFactorEnabled
  };
  res.json({ ok: true });
});

// Recovery-code based reset (no email sending required)
app.post('/api/auth/recover', async (req, res) => {
  const email = String(req.body.email || '').toLowerCase().trim();
  const recoveryCode = String(req.body.recoveryCode || '').trim();
  const newPassword = String(req.body.newPassword || '');

  const expected = process.env.ADMIN_RECOVERY_CODE;
  if (!expected) return res.status(503).json({ error: 'Recovery is not enabled on this server.' });
  if (!email || !recoveryCode || !newPassword) return res.status(400).json({ error: 'Missing fields.' });
  if (recoveryCode !== String(expected)) return res.status(401).json({ error: 'Invalid recovery code.' });

  try {
    requireStrongPassword(newPassword);
  } catch (e) {
    return res.status(e.statusCode || 400).json({ error: e.message || 'Invalid password.' });
  }

  const usersData = loadUsers();
  const users = Array.isArray(usersData.users) ? usersData.users : [];
  const user = users.find((u) => String(u.email).toLowerCase() === email);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  if (user.isMaster) return res.status(400).json({ error: 'Master admin password is controlled by environment variables.' });

  user.passwordHash = await bcrypt.hash(newPassword, 12);
  saveUsers({ users });
  res.json({ ok: true });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ----------------- USERS (admin) -----------------
app.get('/api/users', requireAuth, (req, res) => {
  const usersData = loadUsers();
  const safe = (usersData.users || []).map((u) => ({
    id: u.id,
    email: u.email,
    name: u.name || '',
    role: u.role,
    createdAt: u.createdAt,
    isMaster: !!u.isMaster
  }));
  res.json({ users: safe });
});

app.post('/api/users', requireAuth, async (req, res) => {
  const email = String(req.body.email || '').toLowerCase().trim();
  const password = String(req.body.password || '');
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    requireStrongPassword(password);
  } catch (e) {
    return res.status(e.statusCode || 400).json({ error: e.message || 'Invalid password.' });
  }

  const usersData = loadUsers();
  const users = usersData.users || [];
  if (users.some((u) => String(u.email).toLowerCase() === email)) {
    return res.status(409).json({ error: 'User already exists' });
  }

  users.push({
    id: newId(),
    email,
    passwordHash: await bcrypt.hash(password, 12),
    role: 'admin',
    createdAt: new Date().toISOString(),
    isMaster: false,
    name: ''
  });

  saveUsers({ users });
  res.json({ ok: true });
});

// Create an invite link for a new admin (recommended flow)
app.post('/api/users/invite', requireAuth, async (req, res) => {
  const email = String(req.body.email || '').toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'Email is required' });

  const usersData = loadUsers();
  const users = Array.isArray(usersData.users) ? usersData.users : [];
  if (users.some((u) => String(u.email).toLowerCase() === email)) {
    return res.status(409).json({ error: 'User already exists' });
  }

  const token = randomToken();
  const tokenHash = sha256Hex(token);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  const placeholderPassword = randomToken();

  users.push({
    id: newId(),
    email,
    passwordHash: await bcrypt.hash(placeholderPassword, 12),
    role: 'admin',
    createdAt: new Date().toISOString(),
    isMaster: false,
    name: '',
    mustOnboard: true,
    onboardedAt: '',
    inviteTokenHash: tokenHash,
    inviteExpiresAt: expiresAt,
    twoFactorEnabled: false,
    twoFactorSecret: '',
    twoFactorPendingSecret: ''
  });

  saveUsers({ users });

  const base = getBaseUrl(req);
  const inviteLink = `${base}/admin/#invite=${token}`;
  res.json({ ok: true, inviteLink, expiresAt });
});

// Invite details + 2FA setup payload
app.get('/api/invites/:token', async (req, res) => {
  const token = String(req.params.token || '').trim();
  if (!token) return res.status(400).json({ error: 'Missing token' });

  const usersData = loadUsers();
  const users = Array.isArray(usersData.users) ? usersData.users : [];
  const user = findUserByInviteToken(users, token);
  if (!user || !isInviteValid(user)) return res.status(404).json({ error: 'Invite link is invalid or expired.' });

  if (!user.twoFactorPendingSecret) {
    const secret = speakeasy.generateSecret({
      name: `MMMBC Admin (${user.email})`,
      length: 20
    });
    user.twoFactorPendingSecret = secret.base32;
    saveUsers({ users });
  }

  const otpauthUrl = speakeasy.otpauthURL({
    secret: user.twoFactorPendingSecret,
    label: `MMMBC Admin:${user.email}`,
    issuer: 'MMMBC Admin',
    encoding: 'base32'
  });

  const qrDataUrl = await qrcode.toDataURL(otpauthUrl, { margin: 1, scale: 6 });

  res.json({
    email: user.email,
    expiresAt: user.inviteExpiresAt,
    twoFactor: {
      secret: user.twoFactorPendingSecret,
      otpauthUrl,
      qrDataUrl
    }
  });
});

// Complete onboarding (name + password + confirm 2FA)
app.post('/api/invites/:token/complete', async (req, res) => {
  const token = String(req.params.token || '').trim();
  const name = String(req.body?.name || '').trim();
  const newPassword = String(req.body?.newPassword || '');
  const twoFactorCode = normalizeTotp(req.body?.twoFactorCode || '');
  if (!token) return res.status(400).json({ error: 'Missing token' });

  const usersData = loadUsers();
  const users = Array.isArray(usersData.users) ? usersData.users : [];
  const user = findUserByInviteToken(users, token);
  if (!user || !isInviteValid(user)) return res.status(404).json({ error: 'Invite link is invalid or expired.' });

  try {
    requireStrongPassword(newPassword);
  } catch (e) {
    return res.status(e.statusCode || 400).json({ error: e.message || 'Invalid password.' });
  }

  const pending = String(user.twoFactorPendingSecret || '');
  if (!pending) return res.status(400).json({ error: '2FA setup not initialized. Refresh and try again.' });
  if (!twoFactorCode) return res.status(400).json({ error: '2FA code is required.' });

  const verified = speakeasy.totp.verify({
    secret: pending,
    encoding: 'base32',
    token: twoFactorCode,
    window: 1
  });
  if (!verified) return res.status(400).json({ error: 'Invalid 2FA code. Check your authenticator app and try again.' });

  user.name = name;
  user.passwordHash = await bcrypt.hash(newPassword, 12);
  user.mustOnboard = false;
  user.onboardedAt = new Date().toISOString();
  user.twoFactorEnabled = true;
  user.twoFactorSecret = pending;
  user.twoFactorPendingSecret = '';
  user.inviteTokenHash = '';
  user.inviteExpiresAt = '';

  saveUsers({ users });

  // Log them in immediately after successful onboarding
  req.session.user = {
    id: user.id,
    email: user.email,
    role: user.role,
    name: user.name || '',
    isMaster: !!user.isMaster,
    mustOnboard: !!user.mustOnboard,
    twoFactorEnabled: !!user.twoFactorEnabled
  };

  res.json({ ok: true });
});

// ----------------- ACCOUNT (self service) -----------------
app.put('/api/account', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const nextName = String(req.body?.name || '').trim();
  const nextEmail = String(req.body?.email || '').toLowerCase().trim();
  if (!nextEmail) return res.status(400).json({ error: 'Email is required.' });

  const usersData = loadUsers();
  const users = Array.isArray(usersData.users) ? usersData.users : [];
  const user = users.find((u) => u.id === userId);
  if (!user) return res.status(404).json({ error: 'Not found' });

  if (user.isMaster) {
    return res.status(400).json({ error: 'Master admin email is controlled by environment variables.' });
  }

  if (users.some((u) => u.id !== user.id && String(u.email).toLowerCase() === nextEmail)) {
    return res.status(409).json({ error: 'Email is already in use.' });
  }

  user.name = nextName;
  user.email = nextEmail;
  saveUsers({ users });
  req.session.user = { id: user.id, email: user.email, role: user.role, name: user.name || '', isMaster: !!user.isMaster };
  res.json({ ok: true });
});

app.put('/api/account/password', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  const currentPassword = String(req.body?.currentPassword || '');
  const newPassword = String(req.body?.newPassword || '');
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Missing fields.' });

  try {
    requireStrongPassword(newPassword);
  } catch (e) {
    return res.status(e.statusCode || 400).json({ error: e.message || 'Invalid password.' });
  }

  const usersData = loadUsers();
  const users = Array.isArray(usersData.users) ? usersData.users : [];
  const user = users.find((u) => u.id === userId);
  if (!user) return res.status(404).json({ error: 'Not found' });
  if (user.isMaster) return res.status(400).json({ error: 'Master admin password is controlled by environment variables.' });

  const ok = await bcrypt.compare(currentPassword, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Current password is incorrect.' });

  user.passwordHash = await bcrypt.hash(newPassword, 12);
  saveUsers({ users });
  res.json({ ok: true });
});

app.delete('/api/users/:id', requireAuth, (req, res) => {
  const usersData = loadUsers();
  const users = usersData.users || [];
  const id = String(req.params.id);
  const user = users.find((u) => u.id === id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  if (user.isMaster) return res.status(400).json({ error: 'Cannot delete master admin' });

  const next = users.filter((u) => u.id !== id);
  saveUsers({ users: next });
  res.json({ ok: true });
});

// ----------------- GALLERY -----------------
function loadGallery() {
  return readJson(GALLERY_DATA_PATH, { items: [] });
}
function saveGallery(data) {
  writeJsonAtomic(GALLERY_DATA_PATH, data);
}

const galleryUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024, files: 20 }
});

app.get('/api/gallery', requireAuth, (req, res) => {
  res.json(loadGallery());
});

app.post('/api/gallery/upload', requireAuth, galleryUpload.array('images', 20), async (req, res) => {
  const album = sanitizeSegment(req.body.album || 'General') || 'General';
  const label = sanitizeSegment(req.body.label || '') || '';
  const tagsRaw = String(req.body.tags || '');
  const tags = tagsRaw
    .split(',')
    .map((t) => sanitizeSegment(t).toLowerCase())
    .filter(Boolean)
    .slice(0, 25);

  ensureDir(path.join(GALLERY_DIR, album));
  ensureDir(path.join(GALLERY_DIR, album, '_thumbs'));

  const gallery = loadGallery();
  const items = Array.isArray(gallery.items) ? gallery.items : [];

  const files = req.files || [];
  const added = [];

  for (const file of files) {
    const mimeType = file.mimetype;
    if (!isAllowedImage(mimeType)) continue;

    const ext = mime.extension(mimeType) || 'jpg';
    const id = newId();
    const safeBase = sanitizeSegment(path.parse(file.originalname).name).replace(/\s+/g, '-') || 'image';
    const fileName = `${new Date().toISOString().slice(0, 10)}_${safeBase}_${id}.${ext}`;
    const relPath = path.posix.join('ConImg', 'gallery', album, fileName);
    const absPath = path.join(GALLERY_DIR, album, fileName);

    fs.writeFileSync(absPath, file.buffer);

    // Thumbnail
    const thumbName = fileName.replace(/\.[^.]+$/, '.jpg');
    const relThumb = path.posix.join('ConImg', 'gallery', album, '_thumbs', thumbName);
    const absThumb = path.join(GALLERY_DIR, album, '_thumbs', thumbName);

    try {
      await sharp(file.buffer)
        .rotate()
        .resize(420, 420, { fit: 'cover' })
        .jpeg({ quality: 80 })
        .toFile(absThumb);
    } catch {
      // If sharp fails, skip thumbnail.
    }

    const createdAt = new Date().toISOString();

    const item = {
      id,
      album,
      label,
      tags,
      file: `/${relPath.replace(/\\/g, '/')}`,
      thumb: fs.existsSync(absThumb) ? `/${relThumb.replace(/\\/g, '/')}` : `/${relPath.replace(/\\/g, '/')}`,
      originalName: file.originalname,
      createdAt
    };

    items.unshift(item);
    added.push(item);
  }

  saveGallery({ items });

  if (ENABLE_EXPORTS) {
    writeJsonAtomic(path.join(ROOT_DIR, 'gallery.json'), { items });
  }

  res.json({ ok: true, added });
});

app.put('/api/gallery/:id', requireAuth, (req, res) => {
  const id = String(req.params.id);
  const gallery = loadGallery();
  const items = Array.isArray(gallery.items) ? gallery.items : [];
  const item = items.find((x) => x.id === id);
  if (!item) return res.status(404).json({ error: 'Not found' });

  if (req.body.album) item.album = sanitizeSegment(req.body.album) || item.album;
  if (typeof req.body.label === 'string') item.label = sanitizeSegment(req.body.label);
  if (typeof req.body.tags === 'string') {
    item.tags = String(req.body.tags)
      .split(',')
      .map((t) => sanitizeSegment(t).toLowerCase())
      .filter(Boolean)
      .slice(0, 25);
  }

  saveGallery({ items });
  if (ENABLE_EXPORTS) writeJsonAtomic(path.join(ROOT_DIR, 'gallery.json'), { items });

  res.json({ ok: true, item });
});

app.delete('/api/gallery/:id', requireAuth, (req, res) => {
  const id = String(req.params.id);
  const gallery = loadGallery();
  const items = Array.isArray(gallery.items) ? gallery.items : [];
  const idx = items.findIndex((x) => x.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });

  const [removed] = items.splice(idx, 1);

  // Best-effort delete image + thumbnail
  try {
    if (removed?.file) {
      const abs = path.join(ROOT_DIR, removed.file.replace(/^\//, ''));
      if (fs.existsSync(abs)) fs.unlinkSync(abs);
    }
    if (removed?.thumb && removed.thumb.includes('/_thumbs/')) {
      const absT = path.join(ROOT_DIR, removed.thumb.replace(/^\//, ''));
      if (fs.existsSync(absT)) fs.unlinkSync(absT);
    }
  } catch {
    // ignore
  }

  saveGallery({ items });
  if (ENABLE_EXPORTS) writeJsonAtomic(path.join(ROOT_DIR, 'gallery.json'), { items });

  res.json({ ok: true });
});

// ----------------- ANNOUNCEMENTS -----------------
function loadAnnouncements() {
  const data = readJson(ANNOUNCEMENTS_DATA_PATH, { posts: [] });
  return pruneAndPersistAnnouncements(data);
}
function saveAnnouncements(data) {
  writeJsonAtomic(ANNOUNCEMENTS_DATA_PATH, data);
}

function parseExpiresAtFromBody(body) {
  const now = Date.now();

  // Explicit never-expire
  if (body?.expiresInDays === null) return null;

  // Explicit ISO timestamp wins
  if (typeof body?.expiresAt === 'string' && body.expiresAt.trim()) {
    const t = Date.parse(body.expiresAt);
    if (!Number.isNaN(t)) return new Date(t).toISOString();
  }

  // Days-based lifecycle
  if (body?.expiresInDays !== undefined && body?.expiresInDays !== null && String(body.expiresInDays).trim() !== '') {
    const n = Number(body.expiresInDays);
    if (Number.isFinite(n) && n > 0) return new Date(now + n * 24 * 60 * 60 * 1000).toISOString();
    return null; // 0/invalid => never
  }

  // Default lifecycle to reduce clutter
  return new Date(now + 30 * 24 * 60 * 60 * 1000).toISOString();
}

function isAnnouncementExpired(post) {
  if (!post?.expiresAt) return false;
  const t = Date.parse(post.expiresAt);
  if (Number.isNaN(t)) return false;
  return t <= Date.now();
}

function pruneAndPersistAnnouncements(data) {
  const posts = Array.isArray(data?.posts) ? data.posts : [];
  const next = posts.filter((p) => p && (p.title || p.body) && !isAnnouncementExpired(p));
  if (next.length !== posts.length) {
    const cleaned = { posts: next };
    saveAnnouncements(cleaned);
    if (ENABLE_EXPORTS) writeJsonAtomic(path.join(ROOT_DIR, 'announcements.json'), cleaned);
    return cleaned;
  }
  return { posts };
}

app.get('/api/announcements', requireAuth, (req, res) => {
  res.json(loadAnnouncements());
});

app.post('/api/announcements', requireAuth, (req, res) => {
  const title = String(req.body.title || '').trim().slice(0, 120);
  const body = String(req.body.body || '').trim().slice(0, 5000);
  if (!title || !body) return res.status(400).json({ error: 'Title and body required' });

  const data = loadAnnouncements();
  const posts = Array.isArray(data.posts) ? data.posts : [];
  const expiresAt = parseExpiresAtFromBody(req.body);
  const post = { id: newId(), title, body, createdAt: new Date().toISOString(), expiresAt };
  posts.unshift(post);
  const saved = pruneAndPersistAnnouncements({ posts });

  if (ENABLE_EXPORTS) writeJsonAtomic(path.join(ROOT_DIR, 'announcements.json'), saved);

  res.json({ ok: true, post });
});

app.delete('/api/announcements/:id', requireAuth, (req, res) => {
  const id = String(req.params.id);
  const data = loadAnnouncements();
  const posts = Array.isArray(data.posts) ? data.posts : [];
  const next = posts.filter((p) => p.id !== id);
  saveAnnouncements({ posts: next });
  if (ENABLE_EXPORTS) writeJsonAtomic(path.join(ROOT_DIR, 'announcements.json'), { posts: next });
  res.json({ ok: true });
});

// ----------------- EVENTS (exports to schedule.json) -----------------
function stableEventId(title, date, time) {
  const key = `${String(title || '').trim().toLowerCase()}|${String(date || '').trim()}|${String(time || '').trim()}`;
  return crypto.createHash('sha1').update(key).digest('hex').slice(0, 16);
}

function normalizeTimeValue(value) {
  const t = String(value || '').trim();
  if (!t) return '';
  const m = t.match(/^([0-2]\d):([0-5]\d)/);
  return m ? `${m[1]}:${m[2]}` : '';
}

function normalizeAndSortScheduleLike(events) {
  return (events || [])
    .filter((ev) => ev && ev.title && ev.date)
    .map((ev) => ({
      title: String(ev.title).trim().slice(0, 120),
      date: String(ev.date).trim(),
      time: normalizeTimeValue(ev.time)
    }))
    .sort((a, b) => new Date(`${a.date}T${a.time || '00:00'}`) - new Date(`${b.date}T${b.time || '00:00'}`));
}

function loadEvents() {
  const stored = readJson(EVENTS_DATA_PATH, { events: [] });
  const storedEvents = Array.isArray(stored.events) ? stored.events : [];

  // If schedule.json exists, treat it as the source of truth for what the website scheduler shows.
  const schedulePath = path.join(ROOT_DIR, 'schedule.json');
  if (!ENABLE_EXPORTS || !fs.existsSync(schedulePath)) {
    return { events: storedEvents };
  }

  const scheduleArray = readJson(schedulePath, null);
  if (!Array.isArray(scheduleArray)) {
    return { events: storedEvents };
  }

  const normalized = normalizeAndSortScheduleLike(scheduleArray);
  const keyOf = (e) => `${String(e.title || '').trim().toLowerCase()}|${String(e.date || '').trim()}|${String(e.time || '').trim()}`;
  const existingByKey = new Map(storedEvents.map((e) => [keyOf(e), e]));

  const merged = normalized.map((ev) => {
    const existing = existingByKey.get(keyOf(ev));
    const id = existing?.id || stableEventId(ev.title, ev.date, ev.time);
    return {
      id,
      title: ev.title,
      date: ev.date,
      time: ev.time,
      createdAt: existing?.createdAt || new Date().toISOString(),
      updatedAt: existing?.updatedAt
    };
  });

  const storedComparable = JSON.stringify(storedEvents.map((e) => ({ id: e.id, title: e.title, date: e.date, time: e.time })));
  const mergedComparable = JSON.stringify(merged.map((e) => ({ id: e.id, title: e.title, date: e.date, time: e.time })));

  if (storedComparable !== mergedComparable) {
    saveEvents({ events: merged });
  }

  return { events: merged };
}
function saveEvents(data) {
  writeJsonAtomic(EVENTS_DATA_PATH, data);
}

function exportScheduleJson(events) {
  // Existing site expects: [{title,date,time}]
  const schedule = (events || []).map((e) => ({
    title: e.title,
    date: e.date,
    time: e.time || ''
  }));
  const schedulePath = path.join(ROOT_DIR, 'schedule.json');
  const backupPath = path.join(ROOT_DIR, 'schedule.json.bak');
  try {
    if (fs.existsSync(schedulePath) && !fs.existsSync(backupPath)) {
      fs.copyFileSync(schedulePath, backupPath);
    }
  } catch {
    // ignore backup failures
  }
  writeJsonAtomic(schedulePath, schedule);
}

app.get('/api/events', requireAuth, (req, res) => {
  res.json(loadEvents());
});

app.post('/api/events', requireAuth, (req, res) => {
  const title = String(req.body.title || '').trim().slice(0, 120);
  const date = String(req.body.date || '').trim();
  const time = normalizeTimeValue(req.body.time);
  if (!title || !date) return res.status(400).json({ error: 'Title and date required' });

  const data = loadEvents();
  const events = Array.isArray(data.events) ? data.events : [];
  const ev = { id: newId(), title, date, time, createdAt: new Date().toISOString() };
  events.push(ev);
  events.sort((a, b) => new Date(`${a.date}T${a.time || '00:00'}`) - new Date(`${b.date}T${b.time || '00:00'}`));
  saveEvents({ events });

  if (ENABLE_EXPORTS) exportScheduleJson(events);

  res.json({ ok: true, event: ev, events });
});

app.put('/api/events/:id', requireAuth, (req, res) => {
  const id = String(req.params.id);
  const title = String(req.body.title || '').trim().slice(0, 120);
  const date = String(req.body.date || '').trim();
  const time = normalizeTimeValue(req.body.time);
  if (!title || !date) return res.status(400).json({ error: 'Title and date required' });

  const data = loadEvents();
  const events = Array.isArray(data.events) ? data.events : [];
  const ev = events.find((e) => e.id === id);
  if (!ev) return res.status(404).json({ error: 'Not found' });

  ev.title = title;
  ev.date = date;
  ev.time = time;
  ev.updatedAt = new Date().toISOString();

  events.sort((a, b) => new Date(`${a.date}T${a.time || '00:00'}`) - new Date(`${b.date}T${b.time || '00:00'}`));
  saveEvents({ events });
  if (ENABLE_EXPORTS) exportScheduleJson(events);

  res.json({ ok: true, event: ev, events });
});

app.delete('/api/events/:id', requireAuth, (req, res) => {
  const id = String(req.params.id);
  const data = loadEvents();
  const events = Array.isArray(data.events) ? data.events : [];
  const next = events.filter((e) => e.id !== id);
  saveEvents({ events: next });
  if (ENABLE_EXPORTS) exportScheduleJson(next);
  res.json({ ok: true });
});

// ----------------- DOCUMENTS -----------------
function loadDocuments() {
  return readJson(DOCUMENTS_DATA_PATH, { documents: [] });
}
function saveDocuments(data) {
  writeJsonAtomic(DOCUMENTS_DATA_PATH, data);
}

// ----------------- BULLETINS -----------------
function loadBulletins() {
  return readJson(BULLETINS_DATA_PATH, { bulletins: [] });
}
function saveBulletins(data) {
  writeJsonAtomic(BULLETINS_DATA_PATH, data);
}

function parseIsoMaybe(value) {
  const v = String(value || '').trim();
  if (!v) return '';
  const t = Date.parse(v);
  if (Number.isNaN(t)) return '';
  return new Date(t).toISOString();
}

function ensureRootBulletinsDir() {
  ensureDir(ROOT_BULLETINS_DIR);
}

function exportBulletins(bulletins) {
  if (!ENABLE_EXPORTS) return;
  ensureRootBulletinsDir();
  writeJsonAtomic(path.join(ROOT_DIR, 'bulletins.json'), { bulletins });
}

function copyBulletinToRoot(fileName) {
  if (!ENABLE_EXPORTS) return;
  ensureRootBulletinsDir();
  const src = path.join(BULLETINS_UPLOADS_DIR, fileName);
  const dst = path.join(ROOT_BULLETINS_DIR, fileName);
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, dst);
  }
}

function deleteBulletinFromRoot(fileName) {
  try {
    const dst = path.join(ROOT_BULLETINS_DIR, fileName);
    if (fs.existsSync(dst)) fs.unlinkSync(dst);
  } catch {
    // ignore
  }
}

const bulletinsUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      ensureDir(BULLETINS_UPLOADS_DIR);
      cb(null, BULLETINS_UPLOADS_DIR);
    },
    filename: (req, file, cb) => {
      const safeBase = sanitizeSegment(path.parse(file.originalname).name).replace(/\s+/g, '-') || 'bulletin';
      const ext = path.extname(file.originalname).toLowerCase() || '.bin';
      cb(null, `${new Date().toISOString().slice(0, 10)}_${safeBase}_${newId()}${ext}`);
    }
  }),
  limits: { fileSize: 25 * 1024 * 1024 }
});

app.get('/api/bulletins', requireAuth, (req, res) => {
  res.json(loadBulletins());
});

app.post('/api/bulletins/upload', requireAuth, bulletinsUpload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const title = String(req.body.title || 'Bulletin').trim().slice(0, 120) || 'Bulletin';
  const startsAt = parseIsoMaybe(req.body.startsAt);
  const endsAt = parseIsoMaybe(req.body.endsAt);
  if (!startsAt || !endsAt) return res.status(400).json({ error: 'Show from and show until are required' });
  if (Date.parse(endsAt) <= Date.parse(startsAt)) return res.status(400).json({ error: 'Show until must be after show from' });

  const createAnnouncement = String(req.body.createAnnouncement || 'false').toLowerCase() === 'true';

  const data = loadBulletins();
  const bulletins = Array.isArray(data.bulletins) ? data.bulletins : [];

  let linkedAnnouncementId = '';
  if (createAnnouncement) {
    const aTitle = String(req.body.announcementTitle || '').trim().slice(0, 120) || `Bulletin: ${title}`;
    const aBody = String(req.body.announcementBody || '').trim().slice(0, 5000) || 'A new bulletin has been posted. Click the bulletin frame on the homepage to view it.';

    const announcementsData = loadAnnouncements();
    const posts = Array.isArray(announcementsData.posts) ? announcementsData.posts : [];

    const post = {
      id: newId(),
      title: aTitle,
      body: aBody,
      createdAt: new Date().toISOString(),
      startsAt,
      expiresAt: endsAt,
      source: 'bulletin'
    };

    posts.unshift(post);
    const saved = pruneAndPersistAnnouncements({ posts }, true);
    linkedAnnouncementId = post.id;
    if (ENABLE_EXPORTS) writeJsonAtomic(path.join(ROOT_DIR, 'announcements.json'), saved);
  }

  // Copy file into the public /bulletins/ folder (for static hosting) and point exported URLs there.
  if (ENABLE_EXPORTS) copyBulletinToRoot(req.file.filename);

  const url = ENABLE_EXPORTS ? `/bulletins/${req.file.filename}` : `/admin-uploads/bulletins/${req.file.filename}`;
  const bulletin = {
    id: newId(),
    title,
    originalName: req.file.originalname,
    fileName: req.file.filename,
    mimeType: req.file.mimetype,
    url,
    startsAt,
    endsAt,
    linkedAnnouncementId,
    createdAt: new Date().toISOString()
  };

  bulletins.unshift(bulletin);
  saveBulletins({ bulletins });
  exportBulletins(bulletins);

  res.json({ ok: true, bulletin });
});

app.delete('/api/bulletins/:id', requireAuth, (req, res) => {
  const id = String(req.params.id);
  const data = loadBulletins();
  const bulletins = Array.isArray(data.bulletins) ? data.bulletins : [];
  const bulletin = bulletins.find((b) => b.id === id);
  const next = bulletins.filter((b) => b.id !== id);
  saveBulletins({ bulletins: next });
  exportBulletins(next);

  // Remove uploaded file(s)
  try {
    if (bulletin?.fileName) {
      const abs = path.join(BULLETINS_UPLOADS_DIR, bulletin.fileName);
      if (fs.existsSync(abs)) fs.unlinkSync(abs);
      if (ENABLE_EXPORTS) deleteBulletinFromRoot(bulletin.fileName);
    }
  } catch {
    // ignore
  }

  // If this bulletin created a coordinated announcement, remove it too.
  try {
    if (bulletin?.linkedAnnouncementId) {
      const aData = loadAnnouncements();
      const posts = Array.isArray(aData.posts) ? aData.posts : [];
      const filtered = posts.filter((p) => p.id !== bulletin.linkedAnnouncementId);
      const saved = pruneAndPersistAnnouncements({ posts: filtered }, true);
      if (ENABLE_EXPORTS) writeJsonAtomic(path.join(ROOT_DIR, 'announcements.json'), saved);
    }
  } catch {
    // ignore
  }

  res.json({ ok: true });
});

const docsUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      ensureDir(DOCS_UPLOADS_DIR);
      cb(null, DOCS_UPLOADS_DIR);
    },
    filename: (req, file, cb) => {
      const safeBase = sanitizeSegment(path.parse(file.originalname).name).replace(/\s+/g, '-') || 'document';
      const ext = path.extname(file.originalname).toLowerCase() || '.bin';
      cb(null, `${new Date().toISOString().slice(0, 10)}_${safeBase}_${newId()}${ext}`);
    }
  }),
  limits: { fileSize: 25 * 1024 * 1024 }
});

app.get('/api/documents', requireAuth, (req, res) => {
  res.json(loadDocuments());
});

app.post('/api/documents/upload', requireAuth, docsUpload.single('file'), (req, res) => {
  const kind = String(req.body.kind || 'document').trim().slice(0, 30);
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const data = loadDocuments();
  const documents = Array.isArray(data.documents) ? data.documents : [];

  const doc = {
    id: newId(),
    kind,
    originalName: req.file.originalname,
    fileName: req.file.filename,
    url: `/admin-uploads/docs/${req.file.filename}`,
    createdAt: new Date().toISOString()
  };

  documents.unshift(doc);
  saveDocuments({ documents });
  if (ENABLE_EXPORTS) writeJsonAtomic(path.join(ROOT_DIR, 'documents.json'), { documents });

  res.json({ ok: true, doc });
});

app.delete('/api/documents/:id', requireAuth, (req, res) => {
  const id = String(req.params.id);
  const data = loadDocuments();
  const documents = Array.isArray(data.documents) ? data.documents : [];
  const doc = documents.find((d) => d.id === id);
  const next = documents.filter((d) => d.id !== id);
  saveDocuments({ documents: next });
  if (ENABLE_EXPORTS) writeJsonAtomic(path.join(ROOT_DIR, 'documents.json'), { documents: next });

  try {
    if (doc?.fileName) {
      const abs = path.join(DOCS_UPLOADS_DIR, doc.fileName);
      if (fs.existsSync(abs)) fs.unlinkSync(abs);
    }
  } catch {
    // ignore
  }

  res.json({ ok: true });
});

// ----------------- LIVESTREAM -----------------
function loadLivestream() {
  return readJson(LIVESTREAM_DATA_PATH, readJson(LIVESTREAM_DATA_PATH, {
    active: { platform: 'website', status: 'offline' },
    embeds: { youtube: '', facebook: '', website: '' },
    recurring: []
  }));
}
function saveLivestream(data) {
  writeJsonAtomic(LIVESTREAM_DATA_PATH, data);
}

app.get('/api/livestream', requireAuth, (req, res) => {
  res.json(loadLivestream());
});

app.put('/api/livestream', requireAuth, (req, res) => {
  const data = loadLivestream();
  const next = {
    ...data,
    active: {
      platform: sanitizeSegment(req.body.active?.platform || data.active.platform).toLowerCase(),
      status: sanitizeSegment(req.body.active?.status || data.active.status).toLowerCase()
    },
    embeds: {
      youtube: String(req.body.embeds?.youtube ?? data.embeds.youtube).trim(),
      facebook: String(req.body.embeds?.facebook ?? data.embeds.facebook).trim(),
      website: String(req.body.embeds?.website ?? data.embeds.website).trim()
    },
    recurring: Array.isArray(req.body.recurring) ? req.body.recurring : data.recurring
  };

  saveLivestream(next);
  if (ENABLE_EXPORTS) writeJsonAtomic(path.join(ROOT_DIR, 'livestream.json'), next);

  res.json({ ok: true, data: next });
});

// ----------------- SETTINGS / THEME EXPORT -----------------
function loadSettings() {
  return readJson(SETTINGS_DATA_PATH, {
    social: {},
    theme: { accent: '#c46123', text: '#ffffff', background: '#000000', logoPath: '' }
  });
}
function saveSettings(data) {
  writeJsonAtomic(SETTINGS_DATA_PATH, data);
}

function buildThemeCss(theme) {
  const accent = theme?.accent || '#c46123';
  const text = theme?.text || '#ffffff';
  const background = theme?.background || '#000000';

  return `:root{\n  --mmmbc-accent:${accent};\n  --mmmbc-text:${text};\n  --mmmbc-bg:${background};\n}\n\n/* Optional theme overrides using variables */\n.top-nav .menu-button span{background-color:var(--mmmbc-accent);} \n.nav-links a:hover{background-color:var(--mmmbc-accent);} \n.home section h2{color:var(--mmmbc-accent);} \n.btn-contact{background-color:var(--mmmbc-accent);}\n`;
}

function sanitizeThemeInput(theme) {
  const t = theme || {};
  const pick = (v, fallback) => (typeof v === 'string' && v.trim() ? v.trim() : fallback);
  return {
    accent: pick(t.accent, '#c46123'),
    text: pick(t.text, '#ffffff'),
    background: pick(t.background, '#000000')
  };
}

// Theme preview is stored per-session for the logged-in admin only.
app.post('/api/theme/preview', requireAuth, (req, res) => {
  req.session.themePreview = sanitizeThemeInput(req.body?.theme);
  res.json({ ok: true });
});

app.post('/api/theme/preview/clear', requireAuth, (req, res) => {
  delete req.session.themePreview;
  res.json({ ok: true });
});

app.get('/api/settings', requireAuth, (req, res) => {
  res.json(loadSettings());
});

app.put('/api/settings', requireAuth, (req, res) => {
  const current = loadSettings();
  const next = {
    social: {
      ...current.social,
      ...(req.body.social || {})
    },
    theme: {
      ...current.theme,
      ...(req.body.theme || {})
    }
  };

  saveSettings(next);

  if (ENABLE_EXPORTS) {
    writeJsonAtomic(path.join(ROOT_DIR, 'site-settings.json'), next.social);
    fs.writeFileSync(path.join(ROOT_DIR, 'theme.css'), buildThemeCss(next.theme), 'utf8');
  }

  res.json({ ok: true, data: next });
});

// ----------------- EXPORT ALL -----------------
app.post('/api/export', requireAuth, (req, res) => {
  if (!ENABLE_EXPORTS) return res.status(400).json({ error: 'Exports disabled' });

  const gallery = loadGallery();
  writeJsonAtomic(path.join(ROOT_DIR, 'gallery.json'), gallery);

  const announcements = loadAnnouncements();
  writeJsonAtomic(path.join(ROOT_DIR, 'announcements.json'), announcements);

  const documents = loadDocuments();
  writeJsonAtomic(path.join(ROOT_DIR, 'documents.json'), documents);

  const bulletins = loadBulletins();
  writeJsonAtomic(path.join(ROOT_DIR, 'bulletins.json'), bulletins);
  // Ensure bulletin files are present in /bulletins
  ensureRootBulletinsDir();
  for (const b of (bulletins.bulletins || [])) {
    if (b?.fileName) {
      try { copyBulletinToRoot(b.fileName); } catch { /* ignore */ }
    }
  }

  const settings = loadSettings();
  writeJsonAtomic(path.join(ROOT_DIR, 'site-settings.json'), settings.social);
  fs.writeFileSync(path.join(ROOT_DIR, 'theme.css'), buildThemeCss(settings.theme), 'utf8');

  const events = loadEvents();
  exportScheduleJson(events.events || []);

  const livestream = loadLivestream();
  writeJsonAtomic(path.join(ROOT_DIR, 'livestream.json'), livestream);

  res.json({ ok: true });
});

// ----------------- BOOT -----------------
(async () => {
  ensureDir(DATA_DIR);
  ensureDir(UPLOADS_DIR);
  ensureDir(DOCS_UPLOADS_DIR);
  ensureDir(BULLETINS_UPLOADS_DIR);
  ensureDir(ROOT_BULLETINS_DIR);
  ensureDir(GALLERY_DIR);

  await ensureMasterAdmin();

  app.listen(PORT, () => {
    console.log(`MMMBC Admin server running on http://localhost:${PORT}`);
    console.log(`Admin dashboard: http://localhost:${PORT}/admin/`);
  });
})();
