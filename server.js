const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'kazuchar_secret_key_2024_secure';

// Use /tmp for SQLite on Render (ephemeral storage)
const dbPath = process.env.RENDER ? '/tmp/kazuchar.db' : 'kazuchar.db';
const db = new sqlite3.Database(dbPath);

const dbRun = (sql, params = []) => new Promise((resolve, reject) => {
    db.run(sql, params, function(err) { if (err) reject(err); else resolve({ lastID: this.lastID, changes: this.changes }); });
});
const dbGet = (sql, params = []) => new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => { if (err) reject(err); else resolve(row); });
});
const dbAll = (sql, params = []) => new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => { if (err) reject(err); else resolve(rows); });
});

// AI Providers
class GeminiProvider {
    constructor(config) { this.config = config; }
    async chat(contents, options = {}) {
        const { apiKey, model } = this.config;
        const modelName = model || 'gemini-2.5-flash';
        const safetySettings = options.nsfw ? [
            { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_NONE" },
            { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_NONE" },
            { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold: "BLOCK_NONE" },
            { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_NONE" }
        ] : [
            { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_ONLY_HIGH" },
            { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_ONLY_HIGH" },
            { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold: "BLOCK_ONLY_HIGH" },
            { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_ONLY_HIGH" }
        ];
        
        const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`;
        
        const response = await fetch(apiUrl, {
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                contents, 
                generationConfig: { temperature: 0.9, topK: 40, topP: 0.95, maxOutputTokens: 2048 }, 
                safetySettings 
            })
        });
        
        if (!response.ok) {
            const errorData = await response.text();
            console.error('Gemini API error:', errorData);
            throw new Error('Gemini API error: ' + response.status);
        }
        const data = await response.json();
        return data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    }
}

class OpenAIProvider {
    constructor(config) { this.config = config; }
    async chat(contents) {
        const messages = contents.map(c => ({ role: c.role === 'model' ? 'assistant' : c.role, content: c.parts.map(p => p.text || '').join('') }));
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${this.config.apiKey}` },
            body: JSON.stringify({ model: this.config.model || 'gpt-4o-mini', messages, temperature: 0.9, max_tokens: 2048 })
        });
        if (!response.ok) throw new Error('OpenAI API error');
        return (await response.json()).choices[0].message.content;
    }
}

class DeepSeekProvider {
    constructor(config) { this.config = config; }
    async chat(contents) {
        const messages = contents.map(c => ({ role: c.role === 'model' ? 'assistant' : c.role, content: c.parts.map(p => p.text || '').join('') }));
        const response = await fetch('https://api.deepseek.com/v1/chat/completions', {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${this.config.apiKey}` },
            body: JSON.stringify({ model: this.config.model || 'deepseek-chat', messages, temperature: 0.9, max_tokens: 2048 })
        });
        if (!response.ok) throw new Error('DeepSeek API error');
        return (await response.json()).choices[0].message.content;
    }
}

class GroqProvider {
    constructor(config) { this.config = config; }
    async chat(contents) {
        const messages = contents.map(c => ({ role: c.role === 'model' ? 'assistant' : c.role, content: c.parts.map(p => p.text || '').join('') }));
        const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST', 
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${this.config.apiKey}` },
            body: JSON.stringify({ model: this.config.model || 'llama-3.3-70b-versatile', messages, temperature: 0.9, max_tokens: 2048 })
        });
        if (!response.ok) {
            const errorData = await response.text();
            console.error('Groq API error:', errorData);
            throw new Error('Groq API error: ' + response.status);
        }
        return (await response.json()).choices[0].message.content;
    }
}

class ClaudeProvider {
    constructor(config) { this.config = config; }
    async chat(contents) {
        let systemPrompt = '', messages = [];
        contents.forEach((c, i) => {
            const text = c.parts.map(p => p.text || '').join('');
            if (i === 0 && c.role === 'user') systemPrompt = text;
            else messages.push({ role: c.role === 'model' ? 'assistant' : 'user', content: text });
        });
        const response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': this.config.apiKey, 'anthropic-version': '2023-06-01' },
            body: JSON.stringify({ model: this.config.model || 'claude-3-haiku-20240307', max_tokens: 2048, system: systemPrompt, messages })
        });
        if (!response.ok) throw new Error('Claude API error');
        return (await response.json()).content[0].text;
    }
}

function createProvider(name, config) {
    const providers = { gemini: GeminiProvider, openai: OpenAIProvider, chatgpt: OpenAIProvider, deepseek: DeepSeekProvider, groq: GroqProvider, claude: ClaudeProvider, anthropic: ClaudeProvider };
    return new (providers[name.toLowerCase()] || GeminiProvider)(config);
}

async function getProvider(characterId) {
    const character = await dbGet('SELECT ai_provider FROM characters WHERE id = ?', [characterId]);
    const providerName = character?.ai_provider || 'gemini';
    let apiConfig = await dbGet('SELECT * FROM api_providers WHERE name = ? AND is_active = 1', [providerName]);
    if (!apiConfig) apiConfig = await dbGet('SELECT * FROM api_providers WHERE name = ? AND is_active = 1', ['gemini']);
    if (!apiConfig) apiConfig = await dbGet('SELECT * FROM api_providers WHERE is_active = 1 LIMIT 1');
    if (!apiConfig || !apiConfig.api_key) throw new Error('Tidak ada API provider yang aktif. Silakan konfigurasi API key di menu Admin > API Providers.');
    return createProvider(apiConfig.name, { apiKey: apiConfig.api_key, model: apiConfig.default_model });
}

// Database setup
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, username TEXT UNIQUE,
        password TEXT NOT NULL, name TEXT NOT NULL, profile_photo TEXT, role TEXT DEFAULT 'user',
        status TEXT DEFAULT 'pending', tokens INTEGER DEFAULT 0, age_verified INTEGER DEFAULT 0,
        nsfw_allowed INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS password_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, new_password TEXT,
        request_type TEXT DEFAULT 'change', status TEXT DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS chat_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, character_id INTEGER,
        role TEXT NOT NULL, message TEXT NOT NULL, image_path TEXT,
        visible_to_user INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS characters (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, gender TEXT NOT NULL,
        role_title TEXT, description TEXT, personality TEXT NOT NULL, profile_photo TEXT,
        access_type TEXT DEFAULT 'all', allowed_users TEXT DEFAULT '', nsfw_enabled INTEGER DEFAULT 0,
        ai_provider TEXT DEFAULT 'gemini', category TEXT DEFAULT '', tags TEXT DEFAULT '',
        created_by INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS api_providers (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
        api_key TEXT, default_model TEXT, available_models TEXT, is_active INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS character_categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
        icon TEXT DEFAULT '📁', sort_order INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS character_tags (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
        color TEXT DEFAULT '#6c5ce7', created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS live_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT, from_user_id INTEGER NOT NULL, to_user_id INTEGER NOT NULL,
        message TEXT NOT NULL, is_read INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS app_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL, value TEXT
    )`);

    // Migrations
    ['tokens INTEGER DEFAULT 0', 'age_verified INTEGER DEFAULT 0', 'nsfw_allowed INTEGER DEFAULT 0', 'username TEXT', 'image_path TEXT'].forEach(col => {
        const table = col.includes('image_path') ? 'chat_history' : 'users';
        db.run('ALTER TABLE ' + table + ' ADD COLUMN ' + col, () => {});
    });

    // Default admin
    db.get('SELECT * FROM users WHERE role = ?', ['admin'], (err, row) => {
        if (!row) {
            db.run('INSERT INTO users (email, username, password, name, role, status, tokens, age_verified, nsfw_allowed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                ['admin@kazuchar.ai', 'admin', bcrypt.hashSync('admin123', 10), 'Administrator', 'admin', 'approved', 999999, 1, 1]);
            console.log('Default admin: admin@kazuchar.ai / admin123');
        }
    });

    // Default settings
    db.get('SELECT * FROM app_settings WHERE key = ?', ['nsfw_registration'], (err, row) => {
        if (!row) db.run('INSERT INTO app_settings (key, value) VALUES (?, ?)', ['nsfw_registration', 'true']);
    });
    db.get('SELECT * FROM app_settings WHERE key = ?', ['default_tokens'], (err, row) => {
        if (!row) db.run('INSERT INTO app_settings (key, value) VALUES (?, ?)', ['default_tokens', '100']);
    });

    // Default categories & tags
    [{ name: 'romantic', display_name: 'Romantis', icon: '💕', sort_order: 1 },
     { name: 'friendship', display_name: 'Pertemanan', icon: '🤝', sort_order: 2 },
     { name: 'adventure', display_name: 'Petualangan', icon: '⚔️', sort_order: 3 },
     { name: 'fantasy', display_name: 'Fantasi', icon: '🧙', sort_order: 4 }
    ].forEach(cat => {
        db.get('SELECT * FROM character_categories WHERE name = ?', [cat.name], (err, row) => {
            if (!row) db.run('INSERT INTO character_categories (name, display_name, icon, sort_order) VALUES (?, ?, ?, ?)', [cat.name, cat.display_name, cat.icon, cat.sort_order]);
        });
    });

    [{ name: 'caring', display_name: 'Perhatian', color: '#00cec9' },
     { name: 'playful', display_name: 'Playful', color: '#fdcb6e' },
     { name: 'mysterious', display_name: 'Misterius', color: '#6c5ce7' },
     { name: 'cheerful', display_name: 'Ceria', color: '#ff7675' },
     { name: 'protective', display_name: 'Protektif', color: '#e17055' },
     { name: 'tsundere', display_name: 'Tsundere', color: '#fd79a8' }
    ].forEach(tag => {
        db.get('SELECT * FROM character_tags WHERE name = ?', [tag.name], (err, row) => {
            if (!row) db.run('INSERT INTO character_tags (name, display_name, color) VALUES (?, ?, ?)', [tag.name, tag.display_name, tag.color]);
        });
    });

    // Default character - Alfajri
    db.get('SELECT * FROM characters WHERE name = ?', ['Alfajri'], (err, row) => {
        if (!row) {
            db.run(`INSERT INTO characters (name, gender, role_title, description, personality, access_type, nsfw_enabled, ai_provider, category, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                ['Alfajri', 'Pria', 'Pacar Virtual', 'Pacar virtual yang romantis dan perhatian',
                'Alfajri adalah pacar virtual yang sangat romantis.\n\nSIFAT:\n- Romantis dan suka menggombal\n- Perhatian, selalu tanya kabar\n- Sedikit posesif dan cemburu\n- Protektif dan manja\n\nCARA BICARA:\n- Selalu pakai panggilan sayang\n- Sering tanya "udah makan?", "lagi apa?"',
                'all', 0, 'gemini', 'romantic', 'caring,protective']);
        }
    });

    // Default providers
    [{ name: 'gemini', display_name: 'Google Gemini', default_model: 'gemini-2.5-flash', available_models: 'gemini-2.5-flash,gemini-2.0-flash,gemini-1.5-pro,gemini-1.5-flash' },
     { name: 'openai', display_name: 'OpenAI ChatGPT', default_model: 'gpt-4o-mini', available_models: 'gpt-4o,gpt-4o-mini,gpt-3.5-turbo' },
     { name: 'deepseek', display_name: 'DeepSeek', default_model: 'deepseek-chat', available_models: 'deepseek-chat,deepseek-coder' },
     { name: 'groq', display_name: 'Groq (Fast & Free)', default_model: 'llama-3.3-70b-versatile', available_models: 'llama-3.3-70b-versatile,llama-3.1-8b-instant,mixtral-8x7b-32768,gemma2-9b-it' },
     { name: 'claude', display_name: 'Anthropic Claude', default_model: 'claude-3-haiku-20240307', available_models: 'claude-3-opus-20240229,claude-3-sonnet-20240229,claude-3-haiku-20240307' }
    ].forEach(p => {
        db.get('SELECT * FROM api_providers WHERE name = ?', [p.name], (err, row) => {
            if (!row) db.run('INSERT INTO api_providers (name, display_name, default_model, available_models, is_active) VALUES (?, ?, ?, ?, ?)', [p.name, p.display_name, p.default_model, p.available_models, 0]);
        });
    });
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// Upload directory - use /tmp on Render
const uploadBase = process.env.RENDER ? '/tmp/uploads' : 'uploads';
app.use('/uploads', express.static(uploadBase));

['profiles', 'characters', 'chat'].forEach(dir => {
    const fullPath = `${uploadBase}/${dir}`;
    if (!fs.existsSync(fullPath)) fs.mkdirSync(fullPath, { recursive: true });
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, `${uploadBase}/${req.query.type || 'profiles'}`),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });
const chatUpload = multer({ storage: multer.diskStorage({ destination: `${uploadBase}/chat`, filename: (req, file, cb) => cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname)) }), limits: { fileSize: 20 * 1024 * 1024 } });

const authMiddleware = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token tidak ditemukan' });
    try { req.user = jwt.verify(token, JWT_SECRET); next(); } catch (e) { return res.status(401).json({ error: 'Token tidak valid' }); }
};
const adminMiddleware = (req, res, next) => { if (req.user.role !== 'admin') return res.status(403).json({ error: 'Akses ditolak' }); next(); };

// Token optimization settings
const MAX_HISTORY_MESSAGES = 6; // Only keep last 6 messages (3 exchanges)
const MAX_MESSAGE_LENGTH = 400; // Truncate long messages

function truncateText(text, maxLength = MAX_MESSAGE_LENGTH) {
    if (!text || text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

function buildCharacterSystemPrompt(character, lang = 'id') {
    // Shortened prompt to save tokens
    const personality = truncateText(character.personality, 300);
    
    if (lang === 'en') {
        return `You are "${character.name}" (${character.gender === 'Pria' ? 'M' : 'F'}). ${character.role_title || ''}
${personality}
${character.nsfw_enabled ? '[Adult OK]' : ''}
Rules: Stay in character, use emojis 😊💕, be expressive. Never say you're AI.`;
    }
    
    return `Kamu "${character.name}" (${character.gender === 'Pria' ? 'L' : 'P'}). ${character.role_title || ''}
${personality}
${character.nsfw_enabled ? '[Dewasa OK]' : ''}
Aturan: Tetap in-character, pakai emoji 😊💕, ekspresif. Jangan bilang kamu AI.`;
}

function hasAccessToCharacter(char, userId) {
    if (char.access_type === 'all') return true;
    const allowed = char.allowed_users ? char.allowed_users.split(',').map(id => parseInt(id.trim())) : [];
    return allowed.includes(userId);
}

// AUTH ROUTES
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, username, password, name, age_verified } = req.body;
        if (!email || !password || !name) return res.status(400).json({ error: 'Semua field harus diisi' });
        if (await dbGet('SELECT * FROM users WHERE email = ?', [email])) return res.status(400).json({ error: 'Email sudah terdaftar' });
        if (username && await dbGet('SELECT * FROM users WHERE username = ?', [username])) return res.status(400).json({ error: 'Username sudah dipakai' });
        
        const defaultTokens = (await dbGet('SELECT value FROM app_settings WHERE key = ?', ['default_tokens']))?.value || '100';
        await dbRun('INSERT INTO users (email, username, password, name, tokens, age_verified) VALUES (?, ?, ?, ?, ?, ?)', 
            [email, username || null, bcrypt.hashSync(password, 10), name, parseInt(defaultTokens), age_verified ? 1 : 0]);
        res.json({ success: true, message: 'Registrasi berhasil! Menunggu persetujuan admin.' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Terjadi kesalahan server' }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { login, password } = req.body; // login bisa email atau username
        const user = await dbGet('SELECT * FROM users WHERE email = ? OR username = ?', [login, login]);
        if (!user || !bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: 'Email/Username atau password salah' });
        if (user.status === 'pending') return res.status(400).json({ error: 'Akun belum disetujui admin' });
        if (user.status === 'rejected') return res.status(400).json({ error: 'Akun ditolak admin' });
        
        const token = jwt.sign({ id: user.id, email: user.email, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, token, user: { id: user.id, email: user.email, username: user.username, name: user.name, role: user.role, profile_photo: user.profile_photo, tokens: user.tokens, nsfw_allowed: user.nsfw_allowed, age_verified: user.age_verified } });
    } catch (e) { res.status(500).json({ error: 'Terjadi kesalahan server' }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { login } = req.body;
        const user = await dbGet('SELECT * FROM users WHERE email = ? OR username = ?', [login, login]);
        if (!user) return res.status(400).json({ error: 'User tidak ditemukan' });
        
        // Check if already requested
        const existing = await dbGet('SELECT * FROM password_requests WHERE user_id = ? AND status = ? AND request_type = ?', [user.id, 'pending', 'forgot']);
        if (existing) return res.status(400).json({ error: 'Permintaan reset password sudah dikirim' });
        
        await dbRun('INSERT INTO password_requests (user_id, request_type) VALUES (?, ?)', [user.id, 'forgot']);
        res.json({ success: true, message: 'Permintaan reset password telah dikirim ke admin.' });
    } catch (e) { res.status(500).json({ error: 'Terjadi kesalahan server' }); }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
    const user = await dbGet('SELECT id, email, username, name, role, profile_photo, status, tokens, age_verified, nsfw_allowed FROM users WHERE id = ?', [req.user.id]);
    res.json({ user });
});

app.post('/api/auth/update-profile', authMiddleware, upload.single('photo'), async (req, res) => {
    try {
        const { name } = req.body;
        const userId = req.user.id;
        
        if (req.file) {
            const photoPath = '/uploads/profiles/' + req.file.filename;
            await dbRun('UPDATE users SET profile_photo = ? WHERE id = ?', [photoPath, userId]);
        }
        if (name) {
            await dbRun('UPDATE users SET name = ? WHERE id = ?', [name, userId]);
        }
        
        const user = await dbGet('SELECT id, email, username, name, role, profile_photo, tokens, nsfw_allowed FROM users WHERE id = ?', [userId]);
        res.json({ success: true, user });
    } catch (e) { res.status(500).json({ error: 'Gagal update profile' }); }
});

app.post('/api/auth/request-password-change', authMiddleware, async (req, res) => {
    try {
        const { new_password } = req.body;
        const existing = await dbGet('SELECT * FROM password_requests WHERE user_id = ? AND status = ?', [req.user.id, 'pending']);
        if (existing) return res.status(400).json({ error: 'Sudah ada permintaan pending' });
        
        await dbRun('INSERT INTO password_requests (user_id, new_password, request_type) VALUES (?, ?, ?)', 
            [req.user.id, bcrypt.hashSync(new_password, 10), 'change']);
        res.json({ success: true, message: 'Permintaan ganti password telah dikirim' });
    } catch (e) { res.status(500).json({ error: 'Terjadi kesalahan' }); }
});

// ADMIN ROUTES
app.get('/api/admin/pending-users', authMiddleware, adminMiddleware, async (req, res) => {
    res.json({ users: await dbAll('SELECT id, email, username, name, age_verified, created_at FROM users WHERE status = ?', ['pending']) });
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    res.json({ users: await dbAll('SELECT id, email, username, name, role, status, profile_photo, tokens, age_verified, nsfw_allowed, created_at FROM users WHERE role != ?', ['admin']) });
});

app.post('/api/admin/create-user', authMiddleware, adminMiddleware, async (req, res) => {
    const { email, username, password, name, tokens } = req.body;
    if (!email || !password || !name) return res.status(400).json({ error: 'Semua field harus diisi' });
    if (await dbGet('SELECT * FROM users WHERE email = ?', [email])) return res.status(400).json({ error: 'Email sudah terdaftar' });
    if (username && await dbGet('SELECT * FROM users WHERE username = ?', [username])) return res.status(400).json({ error: 'Username sudah dipakai' });
    const result = await dbRun('INSERT INTO users (email, username, password, name, status, tokens) VALUES (?, ?, ?, ?, ?, ?)', [email, username || null, bcrypt.hashSync(password, 10), name, 'approved', tokens || 100]);
    res.json({ success: true, user: { id: result.lastID } });
});

app.post('/api/admin/user-status', authMiddleware, adminMiddleware, async (req, res) => {
    const { userId, status } = req.body;
    await dbRun('UPDATE users SET status = ? WHERE id = ?', [status, userId]);
    res.json({ success: true });
});

app.post('/api/admin/user-tokens', authMiddleware, adminMiddleware, async (req, res) => {
    const { userId, tokens, action } = req.body;
    if (action === 'set') await dbRun('UPDATE users SET tokens = ? WHERE id = ?', [tokens, userId]);
    else if (action === 'add') await dbRun('UPDATE users SET tokens = tokens + ? WHERE id = ?', [tokens, userId]);
    res.json({ success: true });
});

app.post('/api/admin/user-nsfw', authMiddleware, adminMiddleware, async (req, res) => {
    const { userId, nsfw_allowed } = req.body;
    await dbRun('UPDATE users SET nsfw_allowed = ? WHERE id = ?', [nsfw_allowed ? 1 : 0, userId]);
    res.json({ success: true });
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
    await dbRun('DELETE FROM chat_history WHERE user_id = ?', [req.params.id]);
    await dbRun('DELETE FROM live_messages WHERE from_user_id = ? OR to_user_id = ?', [req.params.id, req.params.id]);
    await dbRun('DELETE FROM password_requests WHERE user_id = ?', [req.params.id]);
    await dbRun('DELETE FROM users WHERE id = ? AND role != ?', [req.params.id, 'admin']);
    res.json({ success: true });
});

app.get('/api/admin/password-requests', authMiddleware, adminMiddleware, async (req, res) => {
    res.json({ requests: await dbAll(`SELECT pr.*, u.email, u.username, u.name FROM password_requests pr JOIN users u ON pr.user_id = u.id WHERE pr.status = 'pending' ORDER BY pr.created_at DESC`) });
});

app.post('/api/admin/password-request-status', authMiddleware, adminMiddleware, async (req, res) => {
    const { requestId, status, newPassword } = req.body;
    const request = await dbGet('SELECT * FROM password_requests WHERE id = ?', [requestId]);
    if (status === 'approved') {
        if (request.request_type === 'forgot' && newPassword) {
            await dbRun('UPDATE users SET password = ? WHERE id = ?', [bcrypt.hashSync(newPassword, 10), request.user_id]);
        } else if (request.new_password) {
            await dbRun('UPDATE users SET password = ? WHERE id = ?', [request.new_password, request.user_id]);
        }
    }
    await dbRun('UPDATE password_requests SET status = ? WHERE id = ?', [status, requestId]);
    res.json({ success: true });
});

app.get('/api/admin/chat-users', authMiddleware, adminMiddleware, async (req, res) => {
    res.json({ users: await dbAll(`SELECT DISTINCT u.id, u.name, u.email, (SELECT COUNT(*) FROM chat_history WHERE user_id = u.id) as message_count, (SELECT MAX(created_at) FROM chat_history WHERE user_id = u.id) as last_chat FROM users u INNER JOIN chat_history ch ON u.id = ch.user_id ORDER BY last_chat DESC`) });
});

app.get('/api/admin/chat-history', authMiddleware, adminMiddleware, async (req, res) => {
    const { userId } = req.query;
    const query = `SELECT ch.*, u.name as user_name, c.name as character_name FROM chat_history ch LEFT JOIN users u ON ch.user_id = u.id LEFT JOIN characters c ON ch.character_id = c.id` + (userId ? ' WHERE ch.user_id = ?' : '') + ' ORDER BY ch.created_at DESC LIMIT 200';
    res.json({ history: await dbAll(query, userId ? [userId] : []) });
});

app.delete('/api/admin/chat-history/:userId', authMiddleware, adminMiddleware, async (req, res) => {
    await dbRun('DELETE FROM chat_history WHERE user_id = ?', [req.params.userId]);
    res.json({ success: true });
});

// Settings
app.get('/api/admin/settings', authMiddleware, adminMiddleware, async (req, res) => {
    const settings = await dbAll('SELECT * FROM app_settings');
    res.json({ settings: settings.reduce((acc, s) => { acc[s.key] = s.value; return acc; }, {}) });
});

app.post('/api/admin/settings', authMiddleware, adminMiddleware, async (req, res) => {
    const { key, value } = req.body;
    await dbRun('INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)', [key, value]);
    res.json({ success: true });
});

app.get('/api/settings/public', async (req, res) => {
    const nsfw = await dbGet('SELECT value FROM app_settings WHERE key = ?', ['nsfw_registration']);
    res.json({ nsfw_registration: nsfw?.value === 'true' });
});

// API Providers
app.get('/api/admin/providers', authMiddleware, adminMiddleware, async (req, res) => {
    res.json({ providers: await dbAll('SELECT * FROM api_providers ORDER BY name') });
});

app.put('/api/admin/providers/:id', authMiddleware, adminMiddleware, async (req, res) => {
    const { api_key, default_model, is_active } = req.body;
    await dbRun('UPDATE api_providers SET api_key = ?, default_model = ?, is_active = ? WHERE id = ?', [api_key, default_model, is_active ? 1 : 0, req.params.id]);
    res.json({ success: true });
});

// Categories & Tags
app.get('/api/categories', authMiddleware, async (req, res) => {
    res.json({ categories: await dbAll('SELECT * FROM character_categories ORDER BY sort_order') });
});

app.post('/api/admin/categories', authMiddleware, adminMiddleware, async (req, res) => {
    const { name, display_name, icon } = req.body;
    await dbRun('INSERT INTO character_categories (name, display_name, icon) VALUES (?, ?, ?)', [name, display_name, icon || '📁']);
    res.json({ success: true });
});

app.delete('/api/admin/categories/:id', authMiddleware, adminMiddleware, async (req, res) => {
    await dbRun('DELETE FROM character_categories WHERE id = ?', [req.params.id]);
    res.json({ success: true });
});

app.get('/api/tags', authMiddleware, async (req, res) => {
    res.json({ tags: await dbAll('SELECT * FROM character_tags ORDER BY name') });
});

app.post('/api/admin/tags', authMiddleware, adminMiddleware, async (req, res) => {
    const { name, display_name, color } = req.body;
    await dbRun('INSERT INTO character_tags (name, display_name, color) VALUES (?, ?, ?)', [name, display_name, color || '#6c5ce7']);
    res.json({ success: true });
});

app.delete('/api/admin/tags/:id', authMiddleware, adminMiddleware, async (req, res) => {
    await dbRun('DELETE FROM character_tags WHERE id = ?', [req.params.id]);
    res.json({ success: true });
});

// Characters with pagination
app.get('/api/characters', authMiddleware, async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    
    const user = await dbGet('SELECT nsfw_allowed FROM users WHERE id = ?', [req.user.id]);
    let allChars = await dbAll('SELECT * FROM characters ORDER BY created_at DESC');
    
    allChars = allChars.filter(c => {
        if (req.user.role !== 'admin' && !hasAccessToCharacter(c, req.user.id)) return false;
        if (c.nsfw_enabled && !user.nsfw_allowed && req.user.role !== 'admin') return false;
        return true;
    });
    
    const total = allChars.length;
    const totalPages = Math.ceil(total / limit);
    const chars = allChars.slice(offset, offset + limit);
    
    res.json({ characters: chars, pagination: { page, limit, total, totalPages } });
});

app.get('/api/characters/:id', authMiddleware, async (req, res) => {
    const char = await dbGet('SELECT * FROM characters WHERE id = ?', [req.params.id]);
    if (!char) return res.status(404).json({ error: 'Karakter tidak ditemukan' });
    res.json({ character: char });
});

app.get('/api/user/character-history', authMiddleware, async (req, res) => {
    res.json({ history: await dbAll(`SELECT c.*, (SELECT MAX(created_at) FROM chat_history WHERE user_id = ? AND character_id = c.id) as last_accessed, (SELECT COUNT(*) FROM chat_history WHERE user_id = ? AND character_id = c.id AND role = 'user') as message_count FROM characters c INNER JOIN chat_history ch ON c.id = ch.character_id WHERE ch.user_id = ? GROUP BY c.id ORDER BY last_accessed DESC`, [req.user.id, req.user.id, req.user.id]) });
});

app.post('/api/admin/characters', authMiddleware, adminMiddleware, upload.single('photo'), async (req, res) => {
    const { name, gender, role_title, description, personality, access_type, allowed_users, nsfw_enabled, ai_provider, category, tags } = req.body;
    if (!name || !gender || !personality) return res.status(400).json({ error: 'Field wajib harus diisi' });
    const photoPath = req.file ? '/uploads/characters/' + req.file.filename : null;
    const result = await dbRun(`INSERT INTO characters (name, gender, role_title, description, personality, profile_photo, access_type, allowed_users, nsfw_enabled, ai_provider, category, tags, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [name, gender, role_title || '', description || '', personality, photoPath, access_type || 'all', allowed_users || '', nsfw_enabled === 'true' ? 1 : 0, ai_provider || 'gemini', category || '', tags || '', req.user.id]);
    res.json({ success: true, character: { id: result.lastID } });
});

app.put('/api/admin/characters/:id', authMiddleware, adminMiddleware, upload.single('photo'), async (req, res) => {
    const char = await dbGet('SELECT * FROM characters WHERE id = ?', [req.params.id]);
    if (!char) return res.status(404).json({ error: 'Karakter tidak ditemukan' });
    const { name, gender, role_title, description, personality, access_type, allowed_users, nsfw_enabled, ai_provider, category, tags } = req.body;
    const photoPath = req.file ? '/uploads/characters/' + req.file.filename : char.profile_photo;
    await dbRun(`UPDATE characters SET name=?, gender=?, role_title=?, description=?, personality=?, profile_photo=?, access_type=?, allowed_users=?, nsfw_enabled=?, ai_provider=?, category=?, tags=? WHERE id=?`,
        [name || char.name, gender || char.gender, role_title ?? char.role_title, description ?? char.description, personality || char.personality, photoPath, access_type || char.access_type, allowed_users ?? char.allowed_users, nsfw_enabled === 'true' ? 1 : 0, ai_provider || char.ai_provider, category ?? char.category, tags ?? char.tags, req.params.id]);
    res.json({ success: true });
});

app.delete('/api/admin/characters/:id', authMiddleware, adminMiddleware, async (req, res) => {
    await dbRun('DELETE FROM chat_history WHERE character_id = ?', [req.params.id]);
    await dbRun('DELETE FROM characters WHERE id = ?', [req.params.id]);
    res.json({ success: true });
});

// Chat
app.post('/api/chat', authMiddleware, chatUpload.single('file'), async (req, res) => {
    try {
        const { message, characterId, lang } = req.body;
        const userId = req.user.id;
        const file = req.file;
        const language = lang || 'id';
        
        const userRow = await dbGet('SELECT tokens FROM users WHERE id = ?', [userId]);
        if (userRow.tokens <= 0) return res.status(400).json({ error: language === 'en' ? 'No tokens left! Contact admin to get tokens.' : 'Token habis! Hubungi admin untuk mendapatkan token.' });

        const char = await dbGet('SELECT * FROM characters WHERE id = ?', [characterId]);
        if (!char) return res.status(400).json({ error: language === 'en' ? 'Character not found' : 'Karakter tidak ditemukan' });

        let userParts = [];
        let userMessage = truncateText(message || '', MAX_MESSAGE_LENGTH);
        let imagePath = null;
        
        if (file) {
            imagePath = '/uploads/chat/' + file.filename;
            if (file.mimetype.startsWith('image/')) {
                const fileBuffer = fs.readFileSync(file.path);
                userParts.push({
                    inline_data: { mime_type: file.mimetype, data: fileBuffer.toString('base64') }
                });
                if (!message) userMessage = language === 'en' ? "Look at this image" : "Lihat gambar ini";
            }
        }

        userParts.unshift({ text: userMessage });

        await dbRun('UPDATE users SET tokens = tokens - 1 WHERE id = ?', [userId]);
        await dbRun('INSERT INTO chat_history (user_id, character_id, role, message, image_path) VALUES (?, ?, ?, ?, ?)', [userId, char.id, 'user', userMessage, imagePath]);

        // Only get last few messages to save tokens
        const history = await dbAll(`SELECT role, message FROM chat_history WHERE user_id = ? AND character_id = ? AND visible_to_user = 1 ORDER BY created_at DESC LIMIT ?`, [userId, char.id, MAX_HISTORY_MESSAGES]);
        history.reverse();

        // Build minimal context
        const contents = [
            { role: 'user', parts: [{ text: buildCharacterSystemPrompt(char, language) }] },
            { role: 'model', parts: [{ text: 'OK! 😊' }] }
        ];
        
        // Add truncated history (exclude current message)
        history.slice(0, -1).forEach(m => {
            contents.push({ 
                role: m.role === 'user' ? 'user' : 'model', 
                parts: [{ text: truncateText(m.message, MAX_MESSAGE_LENGTH) }] 
            });
        });
        contents.push({ role: 'user', parts: userParts });

        const provider = await getProvider(char.id);
        const botResponse = await provider.chat(contents, { nsfw: char.nsfw_enabled === 1 });

        await dbRun('INSERT INTO chat_history (user_id, character_id, role, message) VALUES (?, ?, ?, ?)', [userId, char.id, 'model', botResponse]);
        
        const updatedUser = await dbGet('SELECT tokens FROM users WHERE id = ?', [userId]);
        res.json({ success: true, response: botResponse, tokens: updatedUser.tokens, imagePath });
    } catch (e) {
        console.error('Chat error:', e);
        res.status(500).json({ error: e.message || 'Terjadi kesalahan' });
    }
});

app.get('/api/chat/history/:characterId', authMiddleware, async (req, res) => {
    res.json({ history: await dbAll(`SELECT role, message, image_path, created_at FROM chat_history WHERE user_id = ? AND character_id = ? AND visible_to_user = 1 ORDER BY created_at ASC LIMIT 50`, [req.user.id, req.params.characterId]) });
});

// Clear chat only (hide from user, AI still remembers)
app.post('/api/chat/clear', authMiddleware, async (req, res) => {
    await dbRun('UPDATE chat_history SET visible_to_user = 0 WHERE user_id = ? AND character_id = ?', [req.user.id, req.body.characterId]);
    res.json({ success: true });
});

// Reset chat (delete all, AI forgets)
app.post('/api/chat/reset', authMiddleware, async (req, res) => {
    await dbRun('DELETE FROM chat_history WHERE user_id = ? AND character_id = ?', [req.user.id, req.body.characterId]);
    res.json({ success: true });
});

// Live Chat
app.get('/api/live-chat/conversations', authMiddleware, async (req, res) => {
    if (req.user.role === 'admin') {
        const users = await dbAll(`SELECT DISTINCT u.id, u.name, u.email, u.profile_photo,
            (SELECT message FROM live_messages WHERE (from_user_id = u.id OR to_user_id = u.id) ORDER BY created_at DESC LIMIT 1) as last_message,
            (SELECT created_at FROM live_messages WHERE (from_user_id = u.id OR to_user_id = u.id) ORDER BY created_at DESC LIMIT 1) as last_time,
            (SELECT COUNT(*) FROM live_messages WHERE from_user_id = u.id AND to_user_id = ? AND is_read = 0) as unread
            FROM users u WHERE u.role != 'admin' AND EXISTS (SELECT 1 FROM live_messages WHERE from_user_id = u.id OR to_user_id = u.id) ORDER BY last_time DESC`, [req.user.id]);
        res.json({ conversations: users });
    } else {
        const admin = await dbGet('SELECT id, name, profile_photo FROM users WHERE role = ?', ['admin']);
        const unread = await dbGet('SELECT COUNT(*) as count FROM live_messages WHERE from_user_id = ? AND to_user_id = ? AND is_read = 0', [admin.id, req.user.id]);
        res.json({ admin, unread: unread.count });
    }
});

app.get('/api/live-chat/messages/:partnerId', authMiddleware, async (req, res) => {
    const partnerId = req.params.partnerId;
    const messages = await dbAll(`SELECT * FROM live_messages WHERE (from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?) ORDER BY created_at ASC LIMIT 100`, [req.user.id, partnerId, partnerId, req.user.id]);
    await dbRun('UPDATE live_messages SET is_read = 1 WHERE from_user_id = ? AND to_user_id = ?', [partnerId, req.user.id]);
    res.json({ messages });
});

app.post('/api/live-chat/send', authMiddleware, async (req, res) => {
    const { to_user_id, message } = req.body;
    await dbRun('INSERT INTO live_messages (from_user_id, to_user_id, message) VALUES (?, ?, ?)', [req.user.id, to_user_id, message]);
    res.json({ success: true });
});

app.get('/api/live-chat/unread', authMiddleware, async (req, res) => {
    const count = await dbGet('SELECT COUNT(*) as count FROM live_messages WHERE to_user_id = ? AND is_read = 0', [req.user.id]);
    res.json({ unread: count.count });
});

// Delete live chat for a user (admin only)
app.delete('/api/admin/live-chat/:userId', authMiddleware, adminMiddleware, async (req, res) => {
    await dbRun('DELETE FROM live_messages WHERE from_user_id = ? OR to_user_id = ?', [req.params.userId, req.params.userId]);
    res.json({ success: true });
});

app.get('/api/health', (req, res) => res.json({ status: 'OK', env: process.env.RENDER ? 'render' : 'local' }));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`KazuChar.AI running on port ${PORT}`);
    console.log('Admin: admin@kazuchar.ai / admin123');
    if (process.env.RENDER) console.log('Running on Render.com');
});
