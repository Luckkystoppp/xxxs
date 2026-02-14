#!/bin/bash

echo "╔════════════════════════════════════════════════════╗"
echo "║   SERVER KEY - ULTRA DARK EDITION V2.1            ║"
echo "║   Complete Package Builder                        ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# Create directories
mkdir -p web data uploads

# Package.json
cat > package.json << 'PKGEOF'
{
  "name": "server-key-ultra-dark-v2",
  "version": "2.1.0",
  "description": "Server Key Ultra Dark Edition - Complete System",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "axios": "^1.6.0",
    "body-parser": "^1.20.2",
    "express": "^4.22.1",
    "multer": "^1.4.5-lts.1"
  }
}
PKGEOF

echo "✓ package.json"

# Server.js - COMPLETE BACKEND
cat > server.js << 'SRVEOF'
const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const os = require('os');

const app = express();
const PORT = 3000;

// Multer config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 500 * 1024 * 1024 }
});

// Middleware
app.use(bodyParser.json({ limit: '200mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '200mb' }));
app.use(express.static(path.join(__dirname, 'web')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Data
let loginKeys = [];
let shops = [];
let hotmails = [];
let adminNotes = [];
let notifications = [];
let tokens = new Map();

const FILES = {
  loginKeys: 'data/login-keys.json',
  shops: 'data/shops.json',
  hotmails: 'data/hotmails.json',
  adminNotes: 'data/admin-notes.json',
  notifications: 'data/notifications.json'
};

const ADMIN_KEY = 'XKECEJ-FICMD-XKEK20-X34ICKCK';

// Utils
const sanitize = (i) => typeof i !== 'string' ? i : i.replace(/['"`;]/g, '');
const genKey = () => crypto.randomBytes(16).toString('hex').toUpperCase();

const getExpiryDate = (duration) => {
  const now = new Date();
  switch (duration) {
    case '1day': return new Date(now.getTime() + 24 * 60 * 60 * 1000);
    case '1week': return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    case '1month': return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
    default: return new Date(now.getTime() + 24 * 60 * 60 * 1000);
  }
};

const isKeyExpired = (key) => {
  if (key.role === 'admin') return false;
  if (!key.expiresAt) return false;
  return new Date(key.expiresAt) < new Date();
};

// Load data
async function loadData() {
  try {
    await fs.mkdir('data', { recursive: true });
    await fs.mkdir('uploads', { recursive: true });

    // Load login keys - ALWAYS ensure admin key exists
    try {
      const data = await fs.readFile(FILES.loginKeys, 'utf8');
      loginKeys = JSON.parse(data);
      
      // Check if admin key exists
      const hasAdmin = loginKeys.some(k => k.role === 'admin' && k.key === ADMIN_KEY);
      if (!hasAdmin) {
        loginKeys.unshift({
          id: Date.now(),
          key: ADMIN_KEY,
          role: 'admin',
          created: new Date().toISOString()
        });
        await fs.writeFile(FILES.loginKeys, JSON.stringify(loginKeys, null, 2));
      }
    } catch (e) {
      loginKeys = [{
        id: Date.now(),
        key: ADMIN_KEY,
        role: 'admin',
        created: new Date().toISOString()
      }];
      await fs.writeFile(FILES.loginKeys, JSON.stringify(loginKeys, null, 2));
    }

    // Load other data
    for (const [key, file] of Object.entries(FILES)) {
      if (key === 'loginKeys') continue;
      try {
        const data = await fs.readFile(file, 'utf8');
        switch (key) {
          case 'shops': shops = JSON.parse(data); break;
          case 'hotmails': hotmails = JSON.parse(data); break;
          case 'adminNotes': adminNotes = JSON.parse(data); break;
          case 'notifications': notifications = JSON.parse(data); break;
        }
      } catch (e) {
        await fs.writeFile(file, '[]');
      }
    }
  } catch (e) {
    console.error('Load data error:', e);
  }
}

// Middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization;
  if (token && tokens.has(token) && tokens.get(token).expire > Date.now()) {
    req.user = tokens.get(token).user;
    return next();
  }
  res.status(401).json({ success: false, message: 'Unauthorized' });
};

const adminOnly = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    return next();
  }
  res.status(403).json({ success: false, message: 'Admin only' });
};

// Routes

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { key } = req.body;
    const sanitizedKey = sanitize(key);
    
    // Find key
    const loginKey = loginKeys.find(k => k.key === sanitizedKey);
    
    if (!loginKey) {
      return res.json({ success: false, message: 'Invalid key' });
    }

    // Check expiry
    if (isKeyExpired(loginKey)) {
      return res.json({ success: false, message: 'Key expired (Dead Key)' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    tokens.set(token, {
      user: {
        id: loginKey.id,
        key: loginKey.key,
        role: loginKey.role
      },
      expire: Date.now() + 3600000
    });

    res.json({
      success: true,
      token,
      role: loginKey.role
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Generate key
app.post('/api/genkey', auth, adminOnly, async (req, res) => {
  try {
    const { duration } = req.body;
    const expiresAt = getExpiryDate(duration);
    
    const newLoginKey = {
      id: Date.now(),
      key: genKey(),
      role: 'user',
      duration: duration,
      created: new Date().toISOString(),
      expiresAt: expiresAt.toISOString()
    };

    loginKeys.push(newLoginKey);
    await fs.writeFile(FILES.loginKeys, JSON.stringify(loginKeys, null, 2));

    res.json({
      success: true,
      key: newLoginKey.key,
      duration,
      expiresAt: newLoginKey.expiresAt
    });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.post('/api/deleteloginkey', auth, adminOnly, async (req, res) => {
  try {
    loginKeys = loginKeys.filter(k => k.id !== req.body.id && k.role !== 'admin');
    await fs.writeFile(FILES.loginKeys, JSON.stringify(loginKeys, null, 2));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.get('/api/loginkeys', auth, adminOnly, (req, res) => {
  const keys = loginKeys
    .filter(k => k.role !== 'admin')
    .map(k => ({
      ...k,
      expired: isKeyExpired(k)
    }));
  res.json(keys);
});

// Notifications
app.get('/api/notifications', auth, (req, res) => res.json(notifications));

app.post('/api/createnotification', auth, adminOnly, async (req, res) => {
  try {
    const { title, content } = req.body;
    if (!title || !content) {
      return res.json({ success: false });
    }

    const notification = {
      id: Date.now(),
      title: sanitize(title),
      content: sanitize(content),
      created: new Date().toISOString()
    };

    notifications.push(notification);
    await fs.writeFile(FILES.notifications, JSON.stringify(notifications, null, 2));
    res.json({ success: true, notification });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.post('/api/deletenotification', auth, adminOnly, async (req, res) => {
  try {
    notifications = notifications.filter(n => n.id !== req.body.id);
    await fs.writeFile(FILES.notifications, JSON.stringify(notifications, null, 2));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

// Shops
app.get('/api/shops', auth, (req, res) => res.json(shops));

app.post('/api/createshop', upload.single('image'), auth, adminOnly, async (req, res) => {
  try {
    const { name, note } = req.body;
    let content = req.body.content || '';

    if (!name || !content) {
      return res.json({ success: false, message: 'Name and content required' });
    }

    const lines = content.split('\n').length;
    if (lines > 50000000) {
      return res.json({ success: false, message: 'Max 50M lines' });
    }

    const shop = {
      id: Date.now(),
      name: sanitize(name),
      content: content,
      note: sanitize(note) || '',
      image: req.file ? `/uploads/${req.file.filename}` : null,
      created: new Date().toISOString(),
      lines: lines
    };

    shops.push(shop);
    await fs.writeFile(FILES.shops, JSON.stringify(shops, null, 2));
    res.json({ success: true, shop });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.post('/api/deleteshop', auth, adminOnly, async (req, res) => {
  try {
    shops = shops.filter(s => s.id !== req.body.id);
    await fs.writeFile(FILES.shops, JSON.stringify(shops, null, 2));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.get('/api/shop/:id', auth, (req, res) => {
  const shop = shops.find(s => s.id === parseInt(req.params.id));
  if (shop) res.json(shop);
  else res.status(404).json({ success: false });
});

// Hotmails
app.get('/api/hotmails', auth, (req, res) => res.json(hotmails));

app.post('/api/createhotmail', upload.single('image'), auth, adminOnly, async (req, res) => {
  try {
    const { name, note } = req.body;
    let content = req.body.content || '';

    if (!name || !content) {
      return res.json({ success: false, message: 'Name and content required' });
    }

    const lines = content.split('\n').length;
    if (lines > 50000000) {
      return res.json({ success: false, message: 'Max 50M lines' });
    }

    const hotmail = {
      id: Date.now(),
      name: sanitize(name),
      content: content,
      note: sanitize(note) || '',
      image: req.file ? `/uploads/${req.file.filename}` : null,
      created: new Date().toISOString(),
      lines: lines
    };

    hotmails.push(hotmail);
    await fs.writeFile(FILES.hotmails, JSON.stringify(hotmails, null, 2));
    res.json({ success: true, hotmail });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.post('/api/deletehotmail', auth, adminOnly, async (req, res) => {
  try {
    hotmails = hotmails.filter(h => h.id !== req.body.id);
    await fs.writeFile(FILES.hotmails, JSON.stringify(hotmails, null, 2));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.get('/api/hotmail/:id', auth, (req, res) => {
  const hotmail = hotmails.find(h => h.id === parseInt(req.params.id));
  if (hotmail) res.json(hotmail);
  else res.status(404).json({ success: false });
});

// Admin Notes
app.get('/api/adminnotes', auth, (req, res) => res.json(adminNotes));

app.post('/api/createadminnote', auth, adminOnly, async (req, res) => {
  try {
    const { title, content } = req.body;
    if (!title || !content) {
      return res.json({ success: false });
    }

    const note = {
      id: Date.now(),
      title: sanitize(title),
      content: sanitize(content),
      created: new Date().toISOString()
    };

    adminNotes.push(note);
    await fs.writeFile(FILES.adminNotes, JSON.stringify(adminNotes, null, 2));
    res.json({ success: true, note });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.post('/api/deleteadminnote', auth, adminOnly, async (req, res) => {
  try {
    adminNotes = adminNotes.filter(n => n.id !== req.body.id);
    await fs.writeFile(FILES.adminNotes, JSON.stringify(adminNotes, null, 2));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

// ULP Search
app.post('/api/ulpsearch', auth, async (req, res) => {
  try {
    const { target, total, timeout, server } = req.body;
    if (!target) {
      return res.json({ success: false, message: 'Target required' });
    }

    const serverNum = server || 1;
    const url = `http://79.137.76.211:5119/api/search?keyword=${encodeURIComponent(target)}&timeout=${timeout || 10}&format=ulp&total=${total || 100}&mode=regex&username=ducdz122&password=phuvanduc&sever=${serverNum}`;
    
    const response = await axios.get(url, { timeout: 60000 });

    res.json({
      success: true,
      data: response.data,
      results: response.data.results || response.data
    });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// BIN Checker
app.post('/api/checkbin', auth, async (req, res) => {
  try {
    const { bins } = req.body;
    const results = [];

    for (const bin of bins) {
      try {
        const response = await axios.get(`https://bins.antipublic.cc/bins/${bin.trim()}`, {
          timeout: 15000
        });

        if (response.status === 200 && response.data) {
          results.push({
            bin: bin.trim(),
            status: 'valid',
            brand: response.data.brand || 'N/A',
            type: response.data.type || 'N/A',
            bank: response.data.bank || 'N/A',
            country: response.data.country_name || 'N/A'
          });
        } else {
          results.push({
            bin: bin.trim(),
            status: 'not_found'
          });
        }
      } catch (error) {
        results.push({
          bin: bin.trim(),
          status: 'error'
        });
      }
    }

    res.json({ success: true, results });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

// HTML routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'web/main.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'web/login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'web/dashboard.html')));
app.get('/shop', (req, res) => res.sendFile(path.join(__dirname, 'web/shop.html')));
app.get('/hotmail', (req, res) => res.sendFile(path.join(__dirname, 'web/hotmail.html')));
app.get('/ulp', (req, res) => res.sendFile(path.join(__dirname, 'web/ulp.html')));
app.get('/bin', (req, res) => res.sendFile(path.join(__dirname, 'web/bin.html')));
app.get('/settings', (req, res) => res.sendFile(path.join(__dirname, 'web/settings.html')));

// Start
loadData().then(() => {
  const ip = Object.values(os.networkInterfaces())
    .flat()
    .find(i => i.family === 'IPv4' && !i.internal)?.address || 'localhost';
  
  const link = ip === 'localhost' ? `http://localhost:${PORT}` : `http://${ip}:${PORT}`;

  app.listen(PORT, '0.0.0.0', () => {
    console.log('\n╔══════════════════════════════════════════════════╗');
    console.log('║    SERVER KEY - ULTRA DARK EDITION V2.1         ║');
    console.log('╟──────────────────────────────────────────────────╢');
    console.log(`║ IP           : ${ip.padEnd(37)}║`);
    console.log(`║ LINK         : ${link.padEnd(37)}║`);
    console.log(`║ PORT         : ${PORT.toString().padEnd(37)}║`);
    console.log('╟──────────────────────────────────────────────────╢');
    console.log('║ ✓ Fixed Admin Key Login                          ║');
    console.log('║ ✓ Updated Modern UI                              ║');
    console.log('║ ✓ Dead Key System                                ║');
    console.log('║ ✓ Upload Manager (50M lines)                     ║');
    console.log('║ ✓ ULP Search (5 Servers)                         ║');
    console.log('╚══════════════════════════════════════════════════╝');
    console.log(`\n→ ${link}`);
    console.log(`→ Admin: ${ADMIN_KEY}\n`);
  });
});
SRVEOF

echo "✓ server.js"

# Now create all HTML/CSS files...
echo "Creating web files..."

chmod +x create-all.sh
