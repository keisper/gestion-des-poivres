const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const app = express();
const PORT = 3000;

const jwt = require('jsonwebtoken');
const SECRET_KEY = 'super-secret-key';
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 10;




// Auth simulée (à améliorer plus tard avec BDD)
const USERS = [{ username: 'gilles', password: 'admin123' }];

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Base de données SQLite
const db = new sqlite3.Database('./backend/stock.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS articles (
    id TEXT PRIMARY KEY AUTOINCREMENT,
    grammage INTEGER,
    prix INTEGER,
    stock INTEGER,
    vendue INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )`);

});

// Routes API
app.get('/articles', (req, res) => {
  db.all('SELECT * FROM articles', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/register', (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs requis' });

  bcrypt.hash(password, SALT_ROUNDS, (err, hashedPassword) => {
    if (err) return res.status(500).json({ error: 'Erreur de hashage' });

    db.run(
      'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
      [username, hashedPassword, role || 'user'],
      function (err) {
        if (err) return res.status(500).json({ error: 'Nom d\'utilisateur déjà utilisé' });
        res.status(201).json({ success: true, id: this.lastID });
      }
    );
  });
});




app.post('/articles', (req, res) => {
  const { id, grammage, prix, stock } = req.body;
  db.run('INSERT INTO articles (grammage, prix, stock, vendue) VALUES (?, ?, ?, ?)', [grammage, prix, stock, 0], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ success: true });
  });
});

app.delete('/articles/:id', (req, res) => {
  db.run('DELETE FROM articles WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.put('/articles/:id/vendre', (req, res) => {
  db.run('UPDATE articles SET stock = stock - 1, vendue = vendue + 1 WHERE id = ? AND stock > 0', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(400).json({ error: 'Stock épuisé' });
    res.json({ success: true });
  });
});



app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: 'Identifiants invalides' });

    bcrypt.compare(password, user.password, (err, same) => {
      if (err || !same) return res.status(401).json({ error: 'Identifiants invalides' });

      const token = jwt.sign(
        { username: user.username, role: user.role || 'user' },
        SECRET_KEY,
        { expiresIn: '1h' }
      );
      res.json({ token });
    });
  });
});




function verifierToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Token manquant' });

  const token = auth.split(' ')[1];
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token invalide' });
    req.user = user;
    next();
  });
}

app.get('/stats', (req, res) => {
  db.all('SELECT COUNT(*) AS totalArticles FROM articles', [], (err, countRow) => {
    if (err) return res.status(500).json({ error: err.message });

    db.all('SELECT SUM(stock) AS totalStock, SUM(vendue) AS totalVendue, SUM(vendue * prix) AS totalRevenu FROM articles', [], (err2, dataRow) => {
      if (err2) return res.status(500).json({ error: err2.message });

      res.json({
        totalArticles: countRow[0].totalArticles,
        totalStock: dataRow[0].totalStock || 0,
        totalVendue: dataRow[0].totalVendue || 0,
        totalRevenu: dataRow[0].totalRevenu || 0
      });
    });
  });
});

app.get('/stats/ventes', (req, res) => {
  db.all('SELECT id, vendue FROM articles ORDER BY vendue DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/users', verifierToken, (req, res) => {
  db.all('SELECT id, username FROM users', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.delete('/users/:id', verifierToken, (req, res) => {
  db.run('DELETE FROM users WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});



// Appliquer à toutes les routes sauf /login
app.use((req, res, next) => {
  if (req.path === '/login') return next();
  return verifierToken(req, res, next);
});

// Démarrage du serveur
app.listen(PORT, () => {
  console.log(`Serveur lancé sur http://localhost:${PORT}`);
});


