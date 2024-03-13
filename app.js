var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var cors = require('cors');
var mysql = require('mysql2');
var bcrypt = require('bcryptjs');
var session = require('express-session');
require('dotenv').config();

var app = express();

// Configuration CORS pour supporter les credentials
app.use(cors({
  origin: 'http://localhost:5173', // ou votre URL de front-end
  credentials: true,
}));

// Configuration de la session
app.use(session({
  secret: 'signatureducookiemiam',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: 'auto' }
}));

// Connexion à la base de données
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});

// Middlewares
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Route de connexion
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM users_data WHERE username = ?', [username], async (err, results) => {
    if (err) {
      return res.status(500).send(err);
    }
    if (results.length > 0) {
      const user = results[0];
      const comparison = await bcrypt.compare(password, user.password);
      if (comparison) {
        req.session.userId = user.id; // Stockage de l'ID utilisateur dans la session
        return res.status(200).json({ message: "Authentification réussie" });
      }
    }
    return res.status(401).json({ message: "Identifiants invalides" });
  });
});

// Route d'inscription
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "Tous les champs sont requis." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.query('INSERT INTO users_data (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword], (err, results) => {
      if (err) {
        return res.status(500).json({ message: "Erreur lors de la création de l'utilisateur." });
      }
      res.status(201).json({ message: "Utilisateur créé avec succès." });
    });
  } catch (error) {
    return res.status(500).json({ message: "Erreur lors du traitement de la demande." });
  }
});

// Route de mise à jour du mot de passe
app.post('/updatemdpuser', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Utilisateur non connecté." });
  }

  const { currentPassword, newPassword } = req.body;

// Expression régulière pour valider le mot de passe
  const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;

  // Vérification des critères du mot de passe
  if (!passwordRegex.test(newPassword)) {
    return res.status(400).json({
      message: "Le mot de passe doit contenir au moins 8 caractères, dont une majuscule, un chiffre et un symbole."
    });
  }

  const userId = req.session.userId;

  db.query('SELECT password FROM users_data WHERE id = ?', [userId], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(500).json({ message: "Erreur lors de la récupération de l'utilisateur." });
    }

    const isMatch = await bcrypt.compare(currentPassword, results[0].password);
    if (!isMatch) {
      return res.status(401).json({ message: "Mot de passe actuel incorrect." });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    db.query('UPDATE users_data SET password = ? WHERE id = ?', [hashedNewPassword, userId], (err, results) => {
      if (err) {
        return res.status(500).json({ message: "Erreur lors de la mise à jour du mot de passe." });
      }
      return res.status(200).json({ message: "Mot de passe mis à jour avec succès." });
    });
  });
});


// Route pour obtenir les informations de l'utilisateur connecté
app.get('/user-info', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Utilisateur non connecté." });
  }

  const userId = req.session.userId;

  db.query('SELECT prenom, nom, numero_etudiant FROM users_data WHERE id = ?', [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Erreur lors de la récupération des informations de l'utilisateur." });
    }

    if (results.length > 0) {
      const userInfo = results[0];
      res.json(userInfo);
    } else {
      res.status(404).json({ message: "Utilisateur non trouvé." });
    }
  });
});

// Routes
var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
app.use('/', indexRouter);
app.use('/users', usersRouter);

// Gestion des erreurs
app.use(function(req, res, next) {
  next(createError(404));
});

app.use(function(err, req, res, next) {
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
