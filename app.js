var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var cors = require('cors');
var mysql = require('mysql2/promise');
var bcrypt = require('bcryptjs');
var session = require('express-session');
require('dotenv').config();

var app = express();

// Configuration CORS pour supporter les credentials
app.use(cors({
  origin: 'http://localhost:5173', // URL du Front
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
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});


// Middlewares
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:5173');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});


// Route de connexion
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const [results] = await db.query('SELECT * FROM Users WHERE Username = ?', [username]);
    if (results.length > 0) {
      const user = results[0];
      const comparison = await bcrypt.compare(password, user.PasswordHash);
      if (comparison) {
        req.session.userId = user.UserID;
        return res.status(200).json({ message: "Authentification réussie" });
      }
    }
    return res.status(401).json({ message: "Identifiants invalides" });
  } catch (error) {
    console.error(error);
    return res.status(500).send(error);
  }
});


// Route d'inscription
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "Tous les champs sont requis." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.query('INSERT INTO Users (Username, Email, PasswordHash) VALUES (?, ?, ?)', [username, email, hashedPassword], (err, results) => {
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

  db.query('SELECT PasswordHash FROM Users WHERE UserID = ?', [userId], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(500).json({ message: "Erreur lors de la récupération de l'utilisateur." });
    }

    const isMatch = await bcrypt.compare(currentPassword, results[0].password);
    if (!isMatch) {
      return res.status(401).json({ message: "Mot de passe actuel incorrect." });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    db.query('UPDATE Users SET PasswordHash = ? WHERE UserID = ?', [hashedNewPassword, userId], (err, results) => {
      if (err) {
        return res.status(500).json({ message: "Erreur lors de la mise à jour du mot de passe." });
      }
      return res.status(200).json({ message: "Mot de passe mis à jour avec succès." });
    });
  });
});


// Route pour obtenir les informations de l'utilisateur connecté
app.get('/user-info', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Utilisateur non connecté." });
  }

  const userId = req.session.userId;

  try {
    const [results] = await db.query('SELECT Username, Email FROM Users WHERE UserID = ?', [userId]);
    if (results.length > 0) {
      const userInfo = results[0];
      res.json(userInfo);
    } else {
      res.status(404).json({ message: "Utilisateur non trouvé." });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erreur lors de la récupération des informations de l'utilisateur." });
  }
});



// Route API pour récupérer les données des employés
app.get('/tables/employe', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM Employe');
    if (results.length > 0) {
      res.json(results);
    } else {
      res.status(404).json({ message: "Aucune donnée trouvée dans la table Employe." });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erreur lors de la récupération des informations de la table." });
  }
});

// Envoie du MCD de la base

const mcdData = require('./mcdData');
app.get('/api/mcd', (req, res) => {
  res.json(mcdData);
});

// Récupération des chapitres et infos
app.get('/api/chapitres', async (req, res) => {
  try {
    const [results] = await db.query('SELECT ChapitreID, Nom, Description FROM Chapitre');
    if (results.length > 0) {
      res.json(results);
    } else {
      res.status(404).json({ message: "Aucun chapitre trouvé." });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erreur lors de la récupération des chapitres." });
  }
});


// Récupération des exercices d'un chapitre
app.get('/api/chapitres/:chapitreId/exercices', async (req, res) => {
  const { chapitreId } = req.params;
  try {
    const [exercices] = await db.query('SELECT * FROM Questions WHERE ChapitreID = ?', [chapitreId] );
    res.json(exercices);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur lors de la récupération des exercices." });
  }
});

// Après les autres routes
app.post('/verify-query', async (req, res) => {
  const { QuestionID, UserQuery } = req.body;

  if (!req.session.userId) {
    return res.status(401).json({ message: "Utilisateur non connecté." });
  }

  try {
    const [question] = await db.query('SELECT CorrectQuery FROM Questions WHERE QuestionID = ?', [QuestionID]);

    if (question.length > 0) {
      const isCorrect = UserQuery === question[0].CorrectQuery;

      if (isCorrect) {
        // Si la requête est correcte, insérer la réponse dans la table `users response`
        const [insertResponse] = await db.query(
            'INSERT INTO `userresponses` (UserID, QuestionID, UserQuery, IsCorrect, SubmissionDate) VALUES (?, ?, ?, ?, NOW())',
            [req.session.userId, QuestionID, UserQuery, isCorrect]
        );

        return res.json({ message: "Réponse vérifiée et enregistrée.", isCorrect: true });
      } else {
        // Optionnel : enregistrer aussi les tentatives incorrectes
        return res.json({ message: "Réponse incorrecte.", isCorrect: false });
      }
    } else {
      return res.status(404).json({ message: "Question non trouvée." });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erreur lors de la vérification de la requête." });
  }
});

// Route pour obtenir l'indice d'une question
app.get('/questions/:questionId/indice', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Utilisateur non connecté." });
  }

  const { questionId } = req.params;
  try {
    const [result] = await db.query('SELECT Instructions FROM Questions WHERE QuestionID = ?', [questionId]);
    if (result.length > 0) {
      res.json({ indice: result[0].Instructions });
    } else {
      res.status(404).json({ message: "Question non trouvée." });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur lors de la récupération de l'indice." });
  }
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
