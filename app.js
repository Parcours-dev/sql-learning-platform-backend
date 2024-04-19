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

function checkRole(requiredRole) {
  return function(req, res, next) {
    if (req.session.role === requiredRole) {
      next();
    } else {
      res.status(403).json({ message: "Accès refusé" });
    }
  };
}
// checkRole('Admin') est un middleware qui vérifie si l'utilisateur a le rôle 'Admin'
// Si l'utilisateur n'a pas le rôle 'Admin', il recevra une réponse 403 (Accès refusé)


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
        req.session.role = user.RoleName;  // Stocker le rôle de l'utilisateur dans la session
        // Inclure l'ID de l'utilisateur dans la réponse
        return res.status(200).json({ message: "Authentification réussie", userId: user.UserID });
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
    const [results] = await db.query('SELECT Nom, Prenom, Email, NumEtudiant FROM Users WHERE UserID = ?', [userId]);
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

app.post('/update-profile', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Utilisateur non connecté." });
  }

  const { prenom, nom, email, numero_etudiant } = req.body;
  const userId = req.session.userId;

  try {
    await db.query('UPDATE Users SET Prenom = ?, Nom = ?, Email = ?, NumEtudiant = ? WHERE UserID = ?', [prenom, nom, email, numero_etudiant, userId]);
    res.status(200).json({ message: "Informations utilisateur mises à jour avec succès." });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erreur lors de la mise à jour des informations de l'utilisateur." });
  }
});


// Route de suppression du compte
app.delete('/delete-account', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Utilisateur non connecté." });
  }

  const userId = req.session.userId;

  try {
    await db.query('DELETE FROM Users WHERE UserID = ?', [userId]);
    req.session.destroy(); // Détruire la session après la suppression du compte
    res.status(200).json({ message: "Compte supprimé avec succès." });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erreur lors de la suppression du compte." });
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
    const [results] = await db.query('SELECT ChapitreID, Nom, Description FROM chapitre');
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

app.post('/verify-query', async (req, res) => {
  const { QuestionID, UserQuery } = req.body;

  if (!req.session.userId) {
    return res.status(401).json({ message: "Utilisateur non connecté." });
  }
  // Validation pour s'assurer que la requête commence par SELECT
  if (!UserQuery.trim().toLowerCase().startsWith('select')) {
    return res.status(400).json({ message: "Seules les requêtes SELECT sont autorisées." });
  }

  // Validation pour s'assurer que la requête se termine par ";"
  if (!UserQuery.trim().endsWith(';')) {
    return res.json({ message: "Réponse incorrecte.", isCorrect: false });  }


  try {
    const [question] = await db.query('SELECT CorrectQuery FROM Questions WHERE QuestionID = ?', [QuestionID]);

    if (question.length > 0) {
      // Exécution de la requête de correction prévue
      const [correctResults] = await db.query(question[0].CorrectQuery);
      // Exécution de la requête de l'étudiant
      const [userResults] = await db.query(UserQuery);

      // Comparaison des jeux de données
      // NOTE: Cette comparaison est basique et pourrait nécessiter des ajustements pour gérer différentes structures de données
      const isCorrect = JSON.stringify(correctResults) === JSON.stringify(userResults);

      if (isCorrect) {
        // Si la requête est correcte, insérer la réponse dans la table `users response`
        const [insertResponse] = await db.query(
            'INSERT INTO `userresponses` (UserID, QuestionID, UserQuery, IsCorrect, SubmissionDate) VALUES (?, ?, ?, ?, NOW())',
            [req.session.userId, QuestionID, UserQuery, isCorrect]
        );
        return res.json({ message: "Réponse vérifiée et enregistrée.", isCorrect: true });
      } else {
        // Logique pour gérer la réponse incorrecte
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


// Récupération de la progression de l'utilisateur
// Récupération de la progression de l'utilisateur
app.get('/api/progression', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Utilisateur non connecté." });
  }

  const userId = req.session.userId; // Utilisez l'ID de l'utilisateur à partir de la session
  try {
    const resultat = await db.query(`
      SELECT QuestionID FROM userresponses
      WHERE UserID = ? AND IsCorrect = TRUE
      ORDER BY QuestionID DESC
      LIMIT 1
    `, [userId]);

    res.json(resultat.length > 0 ? resultat[0] : { QuestionID: null });
  } catch (error) {
    res.status(500).json({ message: "Erreur lors de la récupération de la progression." });
  }
});



// Route pour obtenir le pourcentage de questions résolues
app.get('/api/progress', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Utilisateur non connecté." });
  }

  const userId = req.session.userId;

  try {
    // Compter le nombre total de questions disponibles
    const [totalQuestions] = await db.query('SELECT COUNT(*) AS total FROM questions');

    // Compter le nombre unique de questions correctement répondues par cet utilisateur
    const [correctAnswers] = await db.query(
        'SELECT COUNT(DISTINCT QuestionID) AS correct FROM userresponses WHERE UserID = ? AND IsCorrect = 1',
        [userId]
    );

    // Calculer le pourcentage de questions correctement répondues par rapport au total des questions disponibles
    const percentage = totalQuestions[0].total > 0
        ? (correctAnswers[0].correct / totalQuestions[0].total) * 100
        : 0; // Eviter la division par zéro si aucune question n'est disponible

    res.json({ progressPercentage: Math.round(percentage) });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: "Erreur lors de la récupération des informations." });
  }
});

// Route pour ajouter un chapitre
app.post('/api/addchapitres', async (req, res) => {
  const { nom, description } = req.body;

  try {
    const result = await db.query('INSERT INTO Chapitre (Nom, Description) VALUES (?, ?)', [nom, description]);
    res.status(201).json({ message: "Chapitre créé avec succès", chapitreId: result.insertId });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur lors de la création du chapitre" });
  }
});


app.post('/api/addexercices', async (req, res) => {
  const { titre, description, correctQuery, niveau, categorie, texteQuestion, instructions, chapitreId } = req.body;

  // Validation des données requises
  if (!titre || !description || !correctQuery || !niveau || !categorie || !texteQuestion || !instructions || !chapitreId) {
    return res.status(400).json({ message: "Tous les champs sont requis." });
  }

  try {
    // Insertion de l'exercice dans la base de données
    const result = await db.query(
        'INSERT INTO Questions (Title, Description, CorrectQuery, Level, Category, QuestionText, Instructions, ChapitreID) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [titre, description, correctQuery, niveau, categorie, texteQuestion, instructions, chapitreId]
    );

    // Réponse en cas de succès
    res.status(201).json({ message: "Exercice ajouté avec succès", questionId: result.insertId });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur lors de l'ajout de l'exercice" });
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
