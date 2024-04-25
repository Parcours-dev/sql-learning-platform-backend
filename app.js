var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var cors = require('cors');
var mysql = require('mysql2/promise');
var bcrypt = require('bcryptjs');
var session = require('express-session');
let globalSelectedTables = [];
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


app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const [results] = await db.query('SELECT Users.*, Roles.RoleName FROM Users JOIN Roles ON Users.RoleID = Roles.RoleID WHERE Username = ?', [username]);
    if (results.length > 0) {
      const user = results[0];
      const comparison = await bcrypt.compare(password, user.PasswordHash);
      if (comparison) {
        console.log("User role from DB:", user.RoleName); // Assurez-vous que ceci renvoie 'Admin'
        req.session.userId = user.UserID;
        req.session.role = user.RoleName; // Stocker le rôle dans la session
        return res.status(200).json({
          message: "Authentification réussie",
          userId: user.UserID,
          role: user.RoleName // Envoyer le nom du rôle
        });
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
app.post('/api/addchapitres', checkRole("Admin"),async (req, res) => {
  const { nom, description } = req.body;

  try {
    const result = await db.query('INSERT INTO Chapitre (Nom, Description) VALUES (?, ?)', [nom, description]);
    res.status(201).json({ message: "Chapitre créé avec succès", chapitreId: result.insertId });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur lors de la création du chapitre" });
  }
});


app.post('/api/addexercices', checkRole("Admin"),async (req, res) => {
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


app.get('/api/questions', checkRole("Admin"),async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM Questions');
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

// Route to fetch all table names
app.get('/api/tables', checkRole("Admin"),async (req, res) => {
  try {
    const [tables] = await db.query("SHOW TABLES");
    // Assuming MySQL returns tables in a format like: { 'Tables_in_<database>': 'tableName' }
    const tableNames = tables.map((table) => table[Object.keys(table)[0]]);

    if (tableNames.length > 0) {
      res.json(tableNames);
    } else {
      res.status(404).json({ message: "Aucune donnée trouvée dans les tables de la base de données." });
    }
  } catch (error) {
    console.error('Failed to fetch table names:', error);
    res.status(500).json({ message: "Erreur lors de la récupération des noms des tables.", error });
  }
});

// Route to save selected table names globally
app.post('/api/save-tables', checkRole("Admin"),(req, res) => {
  const tables = req.body.tables;

  // Update the global variable with the received tables
  globalSelectedTables = tables;

  res.json({ message: 'Tables saved successfully', tables: globalSelectedTables });
});

app.get('/api/columns',checkRole("Admin"), async (req, res) => {
  try {
    const columnsPerTable = {};

    console.log('Tables sélectionnées:', globalSelectedTables);

    for (const tableName of globalSelectedTables) {
      const [columns] = await db.query(`
        SELECT COLUMN_NAME
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = (SELECT DATABASE()) AND TABLE_NAME = ?
      `, [tableName]);

      console.log('Colonnes pour', tableName, ':', columns);

      columnsPerTable[tableName] = columns.map(column => column.COLUMN_NAME);
    }

    console.log('Colonnes par table:', columnsPerTable);

    if (Object.keys(columnsPerTable).length > 0) {
      res.json(columnsPerTable);
    } else {
      res.status(404).json({ message: 'Aucune colonne trouvée pour les tables sélectionnées' });
    }
  } catch (error) {
    console.error('Échec de récupération des noms de colonne :', error);
    res.status(500).json({ message: "Erreur lors de la récupération des noms de colonne", error });
  }
});


app.get('/api/get-selected-tables',checkRole("Admin"), (req, res) => {
  res.json({ tables: globalSelectedTables }); // Assurez-vous que globalSelectedTables est correctement géré
});


// Route pour modifier un chapitre existant
app.put('/api/chapitres/:chapitreId', checkRole("Admin"),async (req, res) => {
  const { chapitreId } = req.params;
  const { nom, description } = req.body;

  if (!nom || !description) {
    return res.status(400).json({ message: "Nom et description du chapitre sont requis." });
  }

  try {
    const result = await db.query('UPDATE Chapitre SET Nom = ?, Description = ? WHERE ChapitreID = ?', [nom, description, chapitreId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Chapitre non trouvé ou aucune modification apportée." });
    }
    res.status(200).json({ message: "Chapitre mis à jour avec succès." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur lors de la mise à jour du chapitre" });
  }
});


// Route pour supprimer un chapitre
app.delete('/api/deletechapitres/:chapitreId',checkRole("Admin"), async (req, res) => {
  const { chapitreId } = req.params;

  try {
    const result = await db.query('DELETE FROM Chapitre WHERE ChapitreID = ?', [chapitreId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Chapitre non trouvé ou déjà supprimé." });
    }
    res.status(200).json({ message: "Chapitre supprimé avec succès." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur lors de la suppression du chapitre" });
  }
});

// Route pour modifier un exercice existant
app.put('/api/questions/:id', checkRole("Admin"), async (req, res) => {
  const { id } = req.params;
  const { titre, description, correctQuery, niveau, categorie, texteQuestion, instructions, chapitreId } = req.body;
  try {
    const query = 'UPDATE questions SET Title = ?, Description = ?, CorrectQuery = ?, Level = ?, Category = ?, QuestionText = ?, Instructions = ?, ChapitreID = ? WHERE QuestionID = ?';
    const result = await db.query(query, [titre, description, correctQuery, niveau, categorie, texteQuestion, instructions, chapitreId, id]);
    if (result[0].affectedRows === 0) {
      return res.status(404).json({ message: "Exercice non trouvé ou aucune modification apportée." });
    }
    res.status(200).json({ message: "Exercice modifié avec succès" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur lors de la modification de l'exercice", error });
  }
});

// Route pour supprimer un exercice
app.delete('/api/deletequestions/:id', checkRole("Admin"),async (req, res) => {
  const { id } = req.params;
  try {
    const query = 'DELETE FROM questions WHERE QuestionID = ?';
    const result = await db.query(query, [id]);
    if (result[0].affectedRows === 0) {
      return res.status(404).json({ message: "Exercice non trouvé ou déjà supprimé." });
    }
    res.status(200).json({ message: "Exercice supprimé avec succès" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur lors de la suppression de l'exercice", error });
  }
});

// Route pour obtenir l'étudiant avec le plus de réponses correctes
app.get('/api/top-student', async (req, res) => {
  try {
    const [results] = await db.query(`
      SELECT u.Nom, u.Prenom, COUNT(*) AS CorrectAnswers
      FROM Users u
      JOIN userresponses ur ON u.UserID = ur.UserID
      WHERE ur.IsCorrect = 1
      GROUP BY u.UserID
      ORDER BY CorrectAnswers DESC
      LIMIT 1;
    `);
    if (results.length > 0) {
      res.json(results[0]);
    } else {
      res.status(404).json({ message: "Aucun étudiant trouvé." });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur lors de la récupération des informations." });
  }
});


app.get('/api/least-successful-student', async (req, res) => {
  try {
    const [results] = await db.query(`
      SELECT u.Nom, u.Prenom, COUNT(*) AS CorrectAnswersCount
      FROM Users u
      JOIN userresponses ur ON u.UserID = ur.UserID
      WHERE ur.IsCorrect = 1
      GROUP BY u.UserID
      ORDER BY CorrectAnswersCount ASC
      LIMIT 1;
    `);
    if (results.length > 0) {
      res.json(results[0]);
    } else {
      res.status(404).json({ message: "Aucun étudiant trouvé." });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur lors de la récupération des informations." });
  }
});


app.get('/api/most-successful-chapter', async (req, res) => {
  try {
    const [results] = await db.query(`
      SELECT c.Nom as ChapterName, COUNT(ur.ResponseID) as CorrectAnswersCount
      FROM Chapitre c
      JOIN Questions q ON c.ChapitreID = q.ChapitreID
      JOIN userresponses ur ON q.QuestionID = ur.QuestionID
      WHERE ur.IsCorrect = 1
      GROUP BY c.ChapitreID
      ORDER BY CorrectAnswersCount DESC
      LIMIT 1;
    `);
    if (results.length > 0) {
      res.json(results[0]);
    } else {
      res.status(404).json({ message: "Aucun chapitre trouvé avec des réponses correctes." });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur lors de la récupération des informations du chapitre." });
  }
});

app.get('/api/least-successful-chapter', async (req, res) => {
  try {
    const [results] = await db.query(`
      SELECT c.Nom as ChapterName, COUNT(ur.ResponseID) as CorrectAnswersCount
      FROM Chapitre c
      JOIN Questions q ON c.ChapitreID = q.ChapitreID
      JOIN userresponses ur ON q.QuestionID = ur.QuestionID
      WHERE ur.IsCorrect = 1
      GROUP BY c.ChapitreID
      ORDER BY CorrectAnswersCount ASC
      LIMIT 1;
    `);
    if (results.length > 0) {
      res.json(results[0]);
    } else {
      res.status(404).json({ message: "Aucun chapitre trouvé avec des réponses correctes." });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur lors de la récupération des informations du chapitre." });
  }
});

// Route pour obtenir le nombre de bonnes réponses par jour
app.get('/api/daily-correct-answers', async (req, res) => {
  try {
    // Query pour récupérer le nombre de bonnes réponses par jour
    const [results] = await db.query(`
            SELECT DATE(SubmissionDate) AS date, COUNT(*) AS correctAnswers
            FROM userresponses
            WHERE IsCorrect = 1
            GROUP BY DATE(SubmissionDate)
            ORDER BY DATE(SubmissionDate);
        `);
    if (results.length > 0) {
      res.json(results);
    } else {
      res.status(404).json({ message: "Aucune donnée trouvée pour les réponses correctes par jour." });
    }
  } catch (error) {
    console.error("Error fetching daily correct answers:", error);
    res.status(500).json({ message: "Erreur lors de la récupération des données." });
  }
});



app.get('/api/chapter-completion', async (req, res) => {
  try {
    const [results] = await db.query(`
      SELECT
        c.ChapitreID,
        c.Nom as chapterName,
        (SELECT COUNT(*) FROM Questions WHERE ChapitreID = c.ChapitreID) as totalQuestions,
        (SELECT COUNT(DISTINCT UserID) FROM UserResponses ur
                                              JOIN Questions q ON ur.QuestionID = q.QuestionID
         WHERE ur.IsCorrect = 1 AND q.ChapitreID = c.ChapitreID) as correctUsers
      FROM Chapitre c
    `);

    // Calculer le pourcentage de questions résolues par chaque étudiant pour chaque chapitre
    const completionData = results.map(item => ({
      chapterId: item.ChapitreID,
      chapterName: item.chapterName,
      completionPercentage: item.totalQuestions ? Math.round((item.correctUsers / item.totalQuestions) * 100) : 0
    }));

    res.json(completionData);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Error retrieving chapter data." });
  }
});



app.get('/api/last-good-responses', async (req, res) => {
  try {
    const [results] = await db.query(`
      SELECT
        u.Nom,
        u.Prenom,
        q.Title AS QuestionTitle,
        q.ChapitreID AS ChapterNumber,
        ur.SubmissionDate AS LastGoodResponse
      FROM
        userresponses ur
          JOIN
        users u ON ur.UserID = u.UserID
          JOIN
        questions q ON ur.QuestionID = q.QuestionID
      WHERE
        ur.IsCorrect = 1
      GROUP BY
        u.UserID, q.QuestionID
      ORDER BY
        ur.SubmissionDate DESC
        LIMIT 6;
    `);
    res.json(results);
  } catch (error) {
    console.error("Error fetching last good responses:", error);
    res.status(500).json({ message: "Erreur lors de la récupération des données." });
  }
});


app.get('/api/user-ranking', async (req, res) => {
  try {
    const [results] = await db.query(`
      SELECT u.UserID, u.Nom, u.Prenom, COUNT(ur.ResponseID) AS BonnesReponses
      FROM users u
      LEFT JOIN userresponses ur ON u.UserID = ur.UserID AND ur.IsCorrect = 1
      GROUP BY u.UserID
      ORDER BY BonnesReponses DESC, u.Nom, u.Prenom
    `);
    res.json(results.map((item, index) => ({
      ...item,
      Rang: index + 1,
      NomComplet: `${item.Nom} ${item.Prenom}`
    })));
  } catch (error) {
    console.error("Error fetching user ranking:", error);
    res.status(500).json({ message: "Erreur lors de la récupération des données." });
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
