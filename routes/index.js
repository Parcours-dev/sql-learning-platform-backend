var express = require('express');
var router = express.Router();


// Route de test avec CORS spécifique
router.get('/test', (req, res) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    res.json({message: 'Ta grand mère fdp'});
});

module.exports = router;
