const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth');

router.post('/register', authController.register);
router.post('/login', authController.login);
router.get('/refresh', authController.refreshToken);
router.get('/logout', authController.logout);

module.exports = router;