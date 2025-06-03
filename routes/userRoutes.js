const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { protect } = require('../middleware/authMiddleware');

router.post('/register', userController.registerUser);
router.post('/login', userController.loginUser);

router.use(protect);
router.post('/logout', protect, userController.logoutUser);
router.get('/dashboard', protect, userController.getAllUsers);
router.post('/bulk-delete', protect, userController.deleteMultipleUsers);
router.post('/bulk-status', protect, userController.updateMultipleUsersStatus);
module.exports = router;
