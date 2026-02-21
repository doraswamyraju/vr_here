import express from 'express';
const router = express.Router();
import {
    authUser,
    registerUser,
    forgotPassword,
    resetPassword,
    getUserProfile,
    getEmployees,
} from '../controllers/authController.js';
import { protect, admin } from '../middleware/authMiddleware.js';

router.post('/register', registerUser);
router.post('/login', authUser);
router.post('/forgotpassword', forgotPassword);
router.put('/resetpassword/:resetToken', resetPassword);
router.route('/profile').get(protect, getUserProfile);
router.route('/employees').get(protect, admin, getEmployees);

export default router;
