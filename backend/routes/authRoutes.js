import express from 'express';
const router = express.Router();
import {
    authUser,
    registerUser,
    forgotPassword,
    resetPassword,
    getUserProfile,
    getEmployees,
    getUsers,
    createUserByAdmin,
    updateUserByAdmin,
    toggleUserActiveByAdmin,
    sendPasswordLinkByAdmin
} from '../controllers/authController.js';
import { protect, admin } from '../middleware/authMiddleware.js';

router.post('/register', registerUser);
router.post('/login', authUser);
router.post('/forgotpassword', forgotPassword);
router.put('/resetpassword/:resetToken', resetPassword);
router.route('/profile').get(protect, getUserProfile);
router.route('/employees').get(protect, admin, getEmployees);
router.route('/users').get(protect, admin, getUsers).post(protect, admin, createUserByAdmin);
router.route('/users/:id').put(protect, admin, updateUserByAdmin);
router.route('/users/:id/toggle-active').patch(protect, admin, toggleUserActiveByAdmin);
router.route('/users/:id/send-password-link').post(protect, admin, sendPasswordLinkByAdmin);

export default router;

