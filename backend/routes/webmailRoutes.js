import express from 'express';
const router = express.Router();
import {
    getWebmails,
    createWebmail,
    updateWebmail,
    deleteWebmail,
    getDiagnostics,
    triggerSync
} from '../controllers/webmailController.js';
import { protect, admin } from '../middleware/authMiddleware.js';

router.route('/diagnostics')
    .get(protect, admin, getDiagnostics);

router.route('/sync')
    .post(protect, admin, triggerSync);

router.route('/')
    .get(protect, admin, getWebmails)
    .post(protect, admin, createWebmail);

router.route('/:id')
    .put(protect, admin, updateWebmail)
    .delete(protect, admin, deleteWebmail);

export default router;
