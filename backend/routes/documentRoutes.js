import express from 'express';
import {
    getUserDocuments,
    uploadUserDocument,
    deleteUserDocument,
    verifyUserDocument
} from '../controllers/documentController.js';
import { protect, admin } from '../middleware/authMiddleware.js';
import upload from '../middleware/uploadMiddleware.js';

const router = express.Router();

router.get('/', protect, getUserDocuments);
router.post('/upload', protect, upload.single('document'), uploadUserDocument);
router.delete('/:id', protect, deleteUserDocument);
router.put('/:id/verify', protect, admin, verifyUserDocument);

export default router;
