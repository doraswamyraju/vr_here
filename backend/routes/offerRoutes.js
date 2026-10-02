import express from 'express';
import {
    getActiveOffers,
    getAllOffersAdmin,
    createOffer,
    updateOffer,
    deleteOffer
} from '../controllers/offerController.js';
import { protect, admin } from '../middleware/authMiddleware.js';

const router = express.Router();

// Public routes
router.get('/', getActiveOffers);

// Admin routes
router.get('/admin/all', protect, admin, getAllOffersAdmin);
router.post('/', protect, admin, createOffer);
router.put('/:id', protect, admin, updateOffer);
router.delete('/:id', protect, admin, deleteOffer);

export default router;
