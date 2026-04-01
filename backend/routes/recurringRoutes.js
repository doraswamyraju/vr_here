import express from 'express';
const router = express.Router();
import {
    createSubscription,
    getSubscriptions,
    getSubscriptionById,
    updateSubscription,
    deleteSubscription
} from '../controllers/recurringController.js';
import { protect, admin } from '../middleware/authMiddleware.js';

router.route('/')
    .post(protect, admin, createSubscription)
    .get(protect, admin, getSubscriptions);

router.route('/:id')
    .get(protect, admin, getSubscriptionById)
    .put(protect, admin, updateSubscription)
    .delete(protect, admin, deleteSubscription);

export default router;
