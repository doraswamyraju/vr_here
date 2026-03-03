import express from 'express';
import {
    getPayments,
    getPaymentById,
    createPayment
} from '../controllers/paymentController.js';
import { protect, admin } from '../middleware/authMiddleware.js';

const router = express.Router();

router.route('/')
    .get(protect, getPayments)
    .post(protect, admin, createPayment);

router.route('/:id')
    .get(protect, getPaymentById);

export default router;
