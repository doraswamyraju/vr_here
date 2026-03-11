import express from 'express';
import {
    createCheckoutOrder,
    getPayments,
    getPaymentById,
    createPayment,
    verifyPayment
} from '../controllers/paymentController.js';
import { protect, protectOptional, admin } from '../middleware/authMiddleware.js';

const router = express.Router();

router.post('/checkout-order', protectOptional, createCheckoutOrder);
router.post('/verify', protectOptional, verifyPayment);

router.route('/')
    .get(protect, getPayments)
    .post(protect, admin, createPayment);

router.route('/:id')
    .get(protect, getPaymentById);

export default router;
