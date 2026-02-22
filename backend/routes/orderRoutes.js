import express from 'express';
const router = express.Router();
import {
    createOrder,
    getOrders,
    getOrderById,
    updateOrderStatus,
    assignOrder,
    uploadDocument
} from '../controllers/orderController.js';
import { protect, admin } from '../middleware/authMiddleware.js';
import upload from '../middleware/uploadMiddleware.js';

router.route('/')
    .post(protect, createOrder)
    .get(protect, getOrders);

router.route('/:id')
    .get(protect, getOrderById);

router.route('/:id/status')
    .put(protect, updateOrderStatus); // Should be protected, verified by controller logic

router.route('/:id/assign')
    .put(protect, admin, assignOrder);

router.route('/:id/documents')
    .post(protect, upload.single('document'), uploadDocument);

export default router;
