import express from 'express';
const router = express.Router();
import {
    createOrder,
    getOrders,
    getOrderById,
    updateOrderStatus,
    assignOrder,
    uploadDocument,
    addTask,
    updateTask,
    addChecklistItem,
    addInvoice
} from '../controllers/orderController.js';
import { protect, admin } from '../middleware/authMiddleware.js';
import upload from '../middleware/uploadMiddleware.js';

router.route('/')
    .post(protect, createOrder)
    .get(protect, getOrders);

router.route('/:id')
    .get(protect, getOrderById);

router.route('/:id/status')
    .put(protect, updateOrderStatus);

router.route('/:id/assign')
    .put(protect, admin, assignOrder);

router.route('/:id/documents')
    .post(protect, upload.single('document'), uploadDocument);

router.route('/:id/tasks')
    .post(protect, addTask);

router.route('/:id/tasks/:taskId')
    .put(protect, updateTask);

router.route('/:id/checklists')
    .post(protect, addChecklistItem);

router.route('/:id/invoices')
    .post(protect, admin, addInvoice);

export default router;

