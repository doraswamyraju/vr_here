import express from 'express';
import {
    createOrder,
    getOrders,
    getOrderById,
    updateOrderStatus,
    assignOrder,
    updateOrderCommercials,
    uploadDocument,
    addTask,
    updateTask,
    addSubtask,
    addChecklistItem,
    toggleChecklistItem,
    addInvoice,
    updateInvoiceStatus,
    importTasks,
    assignTask,
    addTaskTimeLog,
    importRequirements,
    updateRequirement
} from '../controllers/orderController.js';
import { protect, admin } from '../middleware/authMiddleware.js';
import upload from '../middleware/uploadMiddleware.js';

const router = express.Router();

router.route('/')
    .post(protect, createOrder)
    .get(protect, getOrders);

router.route('/:id')
    .get(protect, getOrderById);

router.route('/:id/status')
    .put(protect, updateOrderStatus);

router.route('/:id/assign')
    .put(protect, admin, assignOrder);

router.route('/:id/commercials')
    .put(protect, admin, updateOrderCommercials);

router.route('/:id/documents')
    .post(protect, upload.single('document'), uploadDocument);

router.route('/:id/tasks')
    .post(protect, addTask);

router.route('/:id/tasks/import')
    .post(protect, admin, importTasks);

router.route('/:id/tasks/:taskId')
    .put(protect, updateTask);

router.route('/:id/tasks/:taskId/assign')
    .put(protect, admin, assignTask);

router.route('/:id/tasks/:taskId/time-log')
    .post(protect, addTaskTimeLog);

router.route('/:id/tasks/:taskId/subtasks')
    .post(protect, admin, addSubtask);

router.route('/:id/checklists')
    .post(protect, addChecklistItem);

router.route('/:id/checklists/:itemId/toggle')
    .put(protect, toggleChecklistItem);

router.route('/:id/invoices')
    .post(protect, admin, addInvoice);

router.route('/:id/invoices/:invoiceId/status')
    .put(protect, admin, updateInvoiceStatus);

router.route('/:id/requirements/import')
    .post(protect, admin, importRequirements);

router.route('/:id/requirements/:requirementId')
    .put(protect, updateRequirement);

export default router;
