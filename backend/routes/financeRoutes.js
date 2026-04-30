import express from 'express';
const router = express.Router();
import {
    createFinanceRecord,
    getFinanceRecords,
    getFinanceRecordById,
    updateFinanceRecord,
    deleteFinanceRecord
} from '../controllers/financeController.js';
import { protect, admin } from '../middleware/authMiddleware.js';

router.route('/')
    .post(protect, createFinanceRecord)
    .get(protect, getFinanceRecords);

router.route('/:id')
    .get(protect, getFinanceRecordById)
    .put(protect, updateFinanceRecord)
    .delete(protect, admin, deleteFinanceRecord);

export default router;
