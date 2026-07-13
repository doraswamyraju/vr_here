import express from 'express';
const router = express.Router();
import {
    createTransaction,
    getTransactions,
    updateTransaction,
    deleteTransaction,
    getCompanyDetails,
    upsertCompanyDetails,
    exportTallyVouchers,
    exportGstr1Data
} from '../controllers/accountingController.js';
import { protect } from '../middleware/authMiddleware.js';

router.route('/transactions')
    .post(protect, createTransaction)
    .get(protect, getTransactions);

router.route('/transactions/:id')
    .put(protect, updateTransaction)
    .delete(protect, deleteTransaction);

router.route('/company')
    .get(protect, getCompanyDetails)
    .post(protect, upsertCompanyDetails);

router.route('/export/tally')
    .get(protect, exportTallyVouchers);

router.route('/export/gstr1')
    .get(protect, exportGstr1Data);

export default router;
