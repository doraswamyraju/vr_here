import express from 'express';
const router = express.Router();
import {
    createTransaction,
    getTransactions,
    updateTransaction,
    deleteTransaction,
    getCompanyDetails,
    upsertCompanyDetails,
    getParties,
    createParty,
    updateParty,
    deleteParty,
    getBankStatements,
    createBankStatement,
    tagBankTransaction,
    getPayrollRecords,
    createPayrollRecord,
    exportTallyVouchers,
    exportGstr1Data,
    exportGstr3bData
} from '../controllers/accountingController.js';
import { protect } from '../middleware/authMiddleware.js';

// Transactions
router.route('/transactions')
    .post(protect, createTransaction)
    .get(protect, getTransactions);

router.route('/transactions/:id')
    .put(protect, updateTransaction)
    .delete(protect, deleteTransaction);

// Company Details
router.route('/company')
    .get(protect, getCompanyDetails)
    .post(protect, upsertCompanyDetails);

// Parties (Customers & Vendors Master)
router.route('/parties')
    .get(protect, getParties)
    .post(protect, createParty);

router.route('/parties/:id')
    .put(protect, updateParty)
    .delete(protect, deleteParty);

// Bank Statements & Manual Payment Tagging
router.route('/bank-statements')
    .get(protect, getBankStatements)
    .post(protect, createBankStatement);

router.route('/bank-statements/:id/tag')
    .post(protect, tagBankTransaction);

// Payroll & Form 16 / TDS
router.route('/payroll')
    .get(protect, getPayrollRecords)
    .post(protect, createPayrollRecord);

// Statutory & Tally Exports
router.route('/export/tally')
    .get(protect, exportTallyVouchers);

router.route('/export/gstr1')
    .get(protect, exportGstr1Data);

router.route('/export/gstr3b')
    .get(protect, exportGstr3bData);

export default router;
