import express from 'express';
import {
    getComplianceRecords,
    createComplianceRecord,
    updateComplianceStatus,
    bulkGenerateCompliance
} from '../controllers/complianceController.js';
import { protect, admin } from '../middleware/authMiddleware.js';

const router = express.Router();

router.route('/')
    .get(protect, admin, getComplianceRecords)
    .post(protect, admin, createComplianceRecord);

router.route('/bulk-generate')
    .post(protect, admin, bulkGenerateCompliance);

router.route('/:id')
    .put(protect, admin, updateComplianceStatus);

export default router;
