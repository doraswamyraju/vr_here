import express from 'express';
import {
    getComplianceRecords,
    createComplianceRecord,
    updateComplianceStatus,
    deleteComplianceRecord,
    bulkGenerateCompliance
} from '../controllers/complianceController.js';
import { protect, canManageCompliance } from '../middleware/authMiddleware.js';

const router = express.Router();

router.route('/')
    .get(protect, canManageCompliance, getComplianceRecords)
    .post(protect, canManageCompliance, createComplianceRecord);

router.route('/bulk-generate')
    .post(protect, canManageCompliance, bulkGenerateCompliance);

router.route('/:id')
    .put(protect, canManageCompliance, updateComplianceStatus)
    .delete(protect, canManageCompliance, deleteComplianceRecord);

export default router;
