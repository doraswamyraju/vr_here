import express from 'express';
import {
    trackTelemetryLead,
    getLeads,
    getLeadStats,
    updateLead,
    deleteLead
} from '../controllers/leadController.js';
import { protect, protectOptional, admin, staff } from '../middleware/authMiddleware.js';

const router = express.Router();

// Telemetry endpoint - supports guest tracking and authenticated tracking from iOS / Android / Web
router.post('/telemetry', protectOptional, trackTelemetryLead);

// Staff management endpoints (Admin & Employee)
router.get('/', protect, staff, getLeads);
router.get('/stats', protect, staff, getLeadStats);
router.put('/:id', protect, staff, updateLead);
router.delete('/:id', protect, admin, deleteLead);

export default router;
