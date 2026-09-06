import express from 'express';
import {
    getReferralStats,
    addReferralLead,
    validateCustomerReferralCode,
    requestUpiPayout,
    getAllReferralsAdmin
} from '../controllers/customerReferralController.js';
import { protect, admin } from '../middleware/authMiddleware.js';

const router = express.Router();

// Public validation
router.get('/validate/:code', validateCustomerReferralCode);

// Customer protected routes
router.get('/stats', protect, getReferralStats);
router.post('/lead', protect, addReferralLead);
router.post('/payout-request', protect, requestUpiPayout);

// Admin route
router.get('/admin/all', protect, admin, getAllReferralsAdmin);

export default router;
