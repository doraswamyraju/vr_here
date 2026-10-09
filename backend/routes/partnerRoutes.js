import express from 'express';
const router = express.Router();
import { 
    getPartnerOrders, 
    createPartnerMasterOrder,
    getPartnerEarnings,
    getPartnerCustomers,
    addPartnerCustomer,
    requestPartnerPayout,
    getPartnerPayouts,
    adminGetPartnerPayouts,
    adminUpdatePartnerPayout,
    getPartnerProfile, 
    updatePartnerProfile,
    validateReferralCode 
} from '../controllers/partnerController.js';
import { protect, admin } from '../middleware/authMiddleware.js';

// Partner Orders & Master Orders
router.route('/orders')
    .get(protect, getPartnerOrders)
    .post(protect, createPartnerMasterOrder);

// Partner Earnings ledger
router.route('/earnings')
    .get(protect, getPartnerEarnings);

// Partner Customer Management
router.route('/customers')
    .get(protect, getPartnerCustomers)
    .post(protect, addPartnerCustomer);

// Partner Payout Requests
router.route('/payout-request')
    .post(protect, requestPartnerPayout);

router.route('/payouts')
    .get(protect, getPartnerPayouts);

// Partner Profile
router.route('/profile')
    .get(protect, getPartnerProfile)
    .put(protect, updatePartnerProfile);

// Admin Partner Payout Management
router.route('/admin/payouts')
    .get(protect, admin, adminGetPartnerPayouts);

router.route('/admin/payouts/:id')
    .put(protect, admin, adminUpdatePartnerPayout);

// Public route for validation
router.get('/validate/:code', validateReferralCode);

export default router;

