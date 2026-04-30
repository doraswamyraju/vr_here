import express from 'express';
const router = express.Router();
import { 
    getPartnerOrders, 
    getPartnerProfile, 
    updatePartnerProfile,
    validateReferralCode 
} from '../controllers/partnerController.js';
import { protect } from '../middleware/authMiddleware.js';

router.route('/orders').get(protect, getPartnerOrders);
router.route('/profile')
    .get(protect, getPartnerProfile)
    .put(protect, updatePartnerProfile);

// Public route for validation
router.get('/validate/:code', validateReferralCode);

export default router;
