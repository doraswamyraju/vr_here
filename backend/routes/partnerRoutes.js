import express from 'express';
const router = express.Router();
import { 
    getPartnerOrders, 
    getPartnerProfile, 
    updatePartnerProfile 
} from '../controllers/partnerController.js';
import { protect } from '../middleware/authMiddleware.js';

router.route('/orders').get(protect, getPartnerOrders);
router.route('/profile')
    .get(protect, getPartnerProfile)
    .put(protect, updatePartnerProfile);

export default router;
