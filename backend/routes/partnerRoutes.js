import express from 'express';
const router = express.Router();
import { getPartnerOrders } from '../controllers/partnerController.js';
import { protect } from '../middleware/authMiddleware.js';

router.route('/orders').get(protect, getPartnerOrders);

export default router;
