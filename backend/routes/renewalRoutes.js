import express from 'express';
import {
    getPendingRenewals,
    updateRenewalPrice,
    sendCustomerReminder,
    processRenewalPayment
} from '../controllers/renewalController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

router.get('/pending', protect, getPendingRenewals);
router.put('/:id/price', protect, updateRenewalPrice);
router.post('/:id/send-reminder', protect, sendCustomerReminder);
router.post('/:id/payment', processRenewalPayment);

export default router;
