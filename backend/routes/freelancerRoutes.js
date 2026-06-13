import express from 'express';
const router = express.Router();
import {
    registerFreelancer,
    getBroadcastedOrders,
    claimOrder,
    clockIn,
    clockOut,
    getFreelancerOrders,
    getFreelancerLedger,
    adminBroadcastOrder,
    checkerApproveOrderPayout,
    adminApproveFreelancer,
    adminGetFreelancers,
    adminGetPayouts,
    adminPayFreelancer,
    adminGetLiveAttendance,
    adminReassignOrder,
    adminUpdateFreelancer,
    adminDeleteFreelancer
} from '../controllers/freelancerController.js';
import { protect, admin } from '../middleware/authMiddleware.js';

// Public Sign Up
router.post('/register', registerFreelancer);

// Freelancer Private Actions
router.route('/broadcasts').get(protect, getBroadcastedOrders);
router.route('/claim/:id').post(protect, claimOrder);
router.route('/clock-in/:id').post(protect, clockIn);
router.route('/clock-out/:id').post(protect, clockOut);
router.route('/orders').get(protect, getFreelancerOrders);
router.route('/ledger').get(protect, getFreelancerLedger);

// Admin & Checker Actions
router.route('/admin/broadcast/:orderId').put(protect, adminBroadcastOrder);
router.route('/admin/reassign/:orderId').post(protect, admin, adminReassignOrder);
router.route('/admin/approve-payout/:orderId').post(protect, checkerApproveOrderPayout);
router.route('/admin/approve-user/:userId').put(protect, admin, adminApproveFreelancer);
router.route('/admin/users').get(protect, admin, adminGetFreelancers);
router.route('/admin/users/:userId')
    .put(protect, admin, adminUpdateFreelancer)
    .delete(protect, admin, adminDeleteFreelancer);
router.route('/admin/payouts').get(protect, admin, adminGetPayouts);
router.route('/admin/pay/:payoutId').put(protect, admin, adminPayFreelancer);
router.route('/admin/live-attendance').get(protect, admin, adminGetLiveAttendance);

export default router;
