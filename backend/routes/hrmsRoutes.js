import express from 'express';
import { protect, admin } from '../middleware/authMiddleware.js';
import {
    applyLeave,
    getMyLeaves,
    getAdminLeaves,
    approveLeave,
    createHoliday,
    getHolidays,
    deleteHoliday,
    createNotice,
    getNotices,
    deleteNotice,
    getLiveStatus
} from '../controllers/hrmsController.js';

const router = express.Router();

// Leaves
router.route('/leaves')
    .post(protect, applyLeave);

router.route('/leaves/my')
    .get(protect, getMyLeaves);

router.route('/leaves/admin')
    .get(protect, admin, getAdminLeaves);

router.route('/leaves/:id/approve')
    .put(protect, admin, approveLeave);

// Holidays
router.route('/holidays')
    .post(protect, admin, createHoliday)
    .get(protect, getHolidays);

router.route('/holidays/:id')
    .delete(protect, admin, deleteHoliday);

// Notices
router.route('/notices')
    .post(protect, admin, createNotice)
    .get(protect, getNotices);

router.route('/notices/:id')
    .delete(protect, admin, deleteNotice);

// Live Dashboards
router.route('/admin/live-status')
    .get(protect, admin, getLiveStatus);

export default router;
