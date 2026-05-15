import express from 'express';
import {
    clockIn,
    clockOut,
    getMyAttendanceStatus,
    getMyAttendanceLogs,
    getAdminAttendanceSummary,
    getEmployeeAnalysis
} from '../controllers/attendanceController.js';
import { protect, admin } from '../middleware/authMiddleware.js';

const router = express.Router();

router.route('/clock-in').post(protect, clockIn);
router.route('/clock-out').post(protect, clockOut);
router.route('/my-status').get(protect, getMyAttendanceStatus);
router.route('/my-logs').get(protect, getMyAttendanceLogs);
router.route('/admin/summary').get(protect, admin, getAdminAttendanceSummary);
router.route('/admin/employee/:id').get(protect, admin, getEmployeeAnalysis);

export default router;
