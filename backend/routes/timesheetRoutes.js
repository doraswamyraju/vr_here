import express from 'express';
import {
    getMyTimesheet,
    submitTimesheet,
    getAdminTimesheets,
    reviewTimesheet,
    exportTimesheetsData
} from '../controllers/timesheetController.js';
import { protect, admin } from '../middleware/authMiddleware.js';

const router = express.Router();

router.route('/my-timesheet').get(protect, getMyTimesheet);
router.route('/submit').post(protect, submitTimesheet);
router.route('/admin/list').get(protect, getAdminTimesheets);
router.route('/admin/export').get(protect, admin, exportTimesheetsData);
router.route('/:id/review').put(protect, reviewTimesheet);

export default router;
