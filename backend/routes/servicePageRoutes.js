import express from 'express';
import {
    getAllServicePages,
    getServicePageById,
    updateServicePage,
    deleteServicePage
} from '../controllers/servicePageController.js';
import {
    getGscAuthUrl,
    gscCallback,
    getGscPerformance
} from '../controllers/gscController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

// Middleware to authorize both Admin and Staff (Employees)
const adminOrStaff = (req, res, next) => {
    if (req.user && (req.user.role === 'admin' || req.user.role === 'employee')) {
        next();
    } else {
        res.status(403);
        res.json({ message: 'Not authorized. Requires Admin or Staff role.' });
    }
};

// Google Search Console OAuth2 callback route (Must be registered before /:pageId to avoid clash)
router.route('/gsc/callback')
    .get(gscCallback);

router.route('/')
    .get(getAllServicePages);

router.route('/:pageId')
    .get(getServicePageById)
    .post(protect, adminOrStaff, updateServicePage)
    .put(protect, adminOrStaff, updateServicePage)
    .delete(protect, adminOrStaff, deleteServicePage);

router.route('/:pageId/gsc/auth')
    .get(protect, adminOrStaff, getGscAuthUrl);

router.route('/:pageId/gsc/performance')
    .get(protect, adminOrStaff, getGscPerformance);

export default router;
