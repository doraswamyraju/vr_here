import express from 'express';
import {
    getAllCities,
    getCityByIdentifier,
    createCity,
    updateCity,
    deleteCity
} from '../controllers/cityController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

const adminOrStaff = (req, res, next) => {
    if (req.user && (req.user.role === 'admin' || req.user.role === 'employee')) {
        next();
    } else {
        res.status(403).json({ message: 'Not authorized. Requires Admin or Staff role.' });
    }
};

router.route('/')
    .get(getAllCities)
    .post(protect, adminOrStaff, createCity);

router.route('/:identifier')
    .get(getCityByIdentifier)
    .put(protect, adminOrStaff, updateCity)
    .delete(protect, adminOrStaff, deleteCity);

export default router;
