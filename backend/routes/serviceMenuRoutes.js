import express from 'express';
import {
    getHeaderMenuConfig,
    updateHeaderMenuConfig,
    uploadServiceOfferImage,
} from '../controllers/serviceMenuController.js';
import { protect, admin } from '../middleware/authMiddleware.js';
import upload from '../middleware/uploadMiddleware.js';

const router = express.Router();

router.route('/header-config')
    .get(getHeaderMenuConfig)
    .put(protect, admin, updateHeaderMenuConfig);

router.route('/header-config/:serviceId/offers/:offerId/image')
    .post(protect, admin, upload.single('image'), uploadServiceOfferImage);

export default router;
