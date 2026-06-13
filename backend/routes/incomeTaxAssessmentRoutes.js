import express from 'express';
import {
    uploadAssessmentDocument,
    submitAssessment,
    getAssessments,
    getAssessmentById,
    updateAssessmentStatus
} from '../controllers/incomeTaxAssessmentController.js';
import { protect, protectOptional, admin } from '../middleware/authMiddleware.js';
import upload from '../middleware/uploadMiddleware.js';

const router = express.Router();

router.route('/')
    .post(protectOptional, submitAssessment)
    .get(protect, getAssessments);

router.route('/upload')
    .post(protectOptional, upload.single('document'), uploadAssessmentDocument);

router.route('/:id')
    .get(protect, getAssessmentById);

router.route('/:id/status')
    .put(protect, admin, updateAssessmentStatus);

export default router;
