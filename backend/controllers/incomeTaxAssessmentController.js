import asyncHandler from 'express-async-handler';
import IncomeTaxAssessment from '../models/IncomeTaxAssessment.js';
import { logOrderActivity } from '../utils/activityLogger.js';

// @desc    Upload document for checklist item
// @route   POST /api/income-tax-assessment/upload
// @access  Private
const uploadAssessmentDocument = asyncHandler(async (req, res) => {
    if (!req.file) {
        res.status(400);
        throw new Error('No file uploaded');
    }

    const documentUrl = `/uploads/${req.file.filename}`;
    res.json({
        documentUrl,
        originalFileName: req.file.originalname
    });
});

// @desc    Submit new income tax assessment
// @route   POST /api/income-tax-assessment
// @access  Private
const submitAssessment = asyncHandler(async (req, res) => {
    const { clientName, pan, financialYear, assessmentYear, responses, orderId } = req.body;

    if (!clientName || !pan || !responses || !Array.isArray(responses)) {
        res.status(400);
        throw new Error('Please fill all required fields and provide responses.');
    }

    const assessment = await IncomeTaxAssessment.create({
        user: req.user ? req.user._id : null,
        orderId: orderId || null,
        clientName,
        pan,
        financialYear,
        assessmentYear,
        responses,
        status: 'Pending'
    });

    if (orderId) {
        try {
            await logOrderActivity(
                orderId,
                req.user ? req.user._id : orderId, // Actor fallback
                'REQUIREMENT_UPLOAD',
                `ITR Assessment Checklist submitted by client for PAN ${pan}`,
                { pan, clientName }
            );
        } catch (logErr) {
            console.error('Failed to log ITR assessment submission activity:', logErr.message);
        }
    }

    res.status(201).json(assessment);
});

// @desc    Get all assessments (Admin gets all, Client gets their own)
// @route   GET /api/income-tax-assessment
// @access  Private
const getAssessments = asyncHandler(async (req, res) => {
    let assessments;
    const query = {};

    if (req.query.orderId) {
        query.orderId = req.query.orderId;
    } else {
        query.orderId = null;
    }

    if (req.user.role === 'admin' || req.user.role === 'employee') {
        assessments = await IncomeTaxAssessment.find(query)
            .populate('user', 'name email')
            .sort({ createdAt: -1 });
    } else {
        query.user = req.user._id;
        assessments = await IncomeTaxAssessment.find(query)
            .sort({ createdAt: -1 });
    }

    res.json(assessments);
});

// @desc    Get assessment by ID
// @route   GET /api/income-tax-assessment/:id
// @access  Private
const getAssessmentById = asyncHandler(async (req, res) => {
    const assessment = await IncomeTaxAssessment.findById(req.params.id)
        .populate('user', 'name email');

    if (!assessment) {
        res.status(404);
        throw new Error('Assessment not found');
    }

    // Check permissions
    if (req.user.role !== 'admin' && assessment.user._id.toString() !== req.user._id.toString()) {
        res.status(403);
        throw new Error('Not authorized to view this assessment');
    }

    res.json(assessment);
});

// @desc    Update assessment status / notes
// @route   PUT /api/income-tax-assessment/:id/status
// @access  Private/Admin
const updateAssessmentStatus = asyncHandler(async (req, res) => {
    const { status, notes } = req.body;
    const assessment = await IncomeTaxAssessment.findById(req.params.id);

    if (!assessment) {
        res.status(404);
        throw new Error('Assessment not found');
    }

    if (status) assessment.status = status;
    if (notes !== undefined) assessment.notes = notes;

    const updated = await assessment.save();
    res.json(updated);
});

export {
    uploadAssessmentDocument,
    submitAssessment,
    getAssessments,
    getAssessmentById,
    updateAssessmentStatus
};
