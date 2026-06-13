import asyncHandler from 'express-async-handler';
import IncomeTaxAssessment from '../models/IncomeTaxAssessment.js';

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
    const { clientName, pan, financialYear, assessmentYear, responses } = req.body;

    if (!clientName || !pan || !responses || !Array.isArray(responses)) {
        res.status(400);
        throw new Error('Please fill all required fields and provide responses.');
    }

    const assessment = await IncomeTaxAssessment.create({
        user: req.user._id,
        clientName,
        pan,
        financialYear,
        assessmentYear,
        responses,
        status: 'Pending'
    });

    res.status(201).json(assessment);
});

// @desc    Get all assessments (Admin gets all, Client gets their own)
// @route   GET /api/income-tax-assessment
// @access  Private
const getAssessments = asyncHandler(async (req, res) => {
    let assessments;

    if (req.user.role === 'admin') {
        assessments = await IncomeTaxAssessment.find({})
            .populate('user', 'name email')
            .sort({ createdAt: -1 });
    } else {
        assessments = await IncomeTaxAssessment.find({ user: req.user._id })
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
