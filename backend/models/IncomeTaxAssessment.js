import mongoose from 'mongoose';

const responseSchema = mongoose.Schema({
    itemId: {
        type: Number,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    section: {
        type: String,
        required: true
    },
    value: {
        type: String,
        enum: ['Yes', 'No', 'N/A'],
        required: true
    },
    remarks: {
        type: String,
        default: ''
    },
    documentUrl: {
        type: String,
        default: null
    },
    originalFileName: {
        type: String,
        default: null
    }
});

const incomeTaxAssessmentSchema = mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    clientName: {
        type: String,
        required: true,
        trim: true
    },
    pan: {
        type: String,
        required: true,
        uppercase: true,
        trim: true
    },
    financialYear: {
        type: String,
        required: true,
        default: '2025-26'
    },
    assessmentYear: {
        type: String,
        required: true,
        default: '2026-27'
    },
    responses: [responseSchema],
    status: {
        type: String,
        enum: ['Pending', 'In Progress', 'Approved', 'Rejected'],
        default: 'Pending'
    },
    notes: {
        type: String,
        default: ''
    }
}, {
    timestamps: true
});

const IncomeTaxAssessment = mongoose.model('IncomeTaxAssessment', incomeTaxAssessmentSchema);

export default IncomeTaxAssessment;
