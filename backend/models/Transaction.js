import mongoose from 'mongoose';

const transactionSchema = new mongoose.Schema({
    clientUser: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    transactionType: {
        type: String,
        enum: ['Sales', 'Purchase', 'Income', 'Expense'],
        required: true
    },
    docNumber: {
        type: String,
        required: true
    },
    docDate: {
        type: Date,
        required: true
    },
    partyName: {
        type: String,
        required: true
    },
    partyGstin: {
        type: String,
        default: ''
    },
    placeOfSupply: {
        type: String, // State code / name (e.g. "37-Andhra Pradesh")
        required: true
    },
    items: [{
        description: { type: String, required: true },
        hsnSac: { type: String },
        qty: { type: Number, default: 1 },
        rate: { type: Number, required: true },
        taxableValue: { type: Number, required: true },
        gstRate: { type: Number, default: 18 },
        cgst: { type: Number, default: 0 },
        sgst: { type: Number, default: 0 },
        igst: { type: Number, default: 0 }
    }],
    summary: {
        totalTaxableValue: { type: Number, required: true },
        totalCgst: { type: Number, default: 0 },
        totalSgst: { type: Number, default: 0 },
        totalIgst: { type: Number, default: 0 },
        totalAmount: { type: Number, required: true }
    },
    itcEligibility: {
        type: String,
        enum: ['Inputs', 'Input Services', 'Capital Goods', 'Ineligible', 'N/A'],
        default: 'N/A'
    },
    status: {
        type: String,
        enum: ['Draft', 'Recorded', 'Verified', 'Flagged'],
        default: 'Recorded'
    },
    notes: String,
    attachmentUrl: String,
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }
}, { timestamps: true });

export default mongoose.model('Transaction', transactionSchema);
