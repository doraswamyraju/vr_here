import mongoose from 'mongoose';

const transactionSchema = new mongoose.Schema({
    clientUser: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    transactionType: {
        type: String,
        enum: ['Sales', 'Purchase', 'Income', 'Expense', 'CreditNote', 'DebitNote'],
        required: true
    },
    copyType: {
        type: String,
        enum: ['Original for Recipient', 'Duplicate for Supplier', 'Triplicate for Transporter'],
        default: 'Original for Recipient'
    },
    docNumber: {
        type: String,
        required: true
    },
    docDate: {
        type: Date,
        required: true
    },
    dueDate: {
        type: Date
    },
    paymentMode: {
        type: String,
        enum: ['Cash', 'Bank Transfer', 'UPI', 'Cheque', 'Credit'],
        default: 'Bank Transfer'
    },
    
    // Party Details (Bill To)
    partyName: {
        type: String,
        required: true
    },
    partyGstin: {
        type: String,
        default: ''
    },
    partyPan: {
        type: String,
        default: ''
    },
    partyAddress: {
        type: String,
        default: ''
    },
    partyState: {
        type: String,
        default: ''
    },
    partyPhone: {
        type: String,
        default: ''
    },
    partyEmail: {
        type: String,
        default: ''
    },
    placeOfSupply: {
        type: String, // State name / code e.g. "37-Andhra Pradesh"
        required: true
    },
    isInterstate: {
        type: Boolean,
        default: false
    },

    // Ship To (Consignee) Details
    shipToSameAsBilling: {
        type: Boolean,
        default: true
    },
    shipToName: { type: String, default: '' },
    shipToAddress: { type: String, default: '' },
    shipToGstin: { type: String, default: '' },
    shipToPan: { type: String, default: '' },
    shipToState: { type: String, default: '' },
    shipToMobile: { type: String, default: '' },
    shipToEmail: { type: String, default: '' },

    // Line items matching SALES INVOICE TEMPLATE.xlsx
    items: [{
        description: { type: String, required: true },
        hsnSac: { type: String, default: '' },
        qty: { type: Number, default: 1 },
        unit: { type: String, default: 'PCS' },
        rate: { type: Number, required: true },
        discPercent: { type: Number, default: 0 },
        taxableValue: { type: Number, required: true },
        gstRate: { type: Number, default: 18 },
        cgst: { type: Number, default: 0 },
        sgst: { type: Number, default: 0 },
        igst: { type: Number, default: 0 },
        total: { type: Number, required: true }
    }],

    // Totals & Summaries
    summary: {
        totalTaxableValue: { type: Number, required: true },
        totalCgst: { type: Number, default: 0 },
        totalSgst: { type: Number, default: 0 },
        totalIgst: { type: Number, default: 0 },
        roundOff: { type: Number, default: 0 },
        totalAmount: { type: Number, required: true },
        amountInWords: { type: String, default: '' }
    },

    itcEligibility: {
        type: String,
        enum: ['Inputs', 'Input Services', 'Capital Goods', 'Ineligible', 'N/A'],
        default: 'N/A'
    },
    paymentStatus: {
        type: String,
        enum: ['Unpaid', 'Partially Paid', 'Paid'],
        default: 'Unpaid'
    },
    paidAmount: {
        type: Number,
        default: 0
    },
    status: {
        type: String,
        enum: ['Draft', 'Recorded', 'Verified', 'Flagged'],
        default: 'Recorded'
    },
    auditorNotes: {
        type: String,
        default: ''
    },
    notes: {
        type: String,
        default: ''
    },
    attachmentUrl: {
        type: String,
        default: ''
    },
    termsAndConditions: {
        type: [String],
        default: [
            'Payment must be made as per the terms and due date mentioned in the invoice.',
            'Taxes: GST and other applicable taxes will be charged as per prevailing laws.',
            'Disputes: Any discrepancy in the invoice must be reported within 7 days of receipt.',
            "Jurisdiction: Any disputes shall be subject to the jurisdiction of the seller's place of business."
        ]
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }
}, { timestamps: true });

export default mongoose.model('Transaction', transactionSchema);
