import mongoose from 'mongoose';

const FinanceSchema = new mongoose.Schema({
    type: {
        type: String,
        enum: ['Estimate', 'Invoice', 'Payment', 'CreditNote', 'Proforma'],
        required: true
    },
    number: {
        type: String,
        required: true,
        unique: true
    },
    date: {
        type: Date,
        default: Date.now
    },
    dueDate: {
        type: Date
    },
    client: {
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        name: { type: String, required: true },
        address: { type: String },
        gstin: { type: String },
        phone: { type: String },
        email: { type: String }
    },
    items: [{
        description: { type: String, required: true },
        hsn: { type: String },
        qty: { type: Number, default: 1 },
        rate: { type: Number, required: true },
        taxRate: { type: Number, default: 18 },
        amount: { type: Number, required: true },
        cgst: { type: Number, default: 0 },
        sgst: { type: Number, default: 0 },
        igst: { type: Number, default: 0 }
    }],
    totals: {
        subtotal: { type: Number, required: true },
        cgst: { type: Number, default: 0 },
        sgst: { type: Number, default: 0 },
        igst: { type: Number, default: 0 },
        total: { type: Number, required: true }
    },
    status: {
        type: String,
        enum: ['Draft', 'Sent', 'Paid', 'Partially Paid', 'Cancelled', 'Closed', 'Accepted', 'Rejected'],
        default: 'Draft'
    },
    notes: { type: String },
    terms: { type: String },
    linkedOrder: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Order'
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }
}, { timestamps: true });

const Finance = mongoose.model('Finance', FinanceSchema);
export default Finance;
