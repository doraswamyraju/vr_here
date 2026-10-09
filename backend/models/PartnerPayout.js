import mongoose from 'mongoose';

const partnerPayoutSchema = new mongoose.Schema({
    partner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    amount: {
        type: Number,
        required: true
    },
    status: {
        type: String,
        enum: ['Pending', 'Approved', 'Paid', 'Rejected'],
        default: 'Pending'
    },
    payoutMethod: {
        type: String,
        enum: ['UPI', 'Bank_Transfer'],
        default: 'UPI'
    },
    upiId: {
        type: String,
        default: ''
    },
    bankDetails: {
        accountName: { type: String, default: '' },
        accountNumber: { type: String, default: '' },
        ifscCode: { type: String, default: '' },
        bankName: { type: String, default: '' }
    },
    transactionRef: {
        type: String,
        default: ''
    },
    requestedAt: {
        type: Date,
        default: Date.now
    },
    paidAt: {
        type: Date
    },
    adminNotes: {
        type: String,
        default: ''
    }
}, { timestamps: true });

partnerPayoutSchema.index({ partner: 1, createdAt: -1 });

const PartnerPayout = mongoose.model('PartnerPayout', partnerPayoutSchema);
export default PartnerPayout;
