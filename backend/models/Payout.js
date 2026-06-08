import mongoose from 'mongoose';

const PayoutSchema = new mongoose.Schema({
    freelancer: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    order: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Order',
        required: true
    },
    amount: {
        type: Number,
        required: true
    },
    status: {
        type: String,
        enum: ['Pending Approval', 'Approved', 'Paid'],
        default: 'Pending Approval'
    },
    method: {
        type: String,
        enum: ['NEFT', 'IMPS', 'UPI', 'Cash', 'Other'],
        default: 'NEFT'
    },
    transactionRef: {
        type: String,
        default: ''
    },
    paidAt: {
        type: Date
    },
    notes: {
        type: String,
        default: ''
    }
}, { timestamps: true });

const Payout = mongoose.model('Payout', PayoutSchema);
export default Payout;
