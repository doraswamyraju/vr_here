import mongoose from 'mongoose';

const PaymentSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
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
    currency: {
        type: String,
        default: 'INR'
    },
    paymentId: {
        type: String,
        required: true,
        unique: true
    },
    razorpayOrderId: {
        type: String,
        default: ''
    },
    signature: {
        type: String,
        default: ''
    },
    status: {
        type: String,
        enum: ['Pending', 'Completed', 'Failed', 'Refunded'],
        default: 'Pending'
    },
    method: {
        type: String,
        enum: ['Razorpay', 'NEFT', 'UPI', 'Cash'],
        required: true
    },
    customerName: {
        type: String,
        default: ''
    },
    email: {
        type: String,
        default: ''
    },
    phone: {
        type: String,
        default: ''
    },
    serviceName: {
        type: String,
        default: ''
    },
    packageName: {
        type: String,
        default: ''
    },
    invoiceUrl: {
        type: String
    }
}, { timestamps: true });

const Payment = mongoose.model('Payment', PaymentSchema);
export default Payment;
