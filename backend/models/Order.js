import mongoose from 'mongoose';

const orderSchema = mongoose.Schema({
    clientName: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
    },
    phone: {
        type: String,
        required: true,
    },
    serviceName: {
        type: String,
        required: true,
    },
    amount: {
        type: Number,
        required: true,
    },
    paymentStatus: {
        type: String,
        enum: ['Pending', 'Paid', 'Failed'],
        default: 'Pending',
    },
    razorpayPaymentId: {
        type: String,
    },
    razorpayOrderId: {
        type: String,
    },
    status: {
        type: String, // Internal processing status
        enum: ['New', 'In Progress', 'Completed', 'Cancelled'],
        default: 'New',
    },
    date: {
        type: Date,
        default: Date.now,
    },
}, {
    timestamps: true,
});

const Order = mongoose.model('Order', orderSchema);

export default Order;
