import mongoose from 'mongoose';

const orderSchema = mongoose.Schema({
<<<<<<< Updated upstream
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
=======
    user: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User'
    },
    serviceName: {
        type: String,
        required: true
    },
    packageName: {
        type: String,
        required: true
    },
    price: {
        type: Number,
        required: true
    },
    paymentId: {
        type: String,
        required: true
    },
    status: {
        type: String,
        enum: ['Pending Documents', 'Documents Verified', 'Processing at Portal', 'Waiting for Clarification', 'Completed'],
        default: 'Pending Documents'
    },
    assignedEmployee: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    clientDocuments: [{
        name: String,
        url: String, // Path to file
        uploadedAt: {
            type: Date,
            default: Date.now
        }
    }],
    finalCertificateUrl: {
        type: String,
        default: null
    }
}, {
    timestamps: true
>>>>>>> Stashed changes
});

const Order = mongoose.model('Order', orderSchema);

export default Order;
