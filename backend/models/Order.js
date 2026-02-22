import mongoose from 'mongoose';

const orderSchema = mongoose.Schema({
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
});

const Order = mongoose.model('Order', orderSchema);

export default Order;
