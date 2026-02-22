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
    },
    tasks: [{
        title: String,
        status: {
            type: String,
            enum: ['Pending', 'In Progress', 'Completed'],
            default: 'Pending'
        },
        description: String,
        subtasks: [{
            title: String,
            isCompleted: {
                type: Boolean,
                default: false
            }
        }],
        assignedTo: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        }
    }],
    invoices: [{
        invoiceNumber: String,
        amount: Number,
        status: {
            type: String,
            enum: ['Draft', 'Sent', 'Paid', 'Overdue'],
            default: 'Draft'
        },
        url: String,
        createdAt: {
            type: Date,
            default: Date.now
        }
    }],
    checklists: [{
        title: String,
        isCompleted: {
            type: Boolean,
            default: false
        },
        documentUrl: String,
        required: {
            type: Boolean,
            default: true
        }
    }]
}, {
    timestamps: true
});

const Order = mongoose.model('Order', orderSchema);

export default Order;
