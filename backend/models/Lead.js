import mongoose from 'mongoose';

const noteSchema = new mongoose.Schema(
    {
        author: { type: String, required: true },
        authorRole: { type: String, default: 'employee' },
        text: { type: String, required: true },
        createdAt: { type: Date, default: Date.now }
    },
    { _id: true }
);

const leadSchema = new mongoose.Schema(
    {
        customerId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            default: null
        },
        customerName: {
            type: String,
            trim: true,
            default: 'Guest Prospect'
        },
        email: {
            type: String,
            trim: true,
            lowercase: true,
            default: ''
        },
        phone: {
            type: String,
            trim: true,
            default: ''
        },
        serviceId: {
            type: String,
            required: true,
            trim: true
        },
        serviceName: {
            type: String,
            required: true,
            trim: true
        },
        packageName: {
            type: String,
            trim: true,
            default: null
        },
        price: {
            type: Number,
            default: 0
        },
        // Lead Classification:
        // PAGE_VIEW: Category A (Browsing / Warm Lead)
        // PACKAGE_CLICK: Category B (High Intent / Hot Lead - Tapped price/checkout)
        category: {
            type: String,
            enum: ['PAGE_VIEW', 'PACKAGE_CLICK'],
            default: 'PAGE_VIEW'
        },
        source: {
            type: String,
            enum: ['ios', 'android', 'web'],
            default: 'web'
        },
        deviceInfo: {
            type: String,
            default: ''
        },
        assignedTo: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            default: null
        },
        status: {
            type: String,
            enum: ['NEW', 'CONTACTED', 'IN_PROGRESS', 'CONVERTED', 'LOST'],
            default: 'NEW'
        },
        priority: {
            type: String,
            enum: ['LOW', 'MEDIUM', 'HIGH', 'URGENT'],
            default: 'MEDIUM'
        },
        orderId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Order',
            default: null
        },
        notes: [noteSchema],
        lastActivityAt: {
            type: Date,
            default: Date.now
        }
    },
    {
        timestamps: true
    }
);

leadSchema.index({ category: 1, status: 1 });
leadSchema.index({ assignedTo: 1 });
leadSchema.index({ customerId: 1 });
leadSchema.index({ phone: 1 });
leadSchema.index({ email: 1 });
leadSchema.index({ createdAt: -1 });

const Lead = mongoose.model('Lead', leadSchema);
export default Lead;
