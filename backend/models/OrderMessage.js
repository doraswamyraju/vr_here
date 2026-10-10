import mongoose from 'mongoose';

const orderMessageSchema = new mongoose.Schema({
    order: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Order',
        required: true,
        index: true
    },
    sender: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    senderName: {
        type: String,
        default: ''
    },
    senderRole: {
        type: String,
        enum: ['admin', 'employee', 'freelancer', 'client'],
        required: true
    },
    senderAvatar: {
        type: String,
        default: null
    },
    messageType: {
        type: String,
        enum: ['client', 'internal'],
        default: 'client',
        index: true
    },
    message: {
        type: String,
        default: ''
    },
    attachments: [{
        name: { type: String, default: '' },
        url: { type: String, default: '' },
        fileType: { type: String, default: '' },
        size: { type: Number, default: 0 }
    }],
    mentions: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    taskRef: {
        taskId: { type: String, default: '' },
        taskTitle: { type: String, default: '' }
    },
    readBy: [{
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        readAt: { type: Date, default: Date.now }
    }]
}, {
    timestamps: true
});

orderMessageSchema.index({ order: 1, createdAt: 1 });

const OrderMessage = mongoose.model('OrderMessage', orderMessageSchema);

export default OrderMessage;
