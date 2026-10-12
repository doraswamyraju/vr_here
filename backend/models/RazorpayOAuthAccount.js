import mongoose from 'mongoose';

const razorpayOAuthAccountSchema = new mongoose.Schema({
    accountId: {
        type: String,
        required: true,
        unique: true
    },
    mode: {
        type: String,
        enum: ['live', 'test'],
        default: 'live'
    },
    accessToken: {
        type: String,
        required: true
    },
    refreshToken: {
        type: String
    },
    publicToken: {
        type: String
    },
    tokenType: {
        type: String,
        default: 'Bearer'
    },
    expiresIn: {
        type: Number
    },
    expiresAt: {
        type: Date
    },
    isActive: {
        type: Boolean,
        default: true
    },
    metadata: {
        type: mongoose.Schema.Types.Mixed
    }
}, { timestamps: true });

export default mongoose.model('RazorpayOAuthAccount', razorpayOAuthAccountSchema);
