import mongoose from 'mongoose';

const partySchema = new mongoose.Schema({
    clientUser: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    partyType: {
        type: String,
        enum: ['Customer', 'Vendor', 'Both'],
        default: 'Customer'
    },
    name: {
        type: String,
        required: true
    },
    tradeName: {
        type: String,
        default: ''
    },
    gstin: {
        type: String,
        default: ''
    },
    pan: {
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
    billingAddress: {
        type: String,
        default: ''
    },
    shippingAddress: {
        type: String,
        default: ''
    },
    state: {
        type: String,
        default: 'Andhra Pradesh'
    },
    pincode: {
        type: String,
        default: ''
    },
    openingBalance: {
        type: Number,
        default: 0
    },
    creditPeriodDays: {
        type: Number,
        default: 30
    }
}, { timestamps: true });

export default mongoose.model('Party', partySchema);
