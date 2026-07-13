import mongoose from 'mongoose';

const companyDetailsSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        unique: true
    },
    companyName: {
        type: String,
        required: true
    },
    tradeName: {
        type: String,
        default: ''
    },
    gstin: {
        type: String,
        required: true
    },
    address: {
        type: String,
        required: true
    },
    state: {
        type: String, // E.g., "Andhra Pradesh"
        required: true
    },
    phone: { type: String, default: '' },
    email: { type: String, default: '' },
    businessType: { type: String, default: '' },
    businessCategory: { type: String, default: '' },
    pincode: { type: String, default: '' },
    logo: { type: String, default: '' },
    signature: { type: String, default: '' },
    upiId: { type: String, default: '' },
    qrCode: { type: String, default: '' },
    bankDetails: {
        accountName: { type: String, default: '' },
        accountNumber: { type: String, default: '' },
        ifscCode: { type: String, default: '' },
        bankName: { type: String, default: '' }
    }
}, { timestamps: true });

export default mongoose.model('CompanyDetails', companyDetailsSchema);
