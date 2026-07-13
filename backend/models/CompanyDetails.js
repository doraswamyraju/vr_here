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
    bankDetails: {
        accountName: { type: String, default: '' },
        accountNumber: { type: String, default: '' },
        ifscCode: { type: String, default: '' },
        bankName: { type: String, default: '' }
    }
}, { timestamps: true });

export default mongoose.model('CompanyDetails', companyDetailsSchema);
