import mongoose from 'mongoose';

const userDocumentSchema = mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    docType: {
        type: String,
        required: true,
        enum: [
            'Aadhaar Card',
            'PAN Card',
            'GST Certificate',
            'Cancelled Cheque',
            'Business Address Proof',
            'Incorporation Certificate',
            'Other'
        ]
    },
    fileName: {
        type: String,
        required: true
    },
    gdriveFileId: {
        type: String,
        required: true
    },
    gdriveWebViewLink: {
        type: String,
        required: true
    },
    verificationStatus: {
        type: String,
        enum: ['Pending', 'Verified', 'Rejected'],
        default: 'Verified'
    },
    notes: {
        type: String,
        default: ''
    }
}, {
    timestamps: true
});

const UserDocument = mongoose.model('UserDocument', userDocumentSchema);

export default UserDocument;
