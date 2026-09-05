import mongoose from 'mongoose';

const bankStatementSchema = new mongoose.Schema({
    clientUser: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    bankName: {
        type: String,
        required: true
    },
    accountNumber: {
        type: String,
        required: true
    },
    statementTitle: {
        type: String,
        default: 'Bank Statement'
    },
    fileName: {
        type: String,
        default: ''
    },
    fileUrl: {
        type: String,
        default: ''
    },
    isPasswordProtected: {
        type: Boolean,
        default: false
    },
    pdfPassword: {
        type: String,
        default: ''
    },
    transactions: [{
        date: {
            type: Date,
            required: true
        },
        description: {
            type: String,
            required: true
        },
        referenceNo: {
            type: String,
            default: ''
        },
        type: {
            type: String,
            enum: ['DEBIT', 'CREDIT'],
            required: true
        },
        amount: {
            type: Number,
            required: true
        },
        balance: {
            type: Number,
            default: 0
        },
        reconciliationStatus: {
            type: String,
            enum: ['UNRECONCILED', 'TAGGED', 'EXCLUDED'],
            default: 'UNRECONCILED'
        },
        taggedVoucher: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Transaction'
        },
        taggedCategory: {
            type: String,
            default: ''
        },
        notes: {
            type: String,
            default: ''
        }
    }]
}, { timestamps: true });

export default mongoose.model('BankStatement', bankStatementSchema);
