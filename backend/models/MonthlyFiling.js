import mongoose from 'mongoose';

const monthlyFilingSchema = new mongoose.Schema({
    clientId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    financialYear: {
        type: String,
        required: true,
        default: '2026-27'
    },
    month: {
        type: String,
        required: true // e.g. 'September 2026'
    },
    bookkeepingStatus: {
        type: String,
        enum: ['Pending', 'In Progress', 'Audited', 'Completed'],
        default: 'Pending'
    },
    bankReconStatus: {
        type: String,
        enum: ['Pending', 'Partially Reconciled', 'Reconciled'],
        default: 'Pending'
    },
    gstr1Status: {
        type: String,
        enum: ['Pending', 'Prepared', 'Filed'],
        default: 'Pending'
    },
    gstr1Arn: {
        type: String,
        default: ''
    },
    gstr1FilingDate: {
        type: Date
    },
    gstr3bStatus: {
        type: String,
        enum: ['Pending', 'Computed', 'Challan Generated', 'Filed'],
        default: 'Pending'
    },
    gstr3bArn: {
        type: String,
        default: ''
    },
    gstr3bFilingDate: {
        type: Date
    },
    tdsStatus: {
        type: String,
        enum: ['N/A', 'Pending', 'Challan Paid', 'Filed'],
        default: 'N/A'
    },
    tallyExportStatus: {
        type: String,
        enum: ['Pending', 'Exported'],
        default: 'Pending'
    },
    auditorNotes: {
        type: String,
        default: ''
    },
    assignedStaff: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    lastAuditedAt: {
        type: Date
    }
}, {
    timestamps: true
});

monthlyFilingSchema.index({ clientId: 1, month: 1 }, { unique: true });

const MonthlyFiling = mongoose.model('MonthlyFiling', monthlyFilingSchema);
export default MonthlyFiling;
