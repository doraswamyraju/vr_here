import mongoose from 'mongoose';

const leaveSchema = mongoose.Schema({
    employee: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    startDate: {
        type: Date,
        required: true
    },
    endDate: {
        type: Date,
        required: true
    },
    type: {
        type: String,
        required: true,
        enum: ['Sick', 'Casual', 'Paid', 'Unpaid'],
        default: 'Casual'
    },
    reason: {
        type: String,
        required: true
    },
    status: {
        type: String,
        required: true,
        enum: ['Pending', 'Approved', 'Rejected'],
        default: 'Pending'
    },
    approvedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    adminNotes: {
        type: String,
        default: ''
    }
}, {
    timestamps: true
});

const Leave = mongoose.model('Leave', leaveSchema);

export default Leave;
