import mongoose from 'mongoose';

const timesheetEntrySchema = mongoose.Schema({
    date: {
        type: String, // 'YYYY-MM-DD'
        required: true
    },
    clockInAt: {
        type: Date,
        default: null
    },
    clockOutAt: {
        type: Date,
        default: null
    },
    grossShiftSeconds: {
        type: Number,
        default: 0
    },
    breakSeconds: {
        type: Number,
        default: 0
    },
    netWorkedSeconds: {
        type: Number,
        default: 0
    },
    taskWorkedSeconds: {
        type: Number,
        default: 0
    },
    idleSeconds: {
        type: Number,
        default: 0
    },
    overtimeSeconds: {
        type: Number,
        default: 0
    },
    ordersWorked: [{
        orderId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Order'
        },
        serviceName: String,
        taskTitle: String,
        minutes: Number
    }],
    status: {
        type: String,
        enum: ['Present', 'Half Day', 'Leave', 'Holiday', 'Absent', 'Weekend'],
        default: 'Present'
    },
    notes: {
        type: String,
        default: ''
    }
}, { _id: false });

const timesheetSchema = mongoose.Schema({
    employee: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    periodType: {
        type: String,
        enum: ['weekly', 'monthly', 'custom'],
        default: 'weekly'
    },
    startDate: {
        type: String, // 'YYYY-MM-DD'
        required: true
    },
    endDate: {
        type: String, // 'YYYY-MM-DD'
        required: true
    },
    entries: [timesheetEntrySchema],
    totalGrossSeconds: {
        type: Number,
        default: 0
    },
    totalBreakSeconds: {
        type: Number,
        default: 0
    },
    totalNetWorkedSeconds: {
        type: Number,
        default: 0
    },
    totalTaskSeconds: {
        type: Number,
        default: 0
    },
    totalIdleSeconds: {
        type: Number,
        default: 0
    },
    totalOvertimeSeconds: {
        type: Number,
        default: 0
    },
    productivityPercentage: {
        type: Number,
        default: 0
    },
    status: {
        type: String,
        enum: ['Draft', 'Submitted', 'Approved', 'Rejected'],
        default: 'Draft'
    },
    submittedAt: {
        type: Date,
        default: null
    },
    submissionNotes: {
        type: String,
        default: ''
    },
    reviewedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    reviewedAt: {
        type: Date,
        default: null
    },
    reviewNotes: {
        type: String,
        default: ''
    }
}, {
    timestamps: true
});

timesheetSchema.index({ employee: 1, startDate: 1, endDate: 1 }, { unique: true });
timesheetSchema.index({ status: 1 });
timesheetSchema.index({ startDate: -1 });

const Timesheet = mongoose.model('Timesheet', timesheetSchema);

export default Timesheet;
