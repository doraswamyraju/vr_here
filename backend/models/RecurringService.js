import mongoose from 'mongoose';

const recurringServiceSchema = mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    clientName: {
        type: String,
        default: ''
    },
    serviceName: {
        type: String,
        required: true
    },
    packageName: {
        type: String,
        required: true
    },
    price: {
        type: Number,
        required: true
    },
    frequency: {
        type: String,
        enum: ['Weekly', 'Monthly', 'Quarterly', 'Half-Yearly', 'Yearly'],
        default: 'Monthly'
    },
    dayOfMonth: {
        type: Number,
        default: 1
    },
    dayOfWeek: {
        type: Number,
        default: 1 // 1-7 (Monday-Sunday)
    },
    startDate: {
        type: Date,
        default: Date.now
    },
    nextRunDate: {
        type: Date,
        required: true
    },
    lastRunDate: {
        type: Date,
        default: null
    },
    isActive: {
        type: Boolean,
        default: true
    },
    assignedEmployee: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    assignedMaker: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    assignedChecker: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    // Templates for the generated order
    tasksTemplate: {
        type: Array,
        default: []
    },
    requirementsTemplate: {
        type: Array,
        default: []
    },
    checklistsTemplate: {
        type: Array,
        default: []
    },
    lastOrderId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Order',
        default: null
    }
}, {
    timestamps: true
});

const RecurringService = mongoose.model('RecurringService', recurringServiceSchema);

export default RecurringService;
