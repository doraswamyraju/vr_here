import mongoose from 'mongoose';

const complianceSchema = mongoose.Schema({
    clientName: {
        type: String,
        required: true,
        trim: true
    },
    category: {
        type: String,
        required: true,
        enum: ['GST', 'MCA', 'TDS/TCS', 'Income Tax', 'Adv Tax', 'ESI', 'PF', 'PT', 'Notices', 'DIN KYC'],
        default: 'GST'
    },
    taskName: {
        type: String,
        required: true,
        trim: true
    },
    dueDate: {
        type: Date,
        required: true
    },
    status: {
        type: String,
        required: true,
        enum: ['Pending', 'Filed', 'Late', 'Missed'],
        default: 'Pending'
    },
    filedAt: {
        type: Date,
        default: null
    },
    periodMonth: {
        type: String,
        required: true,
        enum: ['APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC', 'JAN', 'FEB', 'MAR']
    },
    periodYear: {
        type: String,
        required: true
    },
    notes: {
        type: String,
        default: ''
    },
    assignedTo: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    }
}, {
    timestamps: true
});

const Compliance = mongoose.model('Compliance', complianceSchema);

export default Compliance;
