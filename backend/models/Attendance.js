import mongoose from 'mongoose';

const attendanceSchema = mongoose.Schema({
    employee: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    clockInAt: {
        type: Date,
        required: true
    },
    clockOutAt: {
        type: Date,
        default: null
    },
    totalSeconds: {
        type: Number,
        default: 0
    },
    dateKey: {
        type: String,
        required: true
    },
    source: {
        type: String,
        default: 'employee-dashboard'
    },
    notes: {
        type: String,
        default: ''
    },
    accomplishments: {
        type: String,
        default: ''
    },
    breaks: [{
        breakType: {
            type: String,
            enum: ['Lunch', 'Tea/Coffee', 'Meeting', 'Personal', 'Other'],
            default: 'Lunch'
        },
        startedAt: {
            type: Date,
            required: true
        },
        endedAt: {
            type: Date,
            default: null
        },
        durationSeconds: {
            type: Number,
            default: 0
        },
        notes: {
            type: String,
            default: ''
        }
    }],
    totalBreakSeconds: {
        type: Number,
        default: 0
    },
    netWorkedSeconds: {
        type: Number,
        default: 0
    },
    clockOutReason: {
        type: String,
        enum: ['manual', 'auto-logout', 'auto-capped', 'admin-override'],
        default: 'manual'
    },
    isAutoClosed: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true
});

attendanceSchema.index({ employee: 1, clockInAt: -1 });
attendanceSchema.index({ employee: 1, dateKey: 1 });
attendanceSchema.index({ dateKey: 1 });
attendanceSchema.index({ clockOutAt: 1 });

const Attendance = mongoose.model('Attendance', attendanceSchema);

export default Attendance;
