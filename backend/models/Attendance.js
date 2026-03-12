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
    }
}, {
    timestamps: true
});

const Attendance = mongoose.model('Attendance', attendanceSchema);

export default Attendance;
