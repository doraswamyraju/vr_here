import mongoose from 'mongoose';

const noticeSchema = mongoose.Schema({
    title: {
        type: String,
        required: true
    },
    message: {
        type: String,
        required: true
    },
    priority: {
        type: String,
        required: true,
        enum: ['Low', 'Medium', 'High'],
        default: 'Medium'
    },
    issuedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }
}, {
    timestamps: true
});

const Notice = mongoose.model('Notice', noticeSchema);

export default Notice;
