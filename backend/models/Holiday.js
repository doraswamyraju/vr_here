import mongoose from 'mongoose';

const holidaySchema = mongoose.Schema({
    title: {
        type: String,
        required: true
    },
    date: {
        type: Date,
        required: true
    },
    description: {
        type: String,
        default: ''
    }
}, {
    timestamps: true
});

const Holiday = mongoose.model('Holiday', holidaySchema);

export default Holiday;
