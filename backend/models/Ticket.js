import mongoose from 'mongoose';

const ticketSchema = mongoose.Schema({
    ticketNumber: {
        type: String,
        unique: true,
        sparse: true
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User'
    },
    category: {
        type: String,
        enum: ['Technical', 'Service', 'Support'],
        required: true,
        default: 'Support'
    },
    subject: {
        type: String,
        required: true,
        trim: true
    },
    description: {
        type: String,
        required: true
    },
    status: {
        type: String,
        enum: ['Open', 'In Progress', 'Resolved', 'Closed'],
        default: 'Open'
    },
    priority: {
        type: String,
        enum: ['Low', 'Medium', 'High', 'Urgent'],
        default: 'Medium'
    },
    assignedTo: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    attachments: [{
        name: String,
        fileUrl: String,
        uploadedAt: {
            type: Date,
            default: Date.now
        }
    }],
    messages: [{
        sender: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        },
        message: {
            type: String,
            required: true
        },
        attachments: [{
            name: String,
            fileUrl: String
        }],
        createdAt: {
            type: Date,
            default: Date.now
        }
    }]
}, {
    timestamps: true
});

// Auto-generate unique sequential ticket numbers (e.g. VR-TCK-1001)
ticketSchema.pre('save', async function (next) {
    if (!this.ticketNumber) {
        const count = await mongoose.model('Ticket').countDocuments();
        this.ticketNumber = `VR-TCK-${1000 + count + 1}`;
    }
    next();
});

const Ticket = mongoose.model('Ticket', ticketSchema);

export default Ticket;
