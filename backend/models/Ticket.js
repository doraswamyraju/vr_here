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
        try {
            const lastTicket = await mongoose.model('Ticket')
                .findOne({ ticketNumber: { $exists: true, $ne: null } })
                .sort({ createdAt: -1 });

            let nextNum = 1001;
            if (lastTicket && lastTicket.ticketNumber) {
                const match = String(lastTicket.ticketNumber).match(/\d+$/);
                if (match) {
                    nextNum = parseInt(match[0], 10) + 1;
                }
            }

            let candidate = `VR-TCK-${nextNum}`;
            while (await mongoose.model('Ticket').exists({ ticketNumber: candidate })) {
                nextNum++;
                candidate = `VR-TCK-${nextNum}`;
            }

            this.ticketNumber = candidate;
        } catch (err) {
            // Fallback to timestamp-based unique ticket number
            this.ticketNumber = `VR-TCK-${Date.now().toString().slice(-6)}`;
        }
    }
    next();
});

const Ticket = mongoose.model('Ticket', ticketSchema);

export default Ticket;
