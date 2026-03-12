import mongoose from 'mongoose';

const orderSchema = mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    clientName: {
        type: String,
        default: ''
    },
    email: {
        type: String,
        default: ''
    },
    phone: {
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
    paymentId: {
        type: String,
        required: true
    },
    razorpayOrderId: {
        type: String,
        default: ''
    },
    paymentSignature: {
        type: String,
        default: ''
    },
    paymentStatus: {
        type: String,
        enum: ['Pending', 'Paid', 'Failed', 'Refunded'],
        default: 'Paid'
    },
    status: {
        type: String,
        enum: ['Pending Documents', 'Documents Verified', 'Processing at Portal', 'Waiting for Clarification', 'Completed'],
        default: 'Pending Documents'
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
    clientDocuments: [{
        name: String,
        url: String, // Path to file
        uploadedAt: {
            type: Date,
            default: Date.now
        }
    }],
    adminDocuments: [{
        name: String,
        url: String, // Path to file
        uploadedAt: {
            type: Date,
            default: Date.now
        }
    }],
    finalCertificateUrl: {
        type: String,
        default: null
    },
    tasks: [{
        taskCode: {
            type: String,
            default: ''
        },
        title: String,
        status: {
            type: String,
            enum: ['Pending', 'In Progress', 'Completed'],
            default: 'Pending'
        },
        ownerRole: {
            type: String,
            default: ''
        },
        startTrigger: {
            type: String,
            default: ''
        },
        description: String,
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
        sortOrder: {
            type: Number,
            default: 0
        },
        subtasks: [{
            subTaskCode: {
                type: String,
                default: ''
            },
            title: String,
            isCompleted: {
                type: Boolean,
                default: false
            },
            status: {
                type: String,
                enum: ['Pending', 'In Progress', 'Completed'],
                default: 'Pending'
            },
            makerRole: {
                type: String,
                default: ''
            },
            checkerRole: {
                type: String,
                default: ''
            },
            assignedToMaker: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'User',
                default: null
            },
            assignedToChecker: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'User',
                default: null
            },
            duration: {
                type: String,
                default: ''
            },
            dependency: {
                type: String,
                default: ''
            },
            output: {
                type: String,
                default: ''
            }
        }],
        assignedTo: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        timeLogs: [{
            employee: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'User'
            },
            minutes: {
                type: Number,
                default: 0
            },
            notes: {
                type: String,
                default: ''
            },
            loggedAt: {
                type: Date,
                default: Date.now
            }
        }],
        totalMinutes: {
            type: Number,
            default: 0
        }
    }],
    invoices: [{
        invoiceNumber: String,
        amount: Number,
        status: {
            type: String,
            enum: ['Draft', 'Sent', 'Paid', 'Overdue'],
            default: 'Draft'
        },
        url: String,
        sentAt: Date,
        dueDate: Date,
        notes: String,
        createdAt: {
            type: Date,
            default: Date.now
        }
    }],
    customerRequirements: [{
        title: {
            type: String,
            required: true
        },
        sheetName: {
            type: String,
            default: ''
        },
        category: {
            type: String,
            enum: ['Detail', 'Document'],
            default: 'Document'
        },
        type: {
            type: String,
            enum: ['Detail', 'Document'],
            default: 'Document'
        },
        itemCode: {
            type: String,
            default: ''
        },
        inputType: {
            type: String,
            default: 'text'
        },
        placeholder: {
            type: String,
            default: ''
        },
        options: [{
            type: String
        }],
        required: {
            type: Boolean,
            default: true
        },
        status: {
            type: String,
            enum: ['Pending', 'Received', 'Verified'],
            default: 'Pending'
        },
        description: {
            type: String,
            default: ''
        },
        value: {
            type: String,
            default: ''
        },
        clientValue: {
            type: String,
            default: ''
        },
        clientNotes: {
            type: String,
            default: ''
        },
        documentUrl: {
            type: String,
            default: ''
        },
        uploadedDocumentUrl: {
            type: String,
            default: ''
        },
        uploadedDocumentName: {
            type: String,
            default: ''
        },
        isClientCompleted: {
            type: Boolean,
            default: false
        },
        isAdditional: {
            type: Boolean,
            default: false
        },
        lastSavedAt: {
            type: Date,
            default: null
        }
    }],
    checklists: [{
        title: String,
        isCompleted: {
            type: Boolean,
            default: false
        },
        documentUrl: String,
        required: {
            type: Boolean,
            default: true
        }
    }]
}, {
    timestamps: true
});

const Order = mongoose.model('Order', orderSchema);

export default Order;
