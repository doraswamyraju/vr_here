import mongoose from 'mongoose';

const todoSchema = mongoose.Schema({
    title: {
        type: String,
        required: true
    },
    description: {
        type: String,
        default: ''
    },
    status: {
        type: String,
        enum: ['Pending', 'In Progress', 'Completed', 'Dropped'],
        default: 'Pending'
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
    orderId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Order',
        default: null
    },
    dueDate: {
        type: Date,
        default: null
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }
}, {
    timestamps: true
});

todoSchema.index({ orderId: 1 });
todoSchema.index({ assignedTo: 1 });
todoSchema.index({ status: 1 });
todoSchema.index({ createdAt: -1 });

const Todo = mongoose.model('Todo', todoSchema);

export default Todo;
