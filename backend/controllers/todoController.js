import asyncHandler from 'express-async-handler';
import Todo from '../models/Todo.js';

// @desc    Create a new todo
// @route   POST /api/todos
// @access  Private/Admin
const createTodo = asyncHandler(async (req, res) => {
    const { title, description, status, priority, assignedTo, orderId, dueDate } = req.body;

    const todo = new Todo({
        title,
        description,
        status: status || 'Pending',
        priority: priority || 'Medium',
        assignedTo: assignedTo || null,
        orderId: orderId || null,
        dueDate: dueDate || null,
        createdBy: req.user._id
    });

    const createdTodo = await todo.save();
    res.status(201).json(createdTodo);
});

// @desc    Get all todos
// @route   GET /api/todos
// @access  Private
const getTodos = asyncHandler(async (req, res) => {
    let query = {};

    // If client, they don't see todos usually, but for future proofing:
    if (req.user.role === 'client') {
        return res.status(403).json({ message: 'Not authorized to view todos' });
    }

    // If employee, see assigned todos OR todos linked to orders they are part of
    if (req.user.role === 'employee') {
        // 1. Get IDs of orders where employee is assigned
        const Order = (await import('../models/Order.js')).default;
        const employeeOrders = await Order.find({
            $or: [
                { assignedEmployee: req.user._id },
                { assignedMaker: req.user._id },
                { assignedChecker: req.user._id },
                { 'tasks.assignedTo': req.user._id },
                { 'tasks.assignedMaker': req.user._id },
                { 'tasks.assignedChecker': req.user._id },
                { 'tasks.subtasks.assignedToMaker': req.user._id },
                { 'tasks.subtasks.assignedToChecker': req.user._id }
            ]
        }).select('_id');
        
        const orderIds = employeeOrders.map(o => o._id);

        query = {
            $or: [
                { assignedTo: req.user._id }, // Explicitly assigned to todo
                { orderId: { $in: orderIds } }, // Linked to employee's orders
                { assignedTo: null, orderId: null } // Optionally allow employees to see unassigned standalone todos
            ]
        };
    }

    // If admin, see all
    if (req.user.role === 'admin') {
        query = {};
    }

    const todos = await Todo.find(query)
        .populate('assignedTo', 'name email role')
        .populate('orderId', 'serviceName clientName')
        .populate('createdBy', 'name role')
        .sort({ createdAt: -1 });

    res.json(todos);
});

// @desc    Update a todo
// @route   PUT /api/todos/:id
// @access  Private
const updateTodo = asyncHandler(async (req, res) => {
    const { title, description, status, priority, assignedTo, orderId, dueDate } = req.body;
    const todo = await Todo.findById(req.params.id);

    if (!todo) {
        res.status(404);
        throw new Error('Todo not found');
    }

    // Authorization check
    if (req.user.role !== 'admin' && String(todo.assignedTo) !== String(req.user._id)) {
        res.status(403);
        throw new Error('Not authorized to update this todo');
    }

    if (title !== undefined) todo.title = title;
    if (description !== undefined) todo.description = description;
    if (status !== undefined) todo.status = status;
    if (priority !== undefined) todo.priority = priority;
    if (assignedTo !== undefined) todo.assignedTo = assignedTo || null;
    if (orderId !== undefined) todo.orderId = orderId || null;
    if (dueDate !== undefined) todo.dueDate = dueDate || null;

    const updatedTodo = await todo.save();
    res.json(updatedTodo);
});

// @desc    Delete a todo
// @route   DELETE /api/todos/:id
// @access  Private/Admin
const deleteTodo = asyncHandler(async (req, res) => {
    const todo = await Todo.findById(req.params.id);

    if (!todo) {
        res.status(404);
        throw new Error('Todo not found');
    }

    await todo.deleteOne();
    res.json({ message: 'Todo removed' });
});

export {
    createTodo,
    getTodos,
    updateTodo,
    deleteTodo
};
