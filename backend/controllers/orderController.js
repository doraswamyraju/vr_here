import asyncHandler from 'express-async-handler';
import Order from '../models/Order.js';

// @desc    Create new order
// @route   POST /api/orders
// @access  Private
const createOrder = asyncHandler(async (req, res) => {
    const { serviceName, packageName, price, paymentId } = req.body;

    if (!paymentId) {
        res.status(400);
        throw new Error('Payment ID is required');
    }

    const order = new Order({
        user: req.user._id,
        serviceName,
        packageName,
        price,
        paymentId,
    });

    const createdOrder = await order.save();
    res.status(201).json(createdOrder);
});

// @desc    Get all orders (Admin/Employee/Client based on role)
// @route   GET /api/orders
// @access  Private
const getOrders = asyncHandler(async (req, res) => {
    let orders;

    if (req.user.role === 'admin') {
        // Admin sees all
        orders = await Order.find({}).populate('user', 'name email').populate('assignedEmployee', 'name email');
    } else if (req.user.role === 'employee') {
        // Employee sees assigned
        orders = await Order.find({ assignedEmployee: req.user._id }).populate('user', 'name email');
    } else {
        // Client sees their own
        orders = await Order.find({ user: req.user._id });
    }

    res.json(orders);
});

// @desc    Get order by ID
// @route   GET /api/orders/:id
// @access  Private
const getOrderById = asyncHandler(async (req, res) => {
    const order = await Order.findById(req.params.id)
        .populate('user', 'name email phone')
        .populate('assignedEmployee', 'name email');

    if (order) {
        // Check permissions
        if (req.user.role === 'client' && order.user._id.toString() !== req.user._id.toString()) {
            res.status(403);
            throw new Error('Not authorized to view this order');
        }
        res.json(order);
    } else {
        res.status(404);
        throw new Error('Order not found');
    }
});

// @desc    Update order status (Employee/Admin)
// @route   PUT /api/orders/:id/status
// @access  Private
const updateOrderStatus = asyncHandler(async (req, res) => {
    const { status } = req.body;

    const order = await Order.findById(req.params.id);

    if (order) {
        order.status = status;
        const updatedOrder = await order.save();
        res.json(updatedOrder);
    } else {
        res.status(404);
        throw new Error('Order not found');
    }
});

// @desc    Assign order to employee (Admin only)
// @route   PUT /api/orders/:id/assign
// @access  Private/Admin
const assignOrder = asyncHandler(async (req, res) => {
    const { employeeId } = req.body;

    const order = await Order.findById(req.params.id);

    if (order) {
        order.assignedEmployee = employeeId;
        const updatedOrder = await order.save();
        res.json(updatedOrder);
    } else {
        res.status(404);
        throw new Error('Order not found');
    }
});

// @desc    Upload documents for an order
// @route   POST /api/orders/:id/documents
// @access  Private
const uploadDocument = asyncHandler(async (req, res) => {
    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (!req.file) {
        res.status(400);
        throw new Error('No file uploaded');
    }

    // Client uploading requirements
    if (req.user.role === 'client') {
        const docName = req.body.name || req.file.originalname;
        order.clientDocuments.push({
            name: docName,
            url: `/uploads/${req.file.filename}`
        });
    }
    // Employee/Admin uploading final certificate
    else if (req.user.role === 'employee' || req.user.role === 'admin') {
        order.finalCertificateUrl = `/uploads/${req.file.filename}`;
        order.status = 'Completed';
    }

    const updatedOrder = await order.save();
    res.json(updatedOrder);
});

// @desc    Add task to order
// @route   POST /api/orders/:id/tasks
// @access  Private
const addTask = asyncHandler(async (req, res) => {
    const { title, description } = req.body;
    const order = await Order.findById(req.params.id);

    if (order) {
        order.tasks.push({ title, description, status: 'Pending' });
        await order.save();
        res.status(201).json(order);
    } else {
        res.status(404);
        throw new Error('Order not found');
    }
});

// @desc    Update task status
// @route   PUT /api/orders/:id/tasks/:taskId
// @access  Private
const updateTask = asyncHandler(async (req, res) => {
    const { status, subtasks } = req.body;
    const order = await Order.findById(req.params.id);

    if (order) {
        const task = order.tasks.id(req.params.taskId);
        if (task) {
            if (status) task.status = status;
            if (subtasks) task.subtasks = subtasks;
            await order.save();
            res.json(order);
        } else {
            res.status(404);
            throw new Error('Task not found');
        }
    } else {
        res.status(404);
        throw new Error('Order not found');
    }
});

// @desc    Add checklist item
// @route   POST /api/orders/:id/checklists
// @access  Private
const addChecklistItem = asyncHandler(async (req, res) => {
    const { title, required } = req.body;
    const order = await Order.findById(req.params.id);

    if (order) {
        order.checklists.push({ title, required });
        await order.save();
        res.status(201).json(order);
    } else {
        res.status(404);
        throw new Error('Order not found');
    }
});

// @desc    Toggle checklist item completion
// @route   PUT /api/orders/:id/checklists/:itemId/toggle
// @access  Private
const toggleChecklistItem = asyncHandler(async (req, res) => {
    const order = await Order.findById(req.params.id);

    if (order) {
        const item = order.checklists.id(req.params.itemId);
        if (item) {
            item.isCompleted = !item.isCompleted;
            await order.save();
            res.json(order);
        } else {
            res.status(404);
            throw new Error('Checklist item not found');
        }
    } else {
        res.status(404);
        throw new Error('Order not found');
    }
});

// @desc    Update invoice status
// @route   PUT /api/orders/:id/invoices/:invoiceId/status
// @access  Private/Admin
const updateInvoiceStatus = asyncHandler(async (req, res) => {
    const { status } = req.body;
    const order = await Order.findById(req.params.id);

    if (order) {
        const invoice = order.invoices.id(req.params.invoiceId);
        if (invoice) {
            invoice.status = status;
            await order.save();
            res.json(order);
        } else {
            res.status(404);
            throw new Error('Invoice not found');
        }
    } else {
        res.status(404);
        throw new Error('Order not found');
    }
});

export {
    createOrder,
    getOrders,
    getOrderById,
    updateOrderStatus,
    assignOrder,
    uploadDocument,
    addTask,
    updateTask,
    addChecklistItem,
    toggleChecklistItem,
    addInvoice,
    updateInvoiceStatus
};


