import asyncHandler from 'express-async-handler';
import Order from '../models/Order.js';

const parseTasksFromText = (rawText) => {
    if (!rawText || typeof rawText !== 'string') return [];

    return rawText
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
            const [taskPart, subtaskPart] = line.split('>');
            const title = taskPart.trim();
            const subtasks = subtaskPart
                ? subtaskPart.split('|').map((item) => item.trim()).filter(Boolean).map((title) => ({ title, isCompleted: false }))
                : [];

            return {
                title,
                status: 'Pending',
                subtasks
            };
        })
        .filter((task) => task.title);
};

const parseRequirementsFromText = (rawText) => {
    if (!rawText || typeof rawText !== 'string') return [];

    return rawText
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
            const [prefix, rest] = line.includes(':') ? line.split(':') : ['Document', line];
            const normalizedPrefix = prefix.trim().toLowerCase();
            const type = normalizedPrefix === 'detail' ? 'Detail' : 'Document';
            const body = (rest || '').trim();
            const [title, description] = body.includes('|') ? body.split('|') : [body, ''];

            return {
                title: title.trim(),
                type,
                description: (description || '').trim(),
                required: true,
                status: 'Pending'
            };
        })
        .filter((item) => item.title);
};

// @desc    Create new order
// @route   POST /api/orders
// @access  Private
const createOrder = asyncHandler(async (req, res) => {
    const {
        serviceName,
        packageName,
        price,
        paymentId,
        razorpayOrderId = '',
        paymentSignature = '',
        paymentStatus = 'Paid',
        clientName = '',
        email = '',
        phone = ''
    } = req.body;

    if (!paymentId) {
        res.status(400);
        throw new Error('Payment ID is required');
    }

    const order = new Order({
        user: req.user._id,
        clientName: clientName || req.user.name || '',
        email: email || req.user.email || '',
        phone: phone || req.user.phone || '',
        serviceName,
        packageName,
        price,
        paymentId,
        razorpayOrderId,
        paymentSignature,
        paymentStatus,
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
        orders = await Order.find({})
            .populate('user', 'name email')
            .populate('assignedEmployee', 'name email')
            .populate('tasks.assignedTo', 'name email');
    } else if (req.user.role === 'employee') {
        // Employee sees order-level assignments and task-level assignments
        orders = await Order.find({
            $or: [
                { assignedEmployee: req.user._id },
                { 'tasks.assignedTo': req.user._id }
            ]
        })
            .populate('user', 'name email')
            .populate('assignedEmployee', 'name email')
            .populate('tasks.assignedTo', 'name email');
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
        .populate('assignedEmployee', 'name email')
        .populate('tasks.assignedTo', 'name email')
        .populate('tasks.timeLogs.employee', 'name email');

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
    // Employee/Admin uploading documents (final certificate or general admin/employee document)
    else if (req.user.role === 'employee' || req.user.role === 'admin') {
        if (req.body.isFinalCertificate === 'true' || req.body.isFinalCertificate === true) {
            order.finalCertificateUrl = `/uploads/${req.file.filename}`;
            order.status = 'Completed';
        } else {
            const docName = req.body.name || req.file.originalname;
            order.adminDocuments.push({
                name: docName,
                url: `/uploads/${req.file.filename}`
            });
        }
    }

    const updatedOrder = await order.save();
    res.json(updatedOrder);
});

// @desc    Add task to order
// @route   POST /api/orders/:id/tasks
// @access  Private
const addTask = asyncHandler(async (req, res) => {
    const { title, description, subtasks = [], assignedTo = null } = req.body;
    const order = await Order.findById(req.params.id);

    if (order) {
        const mappedSubtasks = Array.isArray(subtasks)
            ? subtasks.map((item) => ({
                title: typeof item === 'string' ? item : item?.title,
                isCompleted: Boolean(item?.isCompleted)
            })).filter((item) => item.title)
            : [];

        order.tasks.push({ title, description, status: 'Pending', subtasks: mappedSubtasks, assignedTo });
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
    const { status, subtasks, assignedTo, description } = req.body;
    const order = await Order.findById(req.params.id);

    if (order) {
        const task = order.tasks.id(req.params.taskId);
        if (task) {
            if (status) task.status = status;
            if (subtasks) task.subtasks = subtasks;
            if (assignedTo !== undefined) task.assignedTo = assignedTo || null;
            if (description !== undefined) task.description = description;
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

// @desc    Add invoice
// @route   POST /api/orders/:id/invoices
// @access  Private/Admin
const addInvoice = asyncHandler(async (req, res) => {
    const { invoiceNumber, amount, status = 'Draft', url = '', dueDate = null, notes = '' } = req.body;
    const order = await Order.findById(req.params.id);

    if (order) {
        order.invoices.push({
            invoiceNumber,
            amount,
            status,
            url,
            dueDate,
            notes,
            sentAt: status === 'Sent' ? new Date() : null
        });
        await order.save();
        res.status(201).json(order);
    } else {
        res.status(404);
        throw new Error('Order not found');
    }
});

// @desc    Add subtask to a task
// @route   POST /api/orders/:id/tasks/:taskId/subtasks
// @access  Private/Admin
const addSubtask = asyncHandler(async (req, res) => {
    const { title } = req.body;
    const order = await Order.findById(req.params.id);

    if (order) {
        const task = order.tasks.id(req.params.taskId);
        if (task) {
            task.subtasks.push({ title, isCompleted: false });
            await order.save();
            res.status(201).json(order);
        } else {
            res.status(404);
            throw new Error('Task not found');
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
            if (status === 'Sent' && !invoice.sentAt) {
                invoice.sentAt = new Date();
            }
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

// @desc    Update order package/commercial details (Admin)
// @route   PUT /api/orders/:id/commercials
// @access  Private/Admin
const updateOrderCommercials = asyncHandler(async (req, res) => {
    const { packageName, price, serviceName } = req.body;
    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (packageName !== undefined) order.packageName = packageName;
    if (serviceName !== undefined) order.serviceName = serviceName;
    if (price !== undefined) order.price = Number(price);

    const updatedOrder = await order.save();
    res.json(updatedOrder);
});

// @desc    Bulk import tasks/subtasks
// @route   POST /api/orders/:id/tasks/import
// @access  Private/Admin
const importTasks = asyncHandler(async (req, res) => {
    const { tasksText } = req.body;
    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    const parsedTasks = parseTasksFromText(tasksText);

    if (!parsedTasks.length) {
        res.status(400);
        throw new Error('No valid tasks found for import');
    }

    order.tasks.push(...parsedTasks);
    await order.save();
    res.status(201).json(order);
});

// @desc    Assign task to staff
// @route   PUT /api/orders/:id/tasks/:taskId/assign
// @access  Private/Admin
const assignTask = asyncHandler(async (req, res) => {
    const { employeeId } = req.body;
    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    const task = order.tasks.id(req.params.taskId);
    if (!task) {
        res.status(404);
        throw new Error('Task not found');
    }

    task.assignedTo = employeeId || null;
    await order.save();
    res.json(order);
});

// @desc    Track staff time against task
// @route   POST /api/orders/:id/tasks/:taskId/time-log
// @access  Private
const addTaskTimeLog = asyncHandler(async (req, res) => {
    const { minutes, notes = '' } = req.body;
    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    const task = order.tasks.id(req.params.taskId);
    if (!task) {
        res.status(404);
        throw new Error('Task not found');
    }

    const parsedMinutes = Number(minutes);
    if (!Number.isFinite(parsedMinutes) || parsedMinutes <= 0) {
        res.status(400);
        throw new Error('Minutes must be a positive number');
    }

    if (req.user.role === 'employee') {
        const taskOwner = task.assignedTo ? task.assignedTo.toString() : null;
        if (taskOwner && taskOwner !== req.user._id.toString()) {
            res.status(403);
            throw new Error('Not authorized to log time for this task');
        }
    }

    task.timeLogs.push({
        employee: req.user._id,
        minutes: parsedMinutes,
        notes
    });
    task.totalMinutes = (task.totalMinutes || 0) + parsedMinutes;

    await order.save();
    res.status(201).json(order);
});

// @desc    Bulk import customer details/documents requirements
// @route   POST /api/orders/:id/requirements/import
// @access  Private/Admin
const importRequirements = asyncHandler(async (req, res) => {
    const { requirementsText } = req.body;
    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    const parsedRequirements = parseRequirementsFromText(requirementsText);

    if (!parsedRequirements.length) {
        res.status(400);
        throw new Error('No valid requirements found for import');
    }

    order.customerRequirements.push(...parsedRequirements);
    await order.save();
    res.status(201).json(order);
});

// @desc    Update customer requirement status/details
// @route   PUT /api/orders/:id/requirements/:requirementId
// @access  Private
const updateRequirement = asyncHandler(async (req, res) => {
    const { status, value, documentUrl, description } = req.body;
    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    const requirement = order.customerRequirements.id(req.params.requirementId);
    if (!requirement) {
        res.status(404);
        throw new Error('Requirement not found');
    }

    if (status) requirement.status = status;
    if (value !== undefined) requirement.value = value;
    if (documentUrl !== undefined) requirement.documentUrl = documentUrl;
    if (description !== undefined) requirement.description = description;

    await order.save();
    res.json(order);
});

export {

    createOrder,
    getOrders,
    getOrderById,
    updateOrderStatus,
    assignOrder,
    updateOrderCommercials,
    uploadDocument,
    addTask,
    updateTask,
    addSubtask,
    addChecklistItem,
    toggleChecklistItem,
    addInvoice,
    updateInvoiceStatus,
    importTasks,
    assignTask,
    addTaskTimeLog,
    importRequirements,
    updateRequirement
};



