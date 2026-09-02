import asyncHandler from 'express-async-handler';
import Order from '../models/Order.js';
import OrderHistory from '../models/OrderHistory.js';
import Todo from '../models/Todo.js';
import { createSubscriptionInternal } from './recurringController.js';
import { triggerNotification, notifyAdmins, notifyEmployee } from '../services/notificationService.js';
import { getOrderStatusUpdateTemplate, getClientSubmissionTemplate, getAdditionalRequirementTemplate } from '../utils/emailTemplates.js';
import User from '../models/User.js';
import { logOrderActivity } from '../utils/activityLogger.js';
import Razorpay from 'razorpay';
import sendEmail from '../utils/sendEmail.js';
import { generateAndEmailInvoice } from '../utils/invoiceHelper.js';
import { uploadBufferToDrive, getCustomerDriveFolder } from '../services/googleDriveService.js';



const ORDER_POPULATE = [
    { path: 'user', select: 'name email phone' },
    { path: 'assignedEmployee', select: 'name email role' },
    { path: 'assignedMaker', select: 'name email role' },
    { path: 'assignedChecker', select: 'name email role' },
    { path: 'assignedFreelancer', select: 'name email phone isClockedIn lastClockInTime' },
    { path: 'tasks.assignedTo', select: 'name email role' },
    { path: 'tasks.assignedMaker', select: 'name email role' },
    { path: 'tasks.assignedChecker', select: 'name email role' },
    { path: 'tasks.subtasks.assignedToMaker', select: 'name email role' },
    { path: 'tasks.subtasks.assignedToChecker', select: 'name email role' },
    { path: 'tasks.timeLogs.employee', select: 'name email role' }
];

const populateOrderQuery = (query) => {
    let enriched = query;
    ORDER_POPULATE.forEach((populate) => {
        enriched = enriched.populate(populate.path, populate.select);
    });
    return enriched;
};

const parseTasksFromText = (rawText) => {
    if (!rawText || typeof rawText !== 'string') return [];

    return rawText
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line, index) => {
            const [taskPart, subtaskPart] = line.split('>');
            const title = taskPart.trim();
            const subtasks = subtaskPart
                ? subtaskPart.split('|').map((item) => item.trim()).filter(Boolean).map((subtaskTitle) => ({
                    title: subtaskTitle,
                    isCompleted: false,
                    status: 'Pending'
                }))
                : [];

            return {
                title,
                status: 'Pending',
                subtasks,
                sortOrder: index + 1
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
                category: type,
                type,
                description: (description || '').trim(),
                required: true,
                status: 'Pending',
                isClientCompleted: false,
                inputType: type === 'Detail' ? 'text' : 'file'
            };
        })
        .filter((item) => item.title);
};

const sanitizeTaskCode = (value) => String(value || '').trim();

const pickByKeyHint = (row, hints = []) => {
    const keys = Object.keys(row || {});
    const lowered = keys.map((key) => ({ key, lower: key.toLowerCase() }));

    for (const hint of hints) {
        const found = lowered.find((item) => item.lower.includes(String(hint || '').toLowerCase()));
        if (found) {
            const value = row[found.key];
            if (value !== undefined && value !== null && String(value).trim()) {
                return value;
            }
        }
    }

    return '';
};

const pickFirstUsefulText = (row) => {
    const values = Object.values(row || {})
        .map((value) => String(value || '').trim())
        .filter(Boolean);
    return values[0] || '';
};

const mapStructuredTasks = ({ parentTasks = [], subTasks = [], makerId = null, checkerId = null }) => {
    const normalizeTaskStatus = (value) => {
        const raw = String(value || '').trim().toLowerCase();
        if (!raw || raw === 'not started' || raw === 'todo' || raw === 'to do') return 'Pending';
        if (raw === 'in progress' || raw === 'ongoing' || raw === 'wip') return 'In Progress';
        if (raw === 'completed' || raw === 'complete' || raw === 'done') return 'Completed';
        return 'Pending';
    };

    const tasks = [];
    const byCode = new Map();

    parentTasks.forEach((row, idx) => {
        const taskCode = sanitizeTaskCode(row.taskCode || row['Task Code']);
        const task = {
            taskCode,
            title: String(row.mainTask || row.title || row['Main Task'] || '').trim(),
            description: String(row.description || row['Description'] || '').trim(),
            ownerRole: String(row.owner || row.ownerRole || row['Owner (Checker)'] || '').trim(),
            startTrigger: String(row.startTrigger || row['Start Trigger'] || '').trim(),
            status: normalizeTaskStatus(row.status || row['Status'] || 'Pending'),
            assignedMaker: makerId || null,
            assignedChecker: checkerId || null,
            sortOrder: idx + 1,
            subtasks: []
        };

        if (task.title) {
            tasks.push(task);
            if (taskCode) {
                byCode.set(taskCode, task);
            }
        }
    });

    subTasks.forEach((row) => {
        const taskCode = sanitizeTaskCode(row.taskCode || row['Task Code']);
        const parentTask = byCode.get(taskCode) || tasks.find((item) => item.taskCode === taskCode);
        if (!parentTask) return;

        const subtask = {
            subTaskCode: sanitizeTaskCode(row.subTaskCode || row['Sub Task Code']),
            title: String(row.subTaskName || row.title || row['Sub Task Name'] || '').trim(),
            makerRole: String(row.makerRole || row['Maker Role'] || '').trim(),
            checkerRole: String(row.checkerRole || row['Checker Role'] || '').trim(),
            duration: String(row.duration || row['Duration'] || '').trim(),
            dependency: String(row.dependency || row['Dependency'] || '').trim(),
            output: String(row.output || row['Output'] || '').trim(),
            status: 'Pending',
            isCompleted: false,
            assignedToMaker: makerId || null,
            assignedToChecker: checkerId || null
        };

        if (subtask.title) {
            parentTask.subtasks.push(subtask);
        }
    });

    return tasks;
};

const mapStructuredRequirements = ({ detailRows = [], documentRows = [] }) => {
    const details = detailRows
        .map((row) => {
            const title = String(
                row.title ||
                row.fieldName ||
                row.name ||
                row['Field Name'] ||
                row['Detail'] ||
                pickByKeyHint(row, ['field', 'detail', 'title', 'name', 'information']) ||
                pickFirstUsefulText(row)
            ).trim();
            if (!title) return null;
            const requiredRaw = row.required ?? row.mandatory ?? row['Required'];
            const required = typeof requiredRaw === 'boolean'
                ? requiredRaw
                : !['no', 'false', 'optional', '0'].includes(String(requiredRaw || 'yes').trim().toLowerCase());

            return {
                title,
                itemCode: String(row.code || row.itemCode || row['Code'] || pickByKeyHint(row, ['code', 'id']) || '').trim(),
                sheetName: String(row.sheetName || 'Client Details').trim(),
                category: 'Detail',
                type: 'Detail',
                inputType: String(row.inputType || row['Input Type'] || pickByKeyHint(row, ['input', 'type']) || 'text').trim().toLowerCase(),
                placeholder: String(row.placeholder || row['Placeholder'] || pickByKeyHint(row, ['placeholder', 'example', 'sample']) || '').trim(),
                description: String(row.description || row.instructions || row['Description'] || pickByKeyHint(row, ['description', 'instruction', 'remark', 'note']) || '').trim(),
                required,
                status: 'Pending',
                isClientCompleted: false,
                options: Array.isArray(row.options)
                    ? row.options
                    : String(row.options || row['Options'] || pickByKeyHint(row, ['option', 'values']) || '')
                        .split('|')
                        .map((item) => item.trim())
                        .filter(Boolean)
            };
        })
        .filter(Boolean);

    const documents = documentRows
        .map((row) => {
            const title = String(
                row.title ||
                row.documentName ||
                row.name ||
                row['Document Name'] ||
                row['Document'] ||
                pickByKeyHint(row, ['document', 'proof', 'attachment', 'title', 'name']) ||
                pickFirstUsefulText(row)
            ).trim();
            if (!title) return null;
            const requiredRaw = row.required ?? row.mandatory ?? row['Required'];
            const required = typeof requiredRaw === 'boolean'
                ? requiredRaw
                : !['no', 'false', 'optional', '0'].includes(String(requiredRaw || 'yes').trim().toLowerCase());

            return {
                title,
                itemCode: String(row.code || row.itemCode || row['Code'] || pickByKeyHint(row, ['code', 'id']) || '').trim(),
                sheetName: String(row.sheetName || 'Documents Required').trim(),
                category: 'Document',
                type: 'Document',
                inputType: 'file',
                placeholder: String(row.placeholder || row['Placeholder'] || pickByKeyHint(row, ['placeholder', 'example', 'sample']) || '').trim(),
                description: String(row.description || row.instructions || row['Description'] || pickByKeyHint(row, ['description', 'instruction', 'remark', 'note']) || '').trim(),
                required,
                status: 'Pending',
                isClientCompleted: false
            };
        })
        .filter(Boolean);

    return [...details, ...documents];
};

const canAccessOrder = (user, order) => {
    const normalizeId = (value) => {
        if (!value) return '';
        if (value._id) return value._id.toString();
        return value.toString();
    };

    if (!user || !order) return false;
    if (user.role === 'admin') return true;

    if (user.role === 'client') {
        return normalizeId(order.user) === user._id.toString();
    }

    if (user.role === 'employee' || user.role === 'freelancer') {
        const id = user._id.toString();
        if (normalizeId(order.assignedEmployee) === id) return true;
        if (normalizeId(order.assignedFreelancer) === id) return true;
        if (normalizeId(order.assignedMaker) === id) return true;
        if (normalizeId(order.assignedChecker) === id) return true;

        const foundTask = (order.tasks || []).some((task) => {
            const taskAssigned = [task.assignedTo, task.assignedMaker, task.assignedChecker]
                .filter(Boolean)
                .some((assignedId) => normalizeId(assignedId) === id);
            if (taskAssigned) return true;

            return (task.subtasks || []).some((subtask) => [subtask.assignedToMaker, subtask.assignedToChecker]
                .filter(Boolean)
                .some((assignedId) => normalizeId(assignedId) === id));
        });

        return foundTask;
    }

    return false;
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

    if (!paymentId && req.user.role !== 'admin') {
        res.status(400);
        throw new Error('Payment ID is required');
    }

    const order = new Order({
        user: req.body.userId || req.user._id, // Allow admin to specify customer
        clientName: clientName || (req.body.userId ? '' : (req.user.name || '')), // Use provided name or user name
        email: email || (req.body.userId ? '' : (req.user.email || '')),
        phone: phone || (req.body.userId ? '' : (req.user.phone || '')),
        serviceName,
        packageName,
        price,
        paymentId: paymentId || `MANUAL_BY_ADMIN_${Date.now()}`,
        razorpayOrderId,
        paymentSignature,
        paymentStatus: paymentId ? paymentStatus : 'Pending', // Default to Pending if manual (to allow Razorpay link generation)
        assignedEmployee: req.body.assignedEmployee || null
    });

    const createdOrder = await order.save();

    // Auto-generate primary invoice for manual orders
    try {
        await generateAndEmailInvoice(createdOrder, price, {
            status: createdOrder.paymentStatus === 'Paid' ? 'Paid' : 'Sent',
            actorId: req.user._id,
            notes: 'Primary Invoice generated on order registration.'
        });
    } catch (invErr) {
        console.error('Failed to generate initial invoice on order creation:', invErr.message);
    }

    // Trigger customer in-app notification & email for admin-created manual orders
    if (createdOrder.user) {
        const isITR = serviceName?.toLowerCase().includes('income tax') || packageName?.toLowerCase().includes('itr');
        const customMessage = isITR
            ? `An order for ${serviceName} (${packageName}) has been registered on your behalf. Please complete your ITR Checklist questionnaire at https://vrhere.in/income-tax-assessment?orderId=${createdOrder._id} and review your raised invoice to proceed.`
            : `An order for ${serviceName} (${packageName}) has been registered on your behalf. Our team is commencing work.`;

        await triggerNotification({
            userId: createdOrder.user,
            title: 'New Compliance Order Registered',
            message: customMessage,
            type: 'Order',
            emailOpts: {
                send: true,
                subject: `New Project Started: ${serviceName} - VR HERE`
            }
        });
    }

    // Trigger assigned employee notification if any
    if (createdOrder.assignedEmployee) {
        await notifyEmployee({
            employeeId: createdOrder.assignedEmployee,
            title: 'New Project Assigned',
            message: `You have been assigned as the specialist for client ${createdOrder.clientName}'s project: ${serviceName} (${packageName}).`,
            type: 'Order',
            email: true
        });
    }

    // Notify all admins of the manually placed order
    await notifyAdmins({
        title: 'New Order Placed (Manual)',
        message: `Admin ${req.user.name} has manually registered an order for client ${createdOrder.clientName}: ${serviceName} (${packageName}) priced at INR ${Number(price).toLocaleString('en-IN')}.`,
        type: 'Order',
        email: true
    });

    // If isRecurring is true, also create a Subscription record
    if (req.body.isRecurring) {
        try {
            await createSubscriptionInternal({
                userId: createdOrder.user,
                clientName: createdOrder.clientName,
                serviceName: createdOrder.serviceName,
                packageName: createdOrder.packageName,
                price: createdOrder.price,
                frequency: req.body.frequency || 'Monthly',
                dayOfMonth: req.body.dayOfMonth || 1,
                dayOfWeek: req.body.dayOfWeek || 1,
                startDate: new Date(),
                assignedEmployee: createdOrder.assignedEmployee,
                assignedMaker: createdOrder.assignedMaker,
                assignedChecker: createdOrder.assignedChecker
            });
        } catch (subErr) {
            console.error('Error creating linked subscription:', subErr.message);
            // We don't fail the order creation if subscription fails, but we log it
        }
    }

    res.status(201).json(createdOrder);
});

// @desc    Get all orders (Admin/Employee/Client based on role)
// @route   GET /api/orders
// @access  Private
const getOrders = asyncHandler(async (req, res) => {
    let orderQuery;

    if (req.user.role === 'admin') {
        orderQuery = Order.find({});
    } else if (req.user.role === 'employee' || req.user.role === 'freelancer') {
        orderQuery = Order.find({
            $or: [
                { assignedEmployee: req.user._id },
                { assignedFreelancer: req.user._id },
                { assignedMaker: req.user._id },
                { assignedChecker: req.user._id },
                { 'tasks.assignedTo': req.user._id },
                { 'tasks.assignedMaker': req.user._id },
                { 'tasks.assignedChecker': req.user._id },
                { 'tasks.subtasks.assignedToMaker': req.user._id },
                { 'tasks.subtasks.assignedToChecker': req.user._id }
            ]
        });
    } else {
        orderQuery = Order.find({ user: req.user._id });
    }

    const orders = await populateOrderQuery(orderQuery.sort({ createdAt: -1 }));

    // Add linked todos for EACH order in the list
    const ordersWithTodos = await Promise.all(orders.map(async (order) => {
        const orderObj = order.toObject();
        const linkedTodos = await Todo.find({ orderId: order._id }).populate('assignedTo', 'name email role');
        orderObj.linkedTodos = linkedTodos;
        return orderObj;
    }));

    res.json(ordersWithTodos);
});

// @desc    Get order by ID
// @route   GET /api/orders/:id
// @access  Private
const getOrderById = asyncHandler(async (req, res) => {
    const order = await populateOrderQuery(Order.findById(req.params.id));

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (!canAccessOrder(req.user, order)) {
        res.status(403);
        throw new Error('Not authorized to view this order');
    }

    // Add linked todos to the response
    const linkedTodos = await Todo.find({ orderId: order._id }).populate('assignedTo', 'name email role');
    const orderObj = order.toObject();
    orderObj.linkedTodos = linkedTodos;

    res.json(orderObj);
});

// @desc    Update order status (Employee/Admin)
// @route   PUT /api/orders/:id/status
// @access  Private
const updateOrderStatus = asyncHandler(async (req, res) => {
    const { status } = req.body;
    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (!canAccessOrder(req.user, order)) {
        res.status(403);
        throw new Error('Not authorized to update this order');
    }

    const oldStatus = order.status;
    order.status = status;
    const updatedOrder = await order.save();

    if (oldStatus !== status) {
        await logOrderActivity(
            order._id,
            req.user._id,
            'STATUS_CHANGE',
            `Updated order status from "${oldStatus}" to "${status}"`,
            { oldStatus, newStatus: status }
        );
    }

    // Trigger notification if the status has changed
    if (oldStatus !== status && order.user) {
        const clientEmailHtml = getOrderStatusUpdateTemplate({
            clientName: order.clientName || 'Customer',
            serviceName: order.serviceName,
            packageName: order.packageName,
            status: status
        });

        await triggerNotification({
            userId: order.user,
            title: `Project Status Updated: ${status}`,
            message: `The status of your project "${order.serviceName}" has been updated to "${status}".`,
            type: 'Order',
            emailOpts: {
                send: true,
                subject: `Project Update: ${order.serviceName} is now ${status}`,
                html: clientEmailHtml
            }
        });

        // Notify admins about the progress
        await notifyAdmins({
            title: 'Order Status Updated',
            message: `Project "${order.serviceName}" for client "${order.clientName}" was updated from "${oldStatus}" to "${status}" by ${req.user.name}.`,
            type: 'Order',
            email: false
        });
    }

    res.json(updatedOrder);
});

// @desc    Update order core details (Admin only)
// @route   PUT /api/orders/:id
// @access  Private/Admin
const updateOrder = asyncHandler(async (req, res) => {
    const { serviceName, packageName, price, status } = req.body;
    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (serviceName !== undefined) order.serviceName = String(serviceName).trim();
    if (packageName !== undefined) order.packageName = String(packageName).trim();
    if (price !== undefined) order.price = Number(price);
    if (status !== undefined) order.status = status;

    const updatedOrder = await order.save();
    res.json(updatedOrder);
});

// @desc    Delete order (Admin only)
// @route   DELETE /api/orders/:id
// @access  Private/Admin
const deleteOrder = asyncHandler(async (req, res) => {
    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    await order.deleteOne();
    res.json({ message: 'Order deleted successfully' });
});

// @desc    Assign order to employee / maker / checker (Admin only)
// @route   PUT /api/orders/:id/assign
// @access  Private/Admin
const assignOrder = asyncHandler(async (req, res) => {
    const { employeeId, makerId, checkerId } = req.body;
    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    const oldEmployee = order.assignedEmployee?.toString();
    const oldMaker = order.assignedMaker?.toString();
    const oldChecker = order.assignedChecker?.toString();

    if (employeeId !== undefined) order.assignedEmployee = employeeId || null;
    if (makerId !== undefined) order.assignedMaker = makerId || null;
    if (checkerId !== undefined) order.assignedChecker = checkerId || null;

    const updatedOrder = await order.save();

    // Trigger notifications if assignments changed
    if (employeeId && oldEmployee !== employeeId) {
        await notifyEmployee({
            employeeId,
            title: 'New Order Assigned',
            message: `You have been assigned to client ${order.clientName}'s compliance project: ${order.serviceName} (${order.packageName}).`,
            type: 'Order',
            email: true
        });
    }

    if (makerId && oldMaker !== makerId) {
        await notifyEmployee({
            employeeId: makerId,
            title: 'New Order Assigned (Maker)',
            message: `You have been assigned as the Maker for client ${order.clientName}'s project: ${order.serviceName} (${order.packageName}).`,
            type: 'Order',
            email: true
        });
    }

    if (checkerId && oldChecker !== checkerId) {
        await notifyEmployee({
            employeeId: checkerId,
            title: 'New Order Assigned (Checker)',
            message: `You have been assigned as the Checker for client ${order.clientName}'s project: ${order.serviceName} (${order.packageName}).`,
            type: 'Order',
            email: true
        });
    }

    res.json(updatedOrder);
});

// @desc    Update order package/commercial details (Admin)
// @route   PUT /api/orders/:id/commercials
// @access  Private/Admin
const updateOrderCommercials = asyncHandler(async (req, res) => {
    const { packageName, price, serviceName, makerId, checkerId } = req.body;
    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (packageName !== undefined) order.packageName = packageName;
    if (serviceName !== undefined) order.serviceName = serviceName;
    if (price !== undefined) order.price = Number(price);
    if (makerId !== undefined) order.assignedMaker = makerId || null;
    if (checkerId !== undefined) order.assignedChecker = checkerId || null;

    const updatedOrder = await order.save();
    res.json(updatedOrder);
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

    if (!canAccessOrder(req.user, order)) {
        res.status(403);
        throw new Error('Not authorized to upload documents for this order');
    }

    if (!req.file) {
        res.status(400);
        throw new Error('No file uploaded');
    }

    // 1. Get/Create Order folder hierarchy in Google Drive (with safe fallback)
    let orderFolderId = null;
    try {
        const driveHierarchy = await getCustomerDriveFolder({
            clientName: order.clientName || req.user.name,
            orderId: order._id,
            orderDate: order.createdAt
        });
        orderFolderId = driveHierarchy ? driveHierarchy.orderFolderId : null;
    } catch (driveHierErr) {
        console.error('[OrderUpload] Google Drive folder hierarchy warning:', driveHierErr.message);
    }

    // 2. Stream memory buffer directly to Google Drive
    let documentUrl = `/uploads/${req.file.originalname}`;
    try {
        if (req.file.buffer) {
            const driveUpload = await uploadBufferToDrive({
                fileBuffer: req.file.buffer,
                mimeType: req.file.mimetype,
                fileName: `${Date.now()}_${req.file.originalname}`,
                parentFolderId: orderFolderId
            });
            documentUrl = driveUpload.webViewLink;
        }
    } catch (driveErr) {
        console.error('[OrderUpload] Fallback due to Google Drive upload error:', driveErr.message);
    }

    if (req.user.role === 'client' || req.user.role === 'customer') {
        const docName = req.body.name || req.file.originalname;
        if (!order.clientDocuments) {
            order.clientDocuments = [];
        }
        order.clientDocuments.push({
            name: docName,
            url: documentUrl
        });

        if (req.body.requirementId && Array.isArray(order.customerRequirements)) {
            const requirement = order.customerRequirements.find(r => String(r._id) === String(req.body.requirementId)) 
                || (typeof order.customerRequirements.id === 'function' ? order.customerRequirements.id(req.body.requirementId) : null);
            if (requirement) {
                if (!requirement.documents) {
                    requirement.documents = [];
                }
                requirement.documents.push({
                    name: docName,
                    url: documentUrl
                });
                requirement.uploadedDocumentUrl = documentUrl;
                requirement.uploadedDocumentName = docName;
                requirement.documentUrl = documentUrl;
                requirement.status = 'Received';
                requirement.isClientCompleted = true;
                requirement.lastSavedAt = new Date();
            }
        }
    } else if (req.user.role === 'employee' || req.user.role === 'admin' || req.user.role === 'freelancer') {
        if (req.body.isFinalCertificate === 'true' || req.body.isFinalCertificate === true) {
            order.finalCertificateUrl = documentUrl;
            order.status = 'Completed';
        } else {
            const docName = req.body.name || req.file.originalname;
            if (!order.adminDocuments) {
                order.adminDocuments = [];
            }
            order.adminDocuments.push({
                name: docName,
                url: documentUrl
            });
        }
    }

    const updatedOrder = await order.save();

    try {
        const uploadedDocName = req.body.name || (req.file ? req.file.originalname : 'Document');
        await logOrderActivity(
            order._id,
            req.user._id,
            'DOCUMENT_UPLOAD',
            `Uploaded document "${uploadedDocName}"`,
            { documentName: uploadedDocName, url: documentUrl, isFinal: req.body.isFinalCertificate === 'true' }
        );

        // Trigger Notifications after successful upload and save
        if (req.user.role === 'client' || req.user.role === 'customer') {
            const docName = req.body.name || (req.file ? req.file.originalname : 'Document');
            const message = `Client ${order.clientName} has uploaded document "${docName}" for project ${order.serviceName}.`;
            
            if (order.assignedEmployee) {
                const employee = await User.findById(order.assignedEmployee);
                if (employee) {
                    const staffEmailHtml = getClientSubmissionTemplate({
                        staffName: employee.name,
                        clientName: order.clientName,
                        serviceName: order.serviceName
                    });
                    await triggerNotification({
                        userId: order.assignedEmployee,
                        title: 'Client Document Uploaded',
                        message,
                        type: 'Order',
                        emailOpts: {
                            send: true,
                            subject: `Action Required: Client Uploaded Doc - ${order.serviceName}`,
                            html: staffEmailHtml
                        }
                    });
                }
            }
            
            await notifyAdmins({
                title: 'Client Document Uploaded',
                message,
                type: 'Order',
                email: false
            });
        } else {
            // Uploaded by staff/admin
            if (req.body.isFinalCertificate === 'true' || req.body.isFinalCertificate === true) {
                // Notify client of completion
                if (order.user) {
                    const clientEmailHtml = getOrderStatusUpdateTemplate({
                        clientName: order.clientName || 'Customer',
                        serviceName: order.serviceName,
                        packageName: order.packageName,
                        status: 'Completed'
                    });
                    await triggerNotification({
                        userId: order.user,
                        title: 'Compliance Project Completed! 🎉',
                        message: `Congratulations! Your project for "${order.serviceName}" is now fully completed. You can download your final certificate inside your dashboard vault.`,
                        type: 'Order',
                        emailOpts: {
                            send: true,
                            subject: `Project Completed: ${order.serviceName} - VR HERE`,
                            html: clientEmailHtml
                        }
                    });
                }
            } else {
                // Notify client of regular admin document
                if (order.user) {
                    const docName = req.body.name || (req.file ? req.file.originalname : 'Document');
                    await triggerNotification({
                        userId: order.user,
                        title: 'New Document Uploaded by specialist',
                        message: `A new document "${docName}" has been uploaded to your project: "${order.serviceName}".`,
                        type: 'Order',
                        emailOpts: {
                            send: true,
                            subject: `New Document Added: ${order.serviceName}`
                        }
                    });
                }
            }
        }
    } catch (notifErr) {
        console.error('[OrderUpload] Non-blocking notification/log warning:', notifErr.message);
    }

    res.json(updatedOrder);
});

// @desc    Add task to order
// @route   POST /api/orders/:id/tasks
// @access  Private
const addTask = asyncHandler(async (req, res) => {
    const {
        title,
        description,
        taskCode = '',
        ownerRole = '',
        startTrigger = '',
        assignedTo = null,
        assignedMaker = null,
        assignedChecker = null,
        subtasks = []
    } = req.body;

    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    const mappedSubtasks = Array.isArray(subtasks)
        ? subtasks
            .map((item) => ({
                title: typeof item === 'string' ? item : item?.title,
                subTaskCode: item?.subTaskCode || '',
                makerRole: item?.makerRole || '',
                checkerRole: item?.checkerRole || '',
                duration: item?.duration || '',
                dependency: item?.dependency || '',
                output: item?.output || '',
                assignedToMaker: item?.assignedToMaker || null,
                assignedToChecker: item?.assignedToChecker || null,
                status: item?.status || 'Pending',
                isCompleted: Boolean(item?.isCompleted)
            }))
            .filter((item) => item.title)
        : [];

    order.tasks.push({
        title,
        description,
        taskCode,
        ownerRole,
        startTrigger,
        status: 'Pending',
        assignedTo,
        assignedMaker,
        assignedChecker,
        subtasks: mappedSubtasks,
        sortOrder: (order.tasks || []).length + 1
    });

    await order.save();
    res.status(201).json(order);
});

// @desc    Update task status/details/assignment
// @route   PUT /api/orders/:id/tasks/:taskId
// @access  Private
const updateTask = asyncHandler(async (req, res) => {
    const { status, subtasks, assignedTo, assignedMaker, assignedChecker, description, title } = req.body;
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

    if (status) task.status = status;
    if (subtasks) task.subtasks = subtasks;
    if (assignedTo !== undefined) task.assignedTo = assignedTo || null;
    if (assignedMaker !== undefined) task.assignedMaker = assignedMaker || null;
    if (assignedChecker !== undefined) task.assignedChecker = assignedChecker || null;
    if (description !== undefined) task.description = description;
    if (title !== undefined) task.title = title;

    await order.save();
    res.json(order);
});

// @desc    Assign task to staff
// @route   PUT /api/orders/:id/tasks/:taskId/assign
// @access  Private/Admin
const assignTask = asyncHandler(async (req, res) => {
    const { employeeId, makerId, checkerId } = req.body;
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

    if (employeeId !== undefined) task.assignedTo = employeeId || null;
    if (makerId !== undefined) task.assignedMaker = makerId || null;
    if (checkerId !== undefined) task.assignedChecker = checkerId || null;

    await order.save();
    res.json(order);
});

// @desc    Add subtask to a task
// @route   POST /api/orders/:id/tasks/:taskId/subtasks
// @access  Private/Admin
const addSubtask = asyncHandler(async (req, res) => {
    const {
        title,
        subTaskCode = '',
        makerRole = '',
        checkerRole = '',
        duration = '',
        dependency = '',
        output = '',
        assignedToMaker = null,
        assignedToChecker = null
    } = req.body;

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

    task.subtasks.push({
        title,
        subTaskCode,
        makerRole,
        checkerRole,
        duration,
        dependency,
        output,
        assignedToMaker,
        assignedToChecker,
        status: 'Pending',
        isCompleted: false
    });

    await order.save();
    res.status(201).json(order);
});

// @desc    Update subtask assignment/status
// @route   PUT /api/orders/:id/tasks/:taskId/subtasks/:subtaskId
// @access  Private
const updateSubtask = asyncHandler(async (req, res) => {
    const { title, status, isCompleted, makerId, checkerId } = req.body;
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

    const subtask = task.subtasks.id(req.params.subtaskId);
    if (!subtask) {
        res.status(404);
        throw new Error('Subtask not found');
    }

    if (title !== undefined) subtask.title = title;
    if (status !== undefined) subtask.status = status;
    if (isCompleted !== undefined) {
        subtask.isCompleted = Boolean(isCompleted);
        if (Boolean(isCompleted)) {
            subtask.status = 'Completed';
        }
    }
    if (makerId !== undefined) subtask.assignedToMaker = makerId || null;
    if (checkerId !== undefined) subtask.assignedToChecker = checkerId || null;

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

    if (req.user.role === 'employee' || req.user.role === 'freelancer') {
        const taskOwners = [task.assignedTo, task.assignedMaker, task.assignedChecker]
            .filter(Boolean)
            .map((id) => id.toString());

        if (taskOwners.length && !taskOwners.includes(req.user._id.toString())) {
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

// @desc    Bulk import tasks/subtasks
// @route   POST /api/orders/:id/tasks/import
// @access  Private/Admin
const importTasks = asyncHandler(async (req, res) => {
    const {
        tasksText,
        parentTasks = [],
        subTasks = [],
        replaceExisting = true,
        makerId,
        checkerId
    } = req.body;

    const order = await Order.findById(req.params.id);
    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    let parsedTasks = [];

    if (Array.isArray(parentTasks) && parentTasks.length) {
        parsedTasks = mapStructuredTasks({
            parentTasks,
            subTasks: Array.isArray(subTasks) ? subTasks : [],
            makerId: makerId || order.assignedMaker || null,
            checkerId: checkerId || order.assignedChecker || null
        });
    } else {
        parsedTasks = parseTasksFromText(tasksText);
    }

    if (!parsedTasks.length) {
        res.status(400);
        throw new Error('No valid tasks found for import');
    }

    if (replaceExisting) {
        order.tasks = parsedTasks;
    } else {
        order.tasks.push(...parsedTasks);
    }

    await order.save();
    res.status(201).json(order);
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
        await logOrderActivity(
            order._id,
            req.user._id,
            'INVOICE_CREATE',
            `Invoice ${invoiceNumber} created with status "${status}"`,
            { invoiceNumber, amount, status }
        );
        res.status(201).json(order);
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
            const oldStatus = invoice.status;
            invoice.status = status;
            if (status === 'Sent' && !invoice.sentAt) {
                invoice.sentAt = new Date();
            }
            await order.save();
            await logOrderActivity(
                order._id,
                req.user._id,
                'INVOICE_STATUS_UPDATE',
                `Invoice ${invoice.invoiceNumber} status updated from "${oldStatus}" to "${status}"`,
                { invoiceNumber: invoice.invoiceNumber, oldStatus, newStatus: status }
            );
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

// @desc    Bulk import customer details/documents requirements
// @route   POST /api/orders/:id/requirements/import
// @access  Private/Admin
const importRequirements = asyncHandler(async (req, res) => {
    const {
        requirementsText,
        detailRows = [],
        documentRows = [],
        replaceExisting = true
    } = req.body;

    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    let parsedRequirements = [];

    if ((Array.isArray(detailRows) && detailRows.length) || (Array.isArray(documentRows) && documentRows.length)) {
        parsedRequirements = mapStructuredRequirements({
            detailRows: Array.isArray(detailRows) ? detailRows : [],
            documentRows: Array.isArray(documentRows) ? documentRows : []
        });
    } else {
        parsedRequirements = parseRequirementsFromText(requirementsText);
    }

    if (!parsedRequirements.length) {
        res.status(400);
        throw new Error('No valid requirements found for import');
    }

    if (replaceExisting) {
        order.customerRequirements = parsedRequirements;
    } else {
        order.customerRequirements.push(...parsedRequirements);
    }

    await order.save();
    res.status(201).json(order);
});

// @desc    Update customer requirement status/details (supports client partial save)
// @route   PUT /api/orders/:id/requirements/:requirementId
// @access  Private
const updateRequirement = asyncHandler(async (req, res) => {
    const {
        status,
        value,
        clientValue,
        clientNotes,
        documentUrl,
        uploadedDocumentUrl,
        uploadedDocumentName,
        description,
        isClientCompleted
    } = req.body;

    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (!canAccessOrder(req.user, order)) {
        res.status(403);
        throw new Error('Not authorized to update this requirement');
    }

    const requirement = order.customerRequirements.id(req.params.requirementId);
    if (!requirement) {
        res.status(404);
        throw new Error('Requirement not found');
    }

    const oldStatus = requirement.status;
    const oldClientCompleted = requirement.isClientCompleted;

    if (req.user.role === 'client') {
        if (value !== undefined || clientValue !== undefined) {
            const resolvedValue = clientValue !== undefined ? clientValue : value;
            requirement.clientValue = resolvedValue;
            requirement.value = resolvedValue;
        }
        if (clientNotes !== undefined) requirement.clientNotes = clientNotes;
        if (uploadedDocumentUrl !== undefined) {
            requirement.uploadedDocumentUrl = uploadedDocumentUrl;
            requirement.documentUrl = uploadedDocumentUrl;
        }
        if (uploadedDocumentName !== undefined) requirement.uploadedDocumentName = uploadedDocumentName;
        if (isClientCompleted !== undefined) requirement.isClientCompleted = Boolean(isClientCompleted);
        requirement.status = requirement.isClientCompleted ? 'Received' : requirement.status;
        requirement.lastSavedAt = new Date();
    } else {
        if (status !== undefined) requirement.status = status;
        if (value !== undefined) {
            requirement.value = value;
            requirement.clientValue = value;
        }
        if (documentUrl !== undefined) {
            requirement.documentUrl = documentUrl;
            requirement.uploadedDocumentUrl = documentUrl;
        }
        if (description !== undefined) requirement.description = description;
        if (isClientCompleted !== undefined) requirement.isClientCompleted = Boolean(isClientCompleted);
        if (clientNotes !== undefined) requirement.clientNotes = clientNotes;
    }

    await order.save();

    await logOrderActivity(
        order._id,
        req.user._id,
        'REQUIREMENT_UPDATE',
        `Requirement "${requirement.title}" updated (Status: "${requirement.status}")`,
        { requirementId: requirement._id, title: requirement.title, status: requirement.status }
    );

    // Trigger Notifications after save
    if (req.user.role === 'client') {
        if ((requirement.isClientCompleted && !oldClientCompleted) || requirement.status === 'Received') {
            const message = `Client ${order.clientName} has submitted details/documents for requirement "${requirement.title}" under project ${order.serviceName}.`;
            if (order.assignedEmployee) {
                const employee = await User.findById(order.assignedEmployee);
                if (employee) {
                    const staffEmailHtml = getClientSubmissionTemplate({
                        staffName: employee.name,
                        clientName: order.clientName,
                        serviceName: order.serviceName
                    });
                    await triggerNotification({
                        userId: order.assignedEmployee,
                        title: 'Client Submission Logged',
                        message,
                        type: 'Order',
                        emailOpts: {
                            send: true,
                            subject: `Action Required: Client Submitted details - ${order.serviceName}`,
                            html: staffEmailHtml
                        }
                    });
                }
            }
            await notifyAdmins({
                title: 'Client Submission Logged',
                message,
                type: 'Order',
                email: false
            });
        }
    } else {
        // Staff/Admin updated requirement status
        if (status && oldStatus !== status) {
            if (order.user) {
                await triggerNotification({
                    userId: order.user,
                    title: `Requirement Verified: ${requirement.title}`,
                    message: `Your submission for requirement "${requirement.title}" in project "${order.serviceName}" has been updated to status "${status}".`,
                    type: 'Order',
                    emailOpts: {
                        send: true,
                        subject: `Requirement Status Update: ${requirement.title} is ${status}`
                    }
                });
            }
        }
    }

    res.json(order);
});

// @desc    Add a single additional requirement (query)
// @route   POST /api/orders/:id/requirements
// @access  Private
const addRequirement = asyncHandler(async (req, res) => {
    const { title, description, type } = req.body;
    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (!canAccessOrder(req.user, order)) {
        res.status(403);
        throw new Error('Not authorized to add a requirement to this order');
    }

    const newReq = {
        title: title || 'Additional Requirement',
        description: description || '',
        type: type === 'Document' ? 'Document' : 'Detail',
        category: type === 'Document' ? 'Document' : 'Detail',
        inputType: type === 'Document' ? 'file' : 'text',
        required: true,
        status: 'Pending',
        isClientCompleted: false,
        isAdditional: true
    };

    order.customerRequirements.push(newReq);
    await order.save();

    // Trigger Notification to client
    if (order.user) {
        try {
            const clientUser = await User.findById(order.user);
            const clientName = clientUser ? clientUser.name : (order.clientName || 'Valued Customer');
            const emailHtml = getAdditionalRequirementTemplate({
                clientName,
                serviceName: order.serviceName,
                requirementTitle: newReq.title,
                requirementDescription: newReq.description,
                type: newReq.type
            });

            await triggerNotification({
                userId: order.user,
                title: `New Information Requested: ${newReq.title}`,
                message: `We require additional ${newReq.type === 'Document' ? 'document upload' : 'text details'} for "${newReq.title}" under your order for "${order.serviceName}".`,
                type: 'Order',
                emailOpts: {
                    send: true,
                    subject: `Action Required: Additional Information Requested for ${order.serviceName}`,
                    html: emailHtml
                }
            });
        } catch (notifErr) {
            console.error('Error triggering notification for added requirement:', notifErr);
        }
    }

    res.status(201).json(order);
});

// @desc    Delete a customer requirement
// @route   DELETE /api/orders/:id/requirements/:requirementId
// @access  Private/Admin
const deleteRequirement = asyncHandler(async (req, res) => {
    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (!canAccessOrder(req.user, order)) {
        res.status(403);
        throw new Error('Not authorized to delete a requirement from this order');
    }

    order.customerRequirements.pull(req.params.requirementId);
    await order.save();

    res.json(order);
});

// @desc    Get history logs for an order
// @route   GET /api/orders/:id/history
// @access  Private
const getOrderHistory = asyncHandler(async (req, res) => {
    const order = await Order.findById(req.params.id);
    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }
    if (!canAccessOrder(req.user, order)) {
        res.status(403);
        throw new Error('Not authorized to view history for this order');
    }
    const history = await OrderHistory.find({ order: req.params.id })
        .populate('user', 'name email role')
        .sort({ createdAt: -1 });
    res.json(history);
});

const createAdjustedInvoice = asyncHandler(async (req, res) => {
    const { packageName, amount, adjustConsultation = false, adjustPreviousAmount = false, dueDate = null, notes = '', invoiceNumber, splitPercentage = null } = req.body;
    
    const order = await Order.findById(req.params.id);
    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (packageName && packageName !== order.packageName) {
        order.packageName = packageName;
    }
    order.price = Number(amount);

    const savedOrder = await generateAndEmailInvoice(order, amount, {
        invoiceNumber,
        adjustConsultation,
        adjustPreviousAmount,
        splitPercentage,
        dueDate,
        notes,
        actorId: req.user._id
    });

    res.status(201).json(savedOrder);
});

// @desc    Get real-time attendance status of all staff assigned to the order
// @route   GET /api/orders/:id/attendance
// @access  Private
const getOrderAttendance = asyncHandler(async (req, res) => {
    const order = await Order.findById(req.params.id);
    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (!canAccessOrder(req.user, order)) {
        res.status(403);
        throw new Error('Not authorized to view attendance for this order');
    }

    // Collect all assigned employee IDs
    const employeeIds = new Set();
    if (order.assignedEmployee) employeeIds.add(order.assignedEmployee.toString());
    if (order.assignedMaker) employeeIds.add(order.assignedMaker.toString());
    if (order.assignedChecker) employeeIds.add(order.assignedChecker.toString());

    (order.tasks || []).forEach(task => {
        if (task.assignedTo) employeeIds.add(task.assignedTo.toString());
        if (task.assignedMaker) employeeIds.add(task.assignedMaker.toString());
        if (task.assignedChecker) employeeIds.add(task.assignedChecker.toString());

        (task.subtasks || []).forEach(sub => {
            if (sub.assignedToMaker) employeeIds.add(sub.assignedToMaker.toString());
            if (sub.assignedToChecker) employeeIds.add(sub.assignedToChecker.toString());
        });
    });

    const Attendance = (await import('../models/Attendance.js')).default;
    const staffList = await User.find({ _id: { $in: Array.from(employeeIds) } })
        .select('name email role isClockedIn activeOrderId lastClockInTime');

    const result = await Promise.all(staffList.map(async (staff) => {
        let isClockedIn = false;
        let clockInAt = null;

        if (staff.role === 'freelancer') {
            isClockedIn = !!(staff.isClockedIn && staff.activeOrderId?.toString() === order._id.toString());
            clockInAt = isClockedIn ? staff.lastClockInTime : null;
        } else {
            const activeSession = await Attendance.findOne({
                employee: staff._id,
                clockOutAt: null
            });
            isClockedIn = !!activeSession;
            clockInAt = activeSession ? activeSession.clockInAt : null;
        }

        return {
            _id: staff._id,
            name: staff.name,
            email: staff.email,
            role: staff.role,
            isClockedIn,
            clockInAt
        };
    }));

    res.json(result);
});

export {
    createOrder,
    getOrders,
    getOrderHistory,
    createAdjustedInvoice,
    getOrderAttendance,
    getOrderById,
    updateOrderStatus,
    updateOrder,
    deleteOrder,
    assignOrder,
    updateOrderCommercials,
    uploadDocument,
    addTask,
    updateTask,
    assignTask,
    addSubtask,
    updateSubtask,
    addChecklistItem,
    toggleChecklistItem,
    addInvoice,
    updateInvoiceStatus,
    importTasks,
    addTaskTimeLog,
    importRequirements,
    updateRequirement,
    addRequirement,
    deleteRequirement,
    // Export utilities for reuse in Recurring Services
    parseTasksFromText,
    parseRequirementsFromText,
    mapStructuredTasks,
    mapStructuredRequirements
};
