import asyncHandler from 'express-async-handler';
import Order from '../models/Order.js';
import OrderMessage from '../models/OrderMessage.js';
import User from '../models/User.js';
import { triggerNotification } from '../services/notificationService.js';
import { uploadBufferToDrive, getCustomerDriveFolder } from '../services/googleDriveService.js';

// Helper to check order access
const canAccessOrder = (user, order) => {
    if (!user || !order) return false;
    // Admins, employees, and freelancers are internal staff working on orders
    if (user.role === 'admin' || user.role === 'employee' || user.role === 'freelancer') return true;
    if (user.role === 'client') {
        const orderUserId = order.user?._id || order.user;
        return orderUserId && orderUserId.toString() === user._id.toString();
    }
    return false;
};

// @desc    Get messages for an order
// @route   GET /api/orders/:id/messages
// @access  Private
export const getOrderMessages = asyncHandler(async (req, res) => {
    const order = await Order.findById(req.params.id);
    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (!canAccessOrder(req.user, order)) {
        res.status(403);
        throw new Error('Not authorized to view messages for this order');
    }

    let filter = { order: req.params.id };

    // Strict privacy: Customers NEVER see internal messages
    if (req.user.role === 'client') {
        filter.messageType = 'client';
    } else if (req.query.messageType && (req.query.messageType === 'client' || req.query.messageType === 'internal')) {
        filter.messageType = req.query.messageType;
    }

    const messages = await OrderMessage.find(filter)
        .populate('sender', 'name email role profilePhoto')
        .sort({ createdAt: 1 })
        .lean();

    // Mark unread messages as read asynchronously for current user
    const unreadMessageIds = messages
        .filter(m => m.sender?._id?.toString() !== req.user._id.toString() && !m.readBy?.some(r => (r.user?._id || r.user)?.toString() === req.user._id.toString()))
        .map(m => m._id);

    if (unreadMessageIds.length > 0) {
        OrderMessage.updateMany(
            { _id: { $in: unreadMessageIds } },
            { $push: { readBy: { user: req.user._id, readAt: new Date() } } }
        ).catch(err => console.error('[OrderChat] Error marking messages read:', err.message));
    }

    res.json(messages);
});

// @desc    Get unread messages count for an order
// @route   GET /api/orders/:id/messages/unread-count
// @access  Private
export const getOrderUnreadCount = asyncHandler(async (req, res) => {
    const order = await Order.findById(req.params.id);
    if (!order || !canAccessOrder(req.user, order)) {
        return res.json({ unreadCount: 0, clientUnread: 0, internalUnread: 0 });
    }

    const baseFilter = {
        order: req.params.id,
        sender: { $ne: req.user._id },
        'readBy.user': { $ne: req.user._id }
    };

    if (req.user.role === 'client') {
        baseFilter.messageType = 'client';
        const count = await OrderMessage.countDocuments(baseFilter);
        return res.json({ unreadCount: count, clientUnread: count, internalUnread: 0 });
    }

    const [clientCount, internalCount] = await Promise.all([
        OrderMessage.countDocuments({ ...baseFilter, messageType: 'client' }),
        OrderMessage.countDocuments({ ...baseFilter, messageType: 'internal' })
    ]);

    res.json({
        unreadCount: clientCount + internalCount,
        clientUnread: clientCount,
        internalUnread: internalCount
    });
});

// @desc    Post a message in an order
// @route   POST /api/orders/:id/messages
// @access  Private
export const sendOrderMessage = asyncHandler(async (req, res) => {
    const order = await Order.findById(req.params.id);
    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (!canAccessOrder(req.user, order)) {
        res.status(403);
        throw new Error('Not authorized to message on this order');
    }

    const { message, mentions, taskRef, directAttachmentUrl, directAttachmentName } = req.body;
    let messageType = req.body.messageType || 'client';

    // Customers can ONLY send client messages
    if (req.user.role === 'client') {
        messageType = 'client';
    }

    let attachments = [];

    // 1. Direct attachment object from payload (if pre-uploaded)
    if (directAttachmentUrl) {
        attachments.push({
            name: directAttachmentName || 'Attached File',
            url: directAttachmentUrl,
            fileType: directAttachmentUrl.split('.').pop() || 'file',
            size: 0
        });
    }

    // 2. File upload via multipart/form-data
    if (req.file) {
        let orderFolderId = null;
        try {
            const driveHierarchy = await getCustomerDriveFolder({
                clientName: order.clientName || req.user.name,
                orderId: order._id,
                orderDate: order.createdAt
            });
            orderFolderId = driveHierarchy ? driveHierarchy.orderFolderId : null;
        } catch (driveErr) {
            console.warn('[OrderChatUpload] Google Drive folder hierarchy warning:', driveErr.message);
        }

        let documentUrl = `/uploads/${Date.now()}_${req.file.originalname}`;
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
        } catch (uploadErr) {
            console.error('[OrderChatUpload] Drive upload fallback to URL:', uploadErr.message);
        }

        attachments.push({
            name: req.file.originalname,
            url: documentUrl,
            fileType: req.file.mimetype,
            size: req.file.size
        });
    }

    if ((!message || !message.trim()) && attachments.length === 0) {
        res.status(400);
        throw new Error('Message text or an attachment is required');
    }

    let parsedMentions = [];
    if (mentions) {
        try {
            parsedMentions = typeof mentions === 'string' ? JSON.parse(mentions) : mentions;
        } catch (e) {
            parsedMentions = [];
        }
    }

    let parsedTaskRef = null;
    if (taskRef) {
        try {
            parsedTaskRef = typeof taskRef === 'string' ? JSON.parse(taskRef) : taskRef;
        } catch (e) {
            parsedTaskRef = null;
        }
    }

    const newMsg = await OrderMessage.create({
        order: order._id,
        sender: req.user._id,
        senderName: req.user.name,
        senderRole: req.user.role,
        senderAvatar: req.user.profilePhoto || null,
        messageType,
        message: message ? message.trim() : '',
        attachments,
        mentions: parsedMentions,
        taskRef: parsedTaskRef,
        readBy: [{ user: req.user._id, readAt: new Date() }]
    });

    const populatedMsg = await OrderMessage.findById(newMsg._id)
        .populate('sender', 'name email role profilePhoto')
        .lean();

    // --- TRIGGER SMART NOTIFICATIONS & PUSH NOTIFICATIONS ---
    const orderTitle = order.serviceName || `Order #${order._id.toString().slice(-6)}`;
    const senderName = req.user.name || 'Team Member';
    const previewText = (message || (attachments.length > 0 ? `Uploaded ${attachments[0].name}` : 'Sent an attachment')).slice(0, 80);

    if (req.user.role === 'client') {
        // Customer messaged -> notify all assigned staff + active admins
        const staffToNotify = new Set();
        const addStaff = (field) => {
            const sId = field?._id ? field._id.toString() : field ? field.toString() : null;
            if (sId && sId !== req.user._id.toString()) staffToNotify.add(sId);
        };
        addStaff(order.assignedProjectManager);
        addStaff(order.assignedMaker);
        addStaff(order.assignedChecker);
        addStaff(order.assignedEmployee);
        addStaff(order.assignedFreelancer);

        // Fetch all active admins
        const admins = await User.find({ role: 'admin', isActive: true }).select('_id');
        admins.forEach(a => {
            if (a._id.toString() !== req.user._id.toString()) staffToNotify.add(a._id.toString());
        });

        for (const staffId of staffToNotify) {
            triggerNotification({
                userId: staffId,
                title: `Client Message: ${orderTitle}`,
                message: `${senderName}: "${previewText}"`,
                type: 'Order'
            }).catch(err => console.error('[OrderChatNotif] Staff notify error:', err.message));
        }
    } else if (messageType === 'client') {
        // Staff messaged the client -> notify customer
        const customerId = order.user?._id ? order.user._id.toString() : order.user ? order.user.toString() : null;
        if (customerId && customerId !== req.user._id.toString()) {
            triggerNotification({
                userId: customerId,
                title: `VR HERE Support: ${orderTitle}`,
                message: `${senderName}: "${previewText}"`,
                type: 'Order'
            }).catch(err => console.error('[OrderChatNotif] Client notify error:', err.message));
        }
    } else {
        // Staff posted an INTERNAL NOTE -> Notify ALL assigned staff & admins on this order (except sender)
        const staffToNotify = new Set();
        const addStaff = (field) => {
            const sId = field?._id ? field._id.toString() : field ? field.toString() : null;
            if (sId && sId !== req.user._id.toString()) staffToNotify.add(sId);
        };
        addStaff(order.assignedProjectManager);
        addStaff(order.assignedMaker);
        addStaff(order.assignedChecker);
        addStaff(order.assignedEmployee);
        addStaff(order.assignedFreelancer);

        if (Array.isArray(parsedMentions)) {
            parsedMentions.forEach(mId => {
                const s = mId?.toString();
                if (s && s !== req.user._id.toString()) staffToNotify.add(s);
            });
        }

        // Also notify all admins
        const admins = await User.find({ role: 'admin', isActive: true }).select('_id');
        admins.forEach(a => {
            if (a._id.toString() !== req.user._id.toString()) staffToNotify.add(a._id.toString());
        });

        for (const staffId of staffToNotify) {
            triggerNotification({
                userId: staffId,
                title: `[Internal Note] ${orderTitle}`,
                message: `${senderName}: "${previewText}"`,
                type: 'Order'
            }).catch(err => console.error('[OrderChatNotif] Internal note notify error:', err.message));
        }
    }

    res.status(201).json(populatedMsg);
});
