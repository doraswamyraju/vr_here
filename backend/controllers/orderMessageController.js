import asyncHandler from 'express-async-handler';
import Order from '../models/Order.js';
import OrderMessage from '../models/OrderMessage.js';
import { triggerNotification, notifyAdmins, notifyEmployee } from '../services/notificationService.js';
import { uploadBufferToDrive, getCustomerDriveFolder } from '../services/googleDriveService.js';

// Helper to check order access
const canAccessOrder = (user, order) => {
    if (!user || !order) return false;
    if (user.role === 'admin') return true;
    if (user.role === 'client') {
        const orderUserId = order.user?._id || order.user;
        return orderUserId && orderUserId.toString() === user._id.toString();
    }
    if (user.role === 'employee' || user.role === 'freelancer') {
        const uId = user._id.toString();
        const check = (f) => f && (f._id ? f._id.toString() : f.toString()) === uId;
        if (check(order.assignedEmployee) || check(order.assignedProjectManager) ||
            check(order.assignedMaker) || check(order.assignedChecker) ||
            check(order.assignedFreelancer)) return true;
        
        if (Array.isArray(order.tasks)) {
            const hasTask = order.tasks.some(t =>
                check(t.assignedTo) || check(t.assignedMaker) || check(t.assignedChecker) ||
                (Array.isArray(t.subtasks) && t.subtasks.some(st => check(st.assignedToMaker) || check(st.assignedToChecker)))
            );
            if (hasTask) return true;
        }
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

    // Mark unread messages as read asynchronously
    const unreadMessageIds = messages
        .filter(m => !m.readBy?.some(r => r.user?.toString() === req.user._id.toString()))
        .map(m => m._id);

    if (unreadMessageIds.length > 0) {
        OrderMessage.updateMany(
            { _id: { $in: unreadMessageIds } },
            { $push: { readBy: { user: req.user._id, readAt: new Date() } } }
        ).catch(err => console.error('[OrderChat] Error marking messages read:', err.message));
    }

    res.json(messages);
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

    // Trigger Smart Notifications
    const orderTitle = order.serviceName || `Order #${order._id.toString().slice(-6)}`;

    if (req.user.role === 'client') {
        // Customer messaged -> notify admins and assigned PM
        notifyAdmins({
            title: `Client Message: ${orderTitle}`,
            message: `${req.user.name}: "${(message || 'Uploaded attachment').slice(0, 80)}"`,
            type: 'Order',
            link: `/admin?tab=Orders&orderId=${order._id}`
        }).catch(err => console.error('[OrderChatNotif] Admin notify error:', err.message));

        if (order.assignedProjectManager) {
            notifyEmployee(order.assignedProjectManager, {
                title: `Client Message: ${orderTitle}`,
                message: `${req.user.name}: "${(message || 'Uploaded attachment').slice(0, 80)}"`,
                type: 'Order',
                link: `/employee?tab=Orders&orderId=${order._id}`
            }).catch(err => console.error('[OrderChatNotif] PM notify error:', err.message));
        }
    } else if (messageType === 'client') {
        // Staff replied to customer -> notify client
        if (order.user) {
            triggerNotification({
                userId: order.user,
                title: `VR Here Support: ${orderTitle}`,
                message: `${req.user.name} sent a message: "${(message || 'Sent an attachment').slice(0, 80)}"`,
                type: 'Order',
                link: `/dashboard?orderId=${order._id}`
            }).catch(err => console.error('[OrderChatNotif] Client notify error:', err.message));
        }
    } else {
        // Staff sent internal note -> notify mentioned team members
        if (Array.isArray(parsedMentions) && parsedMentions.length > 0) {
            parsedMentions.forEach(mUserId => {
                if (mUserId.toString() !== req.user._id.toString()) {
                    triggerNotification({
                        userId: mUserId,
                        title: `Mentioned in ${orderTitle} (Internal Note)`,
                        message: `${req.user.name}: "${(message || '').slice(0, 80)}"`,
                        type: 'System',
                        link: `/admin?tab=Orders&orderId=${order._id}`
                    }).catch(err => console.error('[OrderChatNotif] Mention notify error:', err.message));
                }
            });
        }
    }

    res.status(201).json(populatedMsg);
});
