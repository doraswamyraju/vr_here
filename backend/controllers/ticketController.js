import asyncHandler from 'express-async-handler';
import Ticket from '../models/Ticket.js';
import User from '../models/User.js';
import { triggerNotification, notifyAdmins } from '../services/notificationService.js';
import { getTicketMessageTemplate } from '../utils/emailTemplates.js';

// @desc    Create a new support ticket
// @route   POST /api/tickets
// @access  Private
const createTicket = asyncHandler(async (req, res) => {
    const { category, subject, description, priority, attachments } = req.body;

    const validCategories = ['Technical', 'Service', 'Support'];
    const cleanCategory = validCategories.includes(category) ? category : 'Support';

    const ticket = new Ticket({
        user: req.user._id,
        category: cleanCategory,
        subject,
        description,
        priority: priority || 'Medium',
        attachments: attachments || []
    });

    const createdTicket = await ticket.save();

    // 1. Notify the client who opened the ticket
    await triggerNotification({
        userId: req.user._id,
        title: `Ticket Created: ${createdTicket.ticketNumber || cleanCategory}`,
        message: `Your ${cleanCategory} ticket "${subject}" has been successfully opened. Our specialized team will assist you shortly.`,
        type: 'Ticket',
        emailOpts: {
            send: true,
            subject: `[${createdTicket.ticketNumber || 'Ticket'}] ${subject}`
        }
    });

    // 2. Notify all Super Admins
    await notifyAdmins({
        title: `New ${cleanCategory} Ticket (${createdTicket.ticketNumber || 'VR-TCK'})`,
        message: `Client ${req.user.name} opened a ${cleanCategory} ticket: "${subject}" [Priority: ${priority || 'Medium'}].`,
        type: 'Ticket',
        email: true
    });

    // 3. Notify ONLY Employees assigned to this specific ticket category
    try {
        const assignedEmployees = await User.find({
            role: 'employee',
            assignedTicketCategories: cleanCategory
        }).select('_id name email');

        for (const emp of assignedEmployees) {
            await triggerNotification({
                userId: emp._id,
                title: `New Assigned ${cleanCategory} Ticket`,
                message: `New ticket ${createdTicket.ticketNumber || ''} (${subject}) is pending in your ${cleanCategory} queue.`,
                type: 'Ticket',
                emailOpts: {
                    send: true,
                    subject: `[${cleanCategory} Queue] New Ticket: ${subject}`
                }
            });
        }
    } catch (empNotifyErr) {
        console.error('Failed to notify category assigned employees:', empNotifyErr.message);
    }

    const populatedTicket = await Ticket.findById(createdTicket._id)
        .populate('user', 'name email phone')
        .populate('assignedTo', 'name email');

    res.status(201).json(populatedTicket);
});

// @desc    Get all tickets filtered by role & category assignment
// @route   GET /api/tickets
// @access  Private
const getTickets = asyncHandler(async (req, res) => {
    let query = {};

    if (req.user.role === 'admin') {
        // Admin sees all tickets
        query = {};
    } else if (req.user.role === 'employee') {
        // Employee ONLY sees tickets matching their assigned categories OR directly assigned to them
        const assignedCategories = req.user.assignedTicketCategories || [];
        if (assignedCategories.length === 0) {
            // Unassigned employee sees only directly assigned tickets
            query = { assignedTo: req.user._id };
        } else {
            query = {
                $or: [
                    { category: { $in: assignedCategories } },
                    { assignedTo: req.user._id }
                ]
            };
        }
    } else {
        // Client sees only their own tickets
        query = { user: req.user._id };
    }

    const tickets = await Ticket.find(query)
        .populate('user', 'name email phone')
        .populate('assignedTo', 'name email')
        .sort({ updatedAt: -1 });

    res.json(tickets);
});

// @desc    Get ticket by ID with strict authorization
// @route   GET /api/tickets/:id
// @access  Private
const getTicketById = asyncHandler(async (req, res) => {
    const ticket = await Ticket.findById(req.params.id)
        .populate('user', 'name email phone')
        .populate('assignedTo', 'name email')
        .populate('messages.sender', 'name role');

    if (!ticket) {
        res.status(404);
        throw new Error('Ticket not found');
    }

    // Access control checks
    if (req.user.role === 'client') {
        if (String(ticket.user._id) !== String(req.user._id)) {
            res.status(403);
            throw new Error('Not authorized to view this ticket');
        }
    } else if (req.user.role === 'employee') {
        const assignedCategories = req.user.assignedTicketCategories || [];
        const isAssignedCategory = assignedCategories.includes(ticket.category);
        const isDirectlyAssigned = ticket.assignedTo && String(ticket.assignedTo._id) === String(req.user._id);

        if (!isAssignedCategory && !isDirectlyAssigned) {
            res.status(403);
            throw new Error('Not authorized to access tickets from this category');
        }
    }

    res.json(ticket);
});

// @desc    Add message / reply to ticket
// @route   POST /api/tickets/:id/messages
// @access  Private
const addTicketMessage = asyncHandler(async (req, res) => {
    const { message, attachments } = req.body;
    const ticket = await Ticket.findById(req.params.id);

    if (!ticket) {
        res.status(404);
        throw new Error('Ticket not found');
    }

    // Authorization check
    if (req.user.role === 'client' && String(ticket.user) !== String(req.user._id)) {
        res.status(403);
        throw new Error('Not authorized to reply to this ticket');
    }

    ticket.messages.push({
        sender: req.user._id,
        message,
        attachments: attachments || []
    });

    // Auto-update status if staff replies and ticket was open
    if (req.user.role !== 'client' && ticket.status === 'Open') {
        ticket.status = 'In Progress';
    }

    const updatedTicket = await ticket.save();

    // Trigger Notifications
    if (req.user.role === 'client') {
        // Notify assigned employee or admins
        if (ticket.assignedTo) {
            await triggerNotification({
                userId: ticket.assignedTo,
                title: `Client Reply on ${ticket.ticketNumber || 'Ticket'}`,
                message: `Client ${req.user.name} sent a reply on "${ticket.subject}": "${message}"`,
                type: 'Ticket'
            });
        }
        await notifyAdmins({
            title: `New Message on ${ticket.ticketNumber || 'Ticket'}`,
            message: `Client ${req.user.name} posted on "${ticket.subject}": "${message}"`,
            type: 'Ticket',
            email: false
        });
    } else {
        // Notify Client
        const clientUser = await User.findById(ticket.user);
        if (clientUser) {
            const clientEmailHtml = getTicketMessageTemplate({
                clientName: clientUser.name,
                subject: ticket.subject,
                message: message,
                senderName: req.user.name
            });

            await triggerNotification({
                userId: ticket.user,
                title: `Update on ${ticket.ticketNumber || 'Ticket'}`,
                message: `${req.user.name} replied to your ${ticket.category} ticket: "${ticket.subject}".`,
                type: 'Ticket',
                emailOpts: {
                    send: true,
                    subject: `Reply on Support Ticket: ${ticket.subject}`,
                    html: clientEmailHtml
                }
            });
        }
    }

    const populated = await Ticket.findById(updatedTicket._id)
        .populate('user', 'name email phone')
        .populate('assignedTo', 'name email')
        .populate('messages.sender', 'name role');

    res.json(populated);
});

// @desc    Update ticket status, category, priority, or assigned agent
// @route   PUT /api/tickets/:id
// @access  Private (Admin or Assigned Employee)
const updateTicket = asyncHandler(async (req, res) => {
    const { status, priority, category, assignedTo } = req.body;
    const ticket = await Ticket.findById(req.params.id);

    if (!ticket) {
        res.status(404);
        throw new Error('Ticket not found');
    }

    // Authorization check
    if (req.user.role === 'client') {
        res.status(403);
        throw new Error('Clients cannot modify ticket properties');
    }

    if (status) ticket.status = status;
    if (priority) ticket.priority = priority;
    if (category) ticket.category = category;
    if (assignedTo !== undefined) ticket.assignedTo = assignedTo || null;

    const updatedTicket = await ticket.save();

    // Notify assigned employee if new assignment
    if (assignedTo && String(assignedTo) !== String(req.user._id)) {
        await triggerNotification({
            userId: assignedTo,
            title: `Ticket Assigned to You (${ticket.ticketNumber || 'Ticket'})`,
            message: `${req.user.name} assigned ${ticket.category} ticket "${ticket.subject}" to you.`,
            type: 'Ticket'
        });
    }

    const populated = await Ticket.findById(updatedTicket._id)
        .populate('user', 'name email phone')
        .populate('assignedTo', 'name email')
        .populate('messages.sender', 'name role');

    res.json(populated);
});

export {
    createTicket,
    getTickets,
    getTicketById,
    addTicketMessage,
    updateTicket
};
