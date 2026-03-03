import asyncHandler from 'express-async-handler';
import Ticket from '../models/Ticket.js';

// @desc    Create a new support ticket
// @route   POST /api/tickets
// @access  Private
const createTicket = asyncHandler(async (req, res) => {
    const { subject, description, priority } = req.body;

    const ticket = new Ticket({
        user: req.user._id,
        subject,
        description,
        priority: priority || 'Low'
    });

    const createdTicket = await ticket.save();
    res.status(201).json(createdTicket);
});

// @desc    Get all tickets (Admin/Employee sees all, Client sees their own)
// @route   GET /api/tickets
// @access  Private
const getTickets = asyncHandler(async (req, res) => {
    let tickets;

    if (req.user.role === 'admin' || req.user.role === 'employee') {
        tickets = await Ticket.find({}).populate('user', 'name email');
    } else {
        tickets = await Ticket.find({ user: req.user._id });
    }

    res.json(tickets);
});

// @desc    Get ticket by ID
// @route   GET /api/tickets/:id
// @access  Private
const getTicketById = asyncHandler(async (req, res) => {
    const ticket = await Ticket.findById(req.params.id).populate('user', 'name email').populate('messages.sender', 'name role');

    if (ticket) {
        if (req.user.role === 'client' && ticket.user._id.toString() !== req.user._id.toString()) {
            res.status(403);
            throw new Error('Not authorized to view this ticket');
        }
        res.json(ticket);
    } else {
        res.status(404);
        throw new Error('Ticket not found');
    }
});

// @desc    Add message to ticket
// @route   POST /api/tickets/:id/messages
// @access  Private
const addTicketMessage = asyncHandler(async (req, res) => {
    const { message } = req.body;
    const ticket = await Ticket.findById(req.params.id);

    if (ticket) {
        ticket.messages.push({
            sender: req.user._id,
            message
        });

        // Auto update status if employee/admin replies
        if (req.user.role !== 'client') {
            ticket.status = 'In Progress';
        }

        const updatedTicket = await ticket.save();
        res.json(updatedTicket);
    } else {
        res.status(404);
        throw new Error('Ticket not found');
    }
});

// @desc    Update ticket status
// @route   PUT /api/tickets/:id/status
// @access  Private (Admin/Employee)
const updateTicketStatus = asyncHandler(async (req, res) => {
    const { status } = req.body;
    const ticket = await Ticket.findById(req.params.id);

    if (ticket) {
        ticket.status = status;
        const updatedTicket = await ticket.save();
        res.json(updatedTicket);
    } else {
        res.status(404);
        throw new Error('Ticket not found');
    }
});

export {
    createTicket,
    getTickets,
    getTicketById,
    addTicketMessage,
    updateTicketStatus
};
