import express from 'express';
import {
    createTicket,
    getTickets,
    getTicketById,
    addTicketMessage,
    updateTicketStatus
} from '../controllers/ticketController.js';
import { protect, admin } from '../middleware/authMiddleware.js';

const router = express.Router();

router.route('/')
    .post(protect, createTicket)
    .get(protect, getTickets);

router.route('/:id')
    .get(protect, getTicketById);

router.route('/:id/status')
    .put(protect, admin, updateTicketStatus);

router.route('/:id/messages')
    .post(protect, addTicketMessage);

export default router;
