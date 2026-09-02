import express from 'express';
import {
    createTicket,
    getTickets,
    getTicketById,
    addTicketMessage,
    updateTicket
} from '../controllers/ticketController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

router.route('/')
    .post(protect, createTicket)
    .get(protect, getTickets);

router.route('/:id')
    .get(protect, getTicketById)
    .put(protect, updateTicket);

router.route('/:id/status')
    .put(protect, updateTicket);

router.route('/:id/messages')
    .post(protect, addTicketMessage);

export default router;
