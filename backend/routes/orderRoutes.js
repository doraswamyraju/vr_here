import express from 'express';
<<<<<<< Updated upstream
import Order from '../models/Order.js';

const router = express.Router();

// @desc    Create a new order
// @route   POST /api/orders
// @access  Public
router.post('/', async (req, res) => {
    try {
        const {
            clientName,
            email,
            phone,
            serviceName,
            amount,
            paymentStatus,
            razorpayPaymentId,
            razorpayOrderId
        } = req.body;

        const order = new Order({
            clientName,
            email,
            phone,
            serviceName,
            amount,
            paymentStatus,
            razorpayPaymentId,
            razorpayOrderId
        });

        const createdOrder = await order.save();
        res.status(201).json(createdOrder);
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({ message: 'Server Error creating order' });
    }
});

// @desc    Get all orders
// @route   GET /api/orders
// @access  Private (Admin)
router.get('/', async (req, res) => {
    try {
        const orders = await Order.find({}).sort({ date: -1 });
        res.json(orders);
    } catch (error) {
        console.error('Error fetching orders:', error);
        res.status(500).json({ message: 'Server Error fetching orders' });
    }
});
=======
const router = express.Router();
import {
    createOrder,
    getOrders,
    getOrderById,
    updateOrderStatus,
    assignOrder,
    uploadDocument
} from '../controllers/orderController.js';
import { protect, admin } from '../middleware/authMiddleware.js';
import upload from '../middleware/uploadMiddleware.js';

router.route('/')
    .post(protect, createOrder)
    .get(protect, getOrders);

router.route('/:id')
    .get(protect, getOrderById);

router.route('/:id/status')
    .put(protect, updateOrderStatus); // Should be protected, verified by controller logic

router.route('/:id/assign')
    .put(protect, admin, assignOrder);

router.route('/:id/documents')
    .post(protect, upload.single('document'), uploadDocument);
>>>>>>> Stashed changes

export default router;
