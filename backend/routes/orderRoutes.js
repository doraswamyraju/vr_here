import express from 'express';
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

export default router;
