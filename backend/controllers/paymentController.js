import Payment from '../models/Payment.js';
import Order from '../models/Order.js';

// @desc    Get all payments for a user
// @route   GET /api/payments
// @access  Private
export const getPayments = async (req, res) => {
    try {
        const payments = await Payment.find({ user: req.user._id }).populate('order', 'serviceName packageName status');
        res.json(payments);
    } catch (error) {
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
};

// @desc    Get payment by ID
// @route   GET /api/payments/:id
// @access  Private
export const getPaymentById = async (req, res) => {
    try {
        const payment = await Payment.findById(req.params.id).populate('order', 'serviceName packageName status');
        if (!payment) return res.status(404).json({ message: 'Payment not found' });

        // Ensure user owns this payment
        if (payment.user.toString() !== req.user._id.toString()) {
            return res.status(401).json({ message: 'Not authorized' });
        }

        res.json(payment);
    } catch (error) {
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
};

// @desc    Create a manual payment entry (e.g. for NEFT/Cash recorded by Admin)
// @route   POST /api/payments
// @access  Private (Admin/Employee)
export const createPayment = async (req, res) => {
    const { order, amount, paymentId, method, status } = req.body;
    try {
        const orderExists = await Order.findById(order);
        if (!orderExists) return res.status(404).json({ message: 'Order not found' });

        const payment = await Payment.create({
            user: orderExists.user,
            order,
            amount,
            paymentId,
            method,
            status: status || 'Completed'
        });

        res.status(201).json(payment);
    } catch (error) {
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
};
