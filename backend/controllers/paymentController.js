import crypto from 'crypto';
import Razorpay from 'razorpay';
import Payment from '../models/Payment.js';
import Order from '../models/Order.js';

const getRazorpayClient = () => {
    const keyId = process.env.RAZORPAY_KEY_ID;
    const keySecret = process.env.RAZORPAY_KEY_SECRET;

    if (!keyId || !keySecret) {
        const error = new Error('Razorpay credentials are not configured on the backend');
        error.statusCode = 500;
        throw error;
    }

    return new Razorpay({
        key_id: keyId,
        key_secret: keySecret
    });
};

// @desc    Create Razorpay checkout order
// @route   POST /api/payments/checkout-order
// @access  Public / Optional Auth
export const createCheckoutOrder = async (req, res) => {
    try {
        const {
            serviceName,
            packageName,
            amount,
            customerName = '',
            email = '',
            phone = ''
        } = req.body;

        const parsedAmount = Number(amount);
        if (!serviceName || !packageName || !Number.isFinite(parsedAmount) || parsedAmount <= 0) {
            return res.status(400).json({ message: 'Valid service, package and amount are required' });
        }

        const razorpay = getRazorpayClient();
        const receipt = `vrhere_${Date.now()}`;
        const order = await razorpay.orders.create({
            amount: Math.round(parsedAmount * 100),
            currency: 'INR',
            receipt,
            notes: {
                serviceName,
                packageName,
                customerName,
                email,
                phone
            }
        });

        res.status(201).json({
            key: process.env.RAZORPAY_KEY_ID || '',
            orderId: order.id,
            amount: order.amount,
            currency: order.currency,
            receipt: order.receipt
        });
    } catch (error) {
        res.status(error.statusCode || 500).json({
            message: error.message || 'Failed to create checkout order'
        });
    }
};

// @desc    Verify Razorpay payment and create order/payment records
// @route   POST /api/payments/verify
// @access  Public / Optional Auth
export const verifyPayment = async (req, res) => {
    try {
        const {
            razorpay_order_id,
            razorpay_payment_id,
            razorpay_signature,
            serviceName,
            packageName,
            amount,
            customerName = '',
            email = '',
            phone = ''
        } = req.body;

        if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
            return res.status(400).json({ message: 'Payment verification details are required' });
        }

        const keySecret = process.env.RAZORPAY_KEY_SECRET;
        if (!keySecret) {
            return res.status(500).json({ message: 'Razorpay secret is not configured on the backend' });
        }

        const generatedSignature = crypto
            .createHmac('sha256', keySecret)
            .update(`${razorpay_order_id}|${razorpay_payment_id}`)
            .digest('hex');

        if (generatedSignature !== razorpay_signature) {
            return res.status(400).json({ message: 'Invalid payment signature' });
        }

        const parsedAmount = Number(amount);

        const existingPayment = await Payment.findOne({ paymentId: razorpay_payment_id });
        if (existingPayment) {
            const existingOrder = await Order.findById(existingPayment.order);
            return res.status(200).json({
                message: 'Payment already verified',
                order: existingOrder,
                payment: existingPayment
            });
        }

        const resolvedCustomerName = customerName || req.user?.name || '';
        const resolvedEmail = email || req.user?.email || '';
        const resolvedPhone = phone || req.user?.phone || '';

        const createdOrder = await Order.create({
            user: req.user?._id || null,
            clientName: resolvedCustomerName,
            email: resolvedEmail,
            phone: resolvedPhone,
            serviceName,
            packageName,
            price: parsedAmount,
            paymentId: razorpay_payment_id,
            razorpayOrderId: razorpay_order_id,
            paymentSignature: razorpay_signature,
            paymentStatus: 'Paid'
        });

        const payment = await Payment.create({
            user: req.user?._id || null,
            order: createdOrder._id,
            amount: parsedAmount,
            currency: 'INR',
            paymentId: razorpay_payment_id,
            razorpayOrderId: razorpay_order_id,
            signature: razorpay_signature,
            status: 'Completed',
            method: 'Razorpay',
            customerName: resolvedCustomerName,
            email: resolvedEmail,
            phone: resolvedPhone,
            serviceName,
            packageName
        });

        res.status(201).json({
            message: 'Payment verified successfully',
            order: createdOrder,
            payment
        });
    } catch (error) {
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
};

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
