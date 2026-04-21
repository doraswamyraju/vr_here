import crypto from 'crypto';
import Razorpay from 'razorpay';
import Payment from '../models/Payment.js';
import Order from '../models/Order.js';
import User from '../models/User.js';
import generateToken from '../utils/generateToken.js';
import sendEmail from '../utils/sendEmail.js';

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

const getAuthPayload = (userDoc) => {
    if (!userDoc) return null;

    return {
        _id: userDoc._id,
        name: userDoc.name,
        email: userDoc.email,
        role: userDoc.role,
        token: generateToken(userDoc._id)
    };
};

const resolveCustomerUser = async ({
    currentUser,
    customerName,
    email,
    phone
}) => {
    if (currentUser?._id) {
        return {
            user: currentUser,
            accountCreated: false
        };
    }

    const normalizedEmail = String(email || '').trim().toLowerCase();
    if (!normalizedEmail) {
        return {
            user: null,
            accountCreated: false
        };
    }

    let user = await User.findOne({ email: normalizedEmail });
    let accountCreated = false;

    if (!user) {
        const tempPassword = `VrHere@${crypto.randomBytes(8).toString('hex')}`;
        user = await User.create({
            name: customerName || 'VR HERE Customer',
            email: normalizedEmail,
            phone: phone || '',
            password: tempPassword,
            role: 'client'
        });
        accountCreated = true;
    } else {
        let shouldSave = false;
        if (!user.phone && phone) {
            user.phone = phone;
            shouldSave = true;
        }
        if (!user.name && customerName) {
            user.name = customerName;
            shouldSave = true;
        }
        if (shouldSave) {
            await user.save();
        }
    }

    return {
        user,
        accountCreated
    };
};

const sendPostPaymentEmail = async ({
    user,
    customerEmail,
    customerName,
    paymentId,
    serviceName,
    packageName,
    amount,
    shouldSendSetPasswordLink
}) => {
    const targetEmail = String(customerEmail || user?.email || '').trim().toLowerCase();
    if (!targetEmail || !user) {
        return {
            emailSent: false,
            resetLinkSent: false
        };
    }

    let resetUrl = '';
    let resetLinkSent = false;

    if (shouldSendSetPasswordLink) {
        const resetToken = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = crypto
            .createHash('sha256')
            .update(resetToken)
            .digest('hex');
        user.resetPasswordExpire = Date.now() + 24 * 60 * 60 * 1000; // 24h
        await user.save();
        resetUrl = `https://vrhere.in/reset-password/${resetToken}`;
        resetLinkSent = true;
    }

    const message = `
      <h2>Payment Successful</h2>
      <p>Hi ${customerName || user.name || 'Customer'},</p>
      <p>We have received your payment successfully.</p>
      <ul>
        <li><strong>Payment ID:</strong> ${paymentId || '-'}</li>
        <li><strong>Service:</strong> ${serviceName || '-'}</li>
        <li><strong>Package:</strong> ${packageName || '-'}</li>
        <li><strong>Amount:</strong> INR ${Number(amount || 0).toLocaleString('en-IN')}</li>
      </ul>
      ${resetLinkSent
            ? `<p>Your customer account is ready. Please set your password using this secure link:</p>
             <p><a href="${resetUrl}">${resetUrl}</a></p>
             <p>This link will expire in 24 hours.</p>`
            : '<p>You can continue using your existing login credentials to access your dashboard.</p>'
        }
      <p>Thanks,<br/>VR HERE Business Solutions</p>
    `;

    try {
        await sendEmail({
            email: targetEmail,
            subject: 'VR HERE Payment Confirmation & Login Details',
            message
        });
        return {
            emailSent: true,
            resetLinkSent
        };
    } catch (error) {
        console.error('Post-payment email send failure:', error);
        return {
            emailSent: false,
            resetLinkSent: false
        };
    }
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
            phone = '',
            referralCode = ''
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
                phone,
                referralCode
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
            phone = '',
            referralCode = ''
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

        const isGuestCheckout = !req.user?._id;
        const { user: customerUser, accountCreated } = await resolveCustomerUser({
            currentUser: req.user,
            customerName,
            email,
            phone
        });
        const auth = getAuthPayload(customerUser);

        const existingPayment = await Payment.findOne({ paymentId: razorpay_payment_id });
        if (existingPayment) {
            const existingOrder = await Order.findById(existingPayment.order);
            const existingMessage = isGuestCheckout
                ? 'Payment already confirmed. Login details were sent to your email.'
                : 'Payment already confirmed.';
            return res.status(200).json({
                message: 'Payment already verified',
                order: existingOrder,
                payment: existingPayment,
                auth,
                accountCreated,
                postPaymentMessage: existingMessage
            });
        }

        const resolvedCustomerName = customerName || customerUser?.name || req.user?.name || '';
        const resolvedEmail = email || customerUser?.email || req.user?.email || '';
        const resolvedPhone = phone || customerUser?.phone || req.user?.phone || '';

        let referralPartnerId = null;
        let partnerCommissionAmount = 0;

        if (referralCode) {
            const partner = await User.findOne({ phone: referralCode, role: 'partner' });
            if (partner) {
                referralPartnerId = partner._id;
                partnerCommissionAmount = Math.round(parsedAmount * (partner.commissionPercentage || 10) / 100);
            }
        }

        const createdOrder = await Order.create({
            user: customerUser?._id || req.user?._id || null,
            clientName: resolvedCustomerName,
            email: resolvedEmail,
            phone: resolvedPhone,
            serviceName,
            packageName,
            price: parsedAmount,
            paymentId: razorpay_payment_id,
            razorpayOrderId: razorpay_order_id,
            paymentSignature: razorpay_signature,
            paymentStatus: 'Paid',
            referralPartner: referralPartnerId,
            partnerCommissionAmount
        });

        const payment = await Payment.create({
            user: customerUser?._id || req.user?._id || null,
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

        const emailStatus = await sendPostPaymentEmail({
            user: customerUser,
            customerEmail: resolvedEmail,
            customerName: resolvedCustomerName,
            paymentId: razorpay_payment_id,
            serviceName,
            packageName,
            amount: parsedAmount,
            shouldSendSetPasswordLink: isGuestCheckout
        });

        let postPaymentMessage = 'Payment successful. Your application has been started.';
        if (isGuestCheckout && emailStatus.emailSent && emailStatus.resetLinkSent) {
            postPaymentMessage = 'Payment successful. We sent login details and a password setup link to your email.';
        } else if (isGuestCheckout && !emailStatus.emailSent) {
            postPaymentMessage = 'Payment successful, but we could not send the login email right now. Please contact support.';
        } else if (!isGuestCheckout && emailStatus.emailSent) {
            postPaymentMessage = 'Payment successful. A confirmation email has been sent to your email.';
        }

        res.status(201).json({
            message: 'Payment verified successfully',
            order: createdOrder,
            payment,
            auth,
            accountCreated,
            emailSent: emailStatus.emailSent,
            resetLinkSent: emailStatus.resetLinkSent,
            postPaymentMessage
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
