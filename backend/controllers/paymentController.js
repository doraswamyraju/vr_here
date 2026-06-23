import crypto from 'crypto';
import Razorpay from 'razorpay';
import Payment from '../models/Payment.js';
import Order from '../models/Order.js';
import User from '../models/User.js';
import generateToken from '../utils/generateToken.js';
import sendEmail from '../utils/sendEmail.js';
import { triggerNotification, notifyAdmins } from '../services/notificationService.js';
import { getOrderPlacedTemplate } from '../utils/emailTemplates.js';
import { logOrderActivity } from '../utils/activityLogger.js';
import { generateAndEmailInvoice } from '../utils/invoiceHelper.js';


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
      <p>Thanks,<br/>VR Here Business Management Solutions</p>
    `;

    try {
        await sendEmail({
            email: targetEmail,
            subject: 'VR Here Business Management Solutions Payment Confirmation & Login Details',
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
            if (partner && partner.isActive) {
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

        // Generate paid invoice automatically
        try {
            await generateAndEmailInvoice(createdOrder, parsedAmount, {
                status: 'Paid',
                notes: 'Primary Invoice generated automatically on successful website checkout.'
            });
        } catch (invErr) {
            console.error('Failed to generate initial paid invoice on payment verification:', invErr.message);
        }

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

        // Trigger customer in-app notification and styled email confirmation if customer account exists
        if (customerUser?._id) {
            const clientEmailHtml = getOrderPlacedTemplate({
                clientName: resolvedCustomerName,
                serviceName,
                packageName,
                price: parsedAmount,
                paymentId: razorpay_payment_id
            });

            await triggerNotification({
                userId: customerUser._id,
                title: 'Order Registered Successfully',
                message: `Your compliance order for ${serviceName} (${packageName}) is successfully registered. Transaction ID: ${razorpay_payment_id}.`,
                type: 'Order',
                emailOpts: {
                    send: !isGuestCheckout, // For guest checkout, sendPostPaymentEmail already covers email notification
                    subject: `Order Confirmed: ${serviceName} - VR HERE`,
                    html: clientEmailHtml
                }
            });
        }

        // Notify admins of the new order placement
        await notifyAdmins({
            title: 'New Order Placed',
            message: `Client ${resolvedCustomerName} has purchased ${serviceName} (${packageName}) for INR ${Number(parsedAmount).toLocaleString('en-IN')}. Payment ID: ${razorpay_payment_id}.`,
            type: 'Order',
            email: true
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
        let query = {};
        if (req.user.role === 'client') {
            query.user = req.user._id;
        }
        if (req.query.orderId) {
            query.order = req.query.orderId;
        }
        const payments = await Payment.find(query).populate('order', 'serviceName packageName status');
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

// @desc    Handle Razorpay Webhook Event (e.g. payment_link.paid, payment.captured)
// @route   POST /api/payments/razorpay/webhook
// @access  Public
export const handleRazorpayWebhook = async (req, res) => {
    try {
        console.log('Razorpay Webhook Triggered:', req.body.event, JSON.stringify(req.body.payload));
        const signature = req.headers['x-razorpay-signature'];
        const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;

        // Verify webhook signature if secret exists
        if (webhookSecret && signature) {
            const shasum = crypto.createHmac('sha256', webhookSecret);
            shasum.update(JSON.stringify(req.body));
            const digest = shasum.digest('hex');
            if (digest !== signature) {
                return res.status(400).json({ message: 'Invalid signature verification' });
            }
        }

        const { event, payload } = req.body;

        if (event === 'payment_link.paid' || event === 'payment.captured') {
            let paymentLinkEntity = null;
            let paymentEntity = null;

            if (event === 'payment_link.paid') {
                paymentLinkEntity = payload.payment_link.entity;
                paymentEntity = payload.payment.entity;
            } else {
                paymentEntity = payload.payment.entity;
            }

            const notes = paymentLinkEntity?.notes || paymentEntity?.notes || {};
            const orderId = notes.orderId;
            const invoiceNumber = notes.invoiceNumber;

            if (orderId && invoiceNumber) {
                const order = await Order.findById(orderId);
                if (order) {
                    const invoice = order.invoices.find(inv => inv.invoiceNumber === invoiceNumber);
                    if (invoice) {
                        const oldStatus = invoice.status;
                        invoice.status = 'Paid';
                        order.paymentStatus = 'Paid';
                        order.markModified('invoices');
                        await order.save();

                        // Add Payment record in Payment collection so the transactions tab lists it
                        const paidAmount = (paymentLinkEntity?.amount || paymentEntity?.amount || 0) / 100;
                        const paymentId = paymentEntity?.id || `PAY_${Date.now()}`;
                        const rzpOrderId = paymentEntity?.order_id || '';

                        // Check if payment already recorded
                        const existingPayment = await Payment.findOne({ paymentId });
                        if (!existingPayment) {
                            await Payment.create({
                                user: order.user || null,
                                order: order._id,
                                amount: paidAmount,
                                currency: 'INR',
                                paymentId,
                                razorpayOrderId: rzpOrderId,
                                signature: signature || 'WEBHOOK_VERIFIED',
                                status: 'Completed',
                                method: 'Razorpay',
                                customerName: order.clientName,
                                email: order.email,
                                phone: order.phone,
                                serviceName: order.serviceName,
                                packageName: order.packageName
                            });
                        }

                        // Log activity in history
                        await logOrderActivity(
                            order._id,
                            order.user || order._id, // Actor fallback to orderId for guest
                            'PAYMENT_RECEIVE',
                            `Payment of INR ${paidAmount.toLocaleString('en-IN')} received via Razorpay for Invoice ${invoiceNumber}`,
                            { invoiceNumber, paymentId, amount: paidAmount }
                        );

                        // Send confirmation email to Client
                        if (order.email) {
                            const clientSubject = `Payment Confirmation - Invoice ${invoiceNumber} Paid`;
                            const clientMessage = `
                                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
                                    <h2 style="color: #16a34a; text-align: center;">Payment Received Successfully</h2>
                                    <p>Hello ${order.clientName || 'Customer'},</p>
                                    <p>We have successfully received your payment of <strong>INR ${paidAmount.toLocaleString('en-IN')}</strong> for Invoice <strong>${invoiceNumber}</strong>.</p>
                                    <div style="background-color: #f8fafc; padding: 15px; border-radius: 8px; margin: 20px 0;">
                                        <p style="margin: 5px 0;"><strong>Invoice Number:</strong> ${invoiceNumber}</p>
                                        <p style="margin: 5px 0;"><strong>Service:</strong> ${order.serviceName}</p>
                                        <p style="margin: 5px 0;"><strong>Package:</strong> ${order.packageName}</p>
                                        <p style="margin: 5px 0;"><strong>Amount Paid:</strong> INR ${paidAmount.toLocaleString('en-IN')}</p>
                                        <p style="margin: 5px 0;"><strong>Status:</strong> Paid</p>
                                        <p style="margin: 5px 0;"><strong>Payment ID:</strong> ${paymentId}</p>
                                    </div>
                                    <p>You can view, print, or download your formal GST Invoice PDF directly from your <a href="https://vrhere.in/" style="color: #4f46e5; text-decoration: underline; font-weight: bold;">Client Dashboard</a> under the <strong>Invoices</strong> section.</p>
                                    <p style="margin-top: 20px; font-size: 14px; color: #475569;">Thank you for choosing VR Here Business Management Solutions.</p>
                                </div>
                            `;
                            try {
                                await sendEmail({
                                    email: order.email,
                                    subject: clientSubject,
                                    message: clientMessage
                                });
                            } catch (clientEmailErr) {
                                console.error(`Failed to send webhook payment confirmation email to client: ${clientEmailErr.message}`);
                            }
                        }

                        // Notify admins
                        await notifyAdmins({
                            title: 'Invoice Paid Successfully',
                            message: `Client ${order.clientName} paid Invoice ${invoiceNumber} for service "${order.serviceName}" through payment link. Amount: INR ${paidAmount.toLocaleString('en-IN')}`,
                            type: 'Order',
                            email: true
                        });
                    }
                }
            }
        }

        res.status(200).json({ status: 'ok' });
    } catch (error) {
        console.error('Webhook processing failure:', error);
        res.status(500).json({ message: 'Webhook processing error', error: error.message });
    }
};
