import asyncHandler from 'express-async-handler';
import RecurringService from '../models/RecurringService.js';
import { sendCustomerRenewalReminder } from '../services/notificationService.js';
import { generateOrderFromSubscription } from '../utils/automationUtils.js';

// @desc    Get all pending service renewals for employee review
// @route   GET /api/renewals/pending
// @access  Private (Employee/Admin)
export const getPendingRenewals = asyncHandler(async (req, res) => {
    const renewals = await RecurringService.find({ isActive: true })
        .populate('user', 'name email phone')
        .populate('assignedEmployee', 'name email role')
        .sort({ nextRunDate: 1 });

    res.json({
        success: true,
        count: renewals.length,
        data: renewals
    });
});

// @desc    Update renewal price by Employee/Admin (Step 3)
// @route   PUT /api/renewals/:id/price
// @access  Private (Employee/Admin)
export const updateRenewalPrice = asyncHandler(async (req, res) => {
    const { price } = req.body;

    if (!price || isNaN(price) || price <= 0) {
        res.status(400);
        throw new Error('Please provide a valid renewal price');
    }

    const subscription = await RecurringService.findById(req.params.id);

    if (!subscription) {
        res.status(404);
        throw new Error('Recurring service record not found');
    }

    subscription.renewalPrice = Number(price);
    subscription.price = Number(price); // Keep current price updated
    subscription.status = 'PriceSet';
    await subscription.save();

    res.json({
        success: true,
        message: `Renewal price updated to ₹${price} successfully`,
        data: subscription
    });
});

// @desc    Send Email & Push Notification reminder to Customer (Step 4 & 5)
// @route   POST /api/renewals/:id/send-reminder
// @access  Private (Employee/Admin)
export const sendCustomerReminder = asyncHandler(async (req, res) => {
    const subscription = await RecurringService.findById(req.params.id)
        .populate('user', 'name email');

    if (!subscription) {
        res.status(404);
        throw new Error('Recurring service record not found');
    }

    const clientUrl = process.env.CLIENT_URL || 'http://localhost:5173';
    const paymentLink = `${clientUrl}/renewals/pay/${subscription._id}`;
    const priceToCharge = subscription.renewalPrice || subscription.price;

    // Trigger Email & Push Notification
    await sendCustomerRenewalReminder({
        subscriptionId: subscription._id,
        userId: subscription.user?._id || subscription.user,
        clientName: subscription.clientName || subscription.user?.name,
        serviceName: subscription.serviceName,
        dueDate: subscription.nextRunDate,
        price: priceToCharge,
        paymentLink
    });

    subscription.status = 'ReminderSent';
    subscription.paymentLinkId = paymentLink;
    subscription.reminderSentAt = new Date();
    await subscription.save();

    res.json({
        success: true,
        message: `Renewal reminder dispatched via Email & Push Notification`,
        data: {
            subscriptionId: subscription._id,
            status: subscription.status,
            paymentLink
        }
    });
});

// @desc    Complete Customer Payment & Auto-Generate Order (Step 6-10)
// @route   POST /api/renewals/:id/payment
// @access  Private/Public (Customer Payment Endpoint / Gateway Webhook)
export const processRenewalPayment = asyncHandler(async (req, res) => {
    const subscription = await RecurringService.findById(req.params.id)
        .populate('user', 'name email phone')
        .populate('assignedEmployee', 'name email role')
        .populate('assignedMaker', 'name email role')
        .populate('assignedChecker', 'name email role');

    if (!subscription) {
        res.status(404);
        throw new Error('Recurring service record not found');
    }

    const { paymentId = `PAY_${Date.now()}` } = req.body;

    // 1. Update status to PaymentSuccess
    subscription.status = 'PaymentSuccess';
    await subscription.save();

    // 2. Auto-generate Order and increment next renewal date cycle
    const createdOrder = await generateOrderFromSubscription(subscription);

    // 3. Reset status for next cycle
    subscription.status = 'Upcoming';
    await subscription.save();

    res.json({
        success: true,
        message: 'Payment recorded, new order created, and next renewal date set successfully.',
        data: {
            orderId: createdOrder._id,
            nextRenewalDate: subscription.nextRunDate,
            paymentId
        }
    });
});
