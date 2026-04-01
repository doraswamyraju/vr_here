import Order from '../models/Order.js';
import Notification from '../models/Notification.js';
import User from '../models/User.js';
import sendEmail from './sendEmail.js';
import { calculateNextRunDate } from './dateUtils.js';

/**
 * Generates an order, notifications, and emails from a subscription record.
 * Handles both CRON runs and immediate first-time generation.
 */
export const generateOrderFromSubscription = async (sub, session = null) => {
    // 1. Fetch Admin for notifications
    const admin = await User.findOne({ role: 'admin' });
    const adminId = admin?._id || '659c1a2b3c4d5e6f7a8b9c0d';
    const adminEmail = admin?.email || 'admin@vrhere.in';

    // 2. Create New Order
    const newOrder = new Order({
        user: sub.user?._id || sub.user,
        clientName: sub.clientName,
        serviceName: sub.serviceName,
        packageName: sub.packageName,
        price: sub.price,
        paymentId: `RECURRING_${sub._id}_${Date.now()}`,
        paymentStatus: 'Paid',
        status: 'Pending Documents',
        assignedEmployee: sub.assignedEmployee?._id || sub.assignedEmployee,
        assignedMaker: sub.assignedMaker?._id || sub.assignedMaker,
        assignedChecker: sub.assignedChecker?._id || sub.assignedChecker,
        tasks: sub.tasksTemplate || [],
        customerRequirements: sub.requirementsTemplate || [],
        checklists: sub.checklistsTemplate || []
    });

    await newOrder.save({ session });

    // 3. IN-APP NOTIFICATIONS
    // Notify Admin
    await Notification.create([{
        user: adminId,
        title: 'Recurring Order Generated',
        message: `New order for ${sub.serviceName} has been automatically created for ${sub.clientName}.`,
        type: 'Order'
    }], { session });

    // Notify Client
    await Notification.create([{
        user: sub.user?._id || sub.user,
        title: 'New Service Initiated',
        message: `Your recurring service ${sub.serviceName} for the new period has been started.`,
        type: 'Order'
    }], { session });

    // Notify Staff
    const staffToNotify = [sub.assignedEmployee, sub.assignedMaker, sub.assignedChecker].filter(Boolean);
    for (const staff of staffToNotify) {
        await Notification.create([{
            user: staff._id || staff,
            title: 'New Assignment (Recurring)',
            message: `You have been assigned to a new recurring order for ${sub.clientName} (${sub.serviceName}).`,
            type: 'Order'
        }], { session });
    }

    // 4. EMAIL NOTIFICATIONS (Async, don't wait for completion)
    const sendEmails = async () => {
        try {
            // Email to Client
            if (sub.user?.email) {
                await sendEmail({
                    email: sub.user.email,
                    subject: `Service Initiated: ${sub.serviceName}`,
                    message: `
                        <h3>Hello ${sub.user.name},</h3>
                        <p>Your recurring service <b>${sub.serviceName}</b> has been automatically initiated for the new period.</p>
                        <p>Our team is now processing the documents. You can track the status on your dashboard.</p>
                        <p>Thank you for choosing VR HERE!</p>
                    `
                });
            }

            // Email to Admin
            await sendEmail({
                email: adminEmail,
                subject: `RECURRING ORDER: ${sub.clientName} - ${sub.serviceName}`,
                message: `
                    <h3>Automatic Order Generation</h3>
                    <p>An automated order has been created successfully.</p>
                    <ul>
                        <li><b>Client:</b> ${sub.clientName}</li>
                        <li><b>Service:</b> ${sub.serviceName}</li>
                        <li><b>Price:</b> Rs. ${sub.price}</li>
                    </ul>
                    <p>Please review the assignment in the Admin Studio.</p>
                `
            });

            // Email to Staff
            for (const staff of staffToNotify) {
                if (staff.email) {
                    await sendEmail({
                        email: staff.email,
                        subject: `New Recurring Assignment: ${sub.serviceName}`,
                        message: `
                            <h3>Hello ${staff.name},</h3>
                            <p>A new recurring order for <b>${sub.clientName}</b> has been generated and assigned to you.</p>
                            <p><b>Service:</b> ${sub.serviceName}</p>
                            <p>Please check your work queue to start processing.</p>
                        `
                    });
                }
            }
        } catch (emailErr) {
            console.error('[Automation] Email dispatch failed:', emailErr.message);
        }
    };
    
    sendEmails(); // Trigger async

    // 5. Update Subscription Metadata
    sub.lastRunDate = new Date();
    sub.lastOrderId = newOrder._id;
    sub.nextRunDate = calculateNextRunDate(sub.frequency, sub.dayOfMonth, sub.dayOfWeek, sub.nextRunDate);
    await sub.save({ session });

    return newOrder;
};
