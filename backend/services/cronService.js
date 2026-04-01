import cron from 'node-cron';
import RecurringService from '../models/RecurringService.js';
import Order from '../models/Order.js';
import Notification from '../models/Notification.js';
import User from '../models/User.js';
import sendEmail from '../utils/sendEmail.js';
import { calculateNextRunDate } from '../utils/dateUtils.js';

export const initCronJobs = () => {
    // Run every day at 00:01
    cron.schedule('1 0 * * *', async () => {
        console.log('[CRON] Checking for recurring services due today...'.blue);
        
        try {
            const today = new Date();
            today.setHours(23, 59, 59, 999); // End of today

            // Find due subscriptions and populate users to get emails
            const dueSubscriptions = await RecurringService.find({
                isActive: true,
                nextRunDate: { $lte: today }
            })
            .populate('user', 'name email phone')
            .populate('assignedEmployee', 'name email role')
            .populate('assignedMaker', 'name email role')
            .populate('assignedChecker', 'name email role');

            console.log(`[CRON] Found ${dueSubscriptions.length} subscriptions due.`.cyan);

            if (dueSubscriptions.length === 0) return;

            // Fetch Admin for notifications
            const admin = await User.findOne({ role: 'admin' });
            const adminId = admin?._id || '659c1a2b3c4d5e6f7a8b9c0d'; // Fallback
            const adminEmail = admin?.email || 'admin@vrhere.in';

            for (const sub of dueSubscriptions) {
                try {
                    // Create New Order
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

                    await newOrder.save();

                    // 1. IN-APP NOTIFICATIONS
                    // Notify Admin
                    await Notification.create({
                        user: adminId,
                        title: 'Recurring Order Generated',
                        message: `New order for ${sub.serviceName} has been automatically created for ${sub.clientName}.`,
                        type: 'Order'
                    });

                    // Notify Client
                    await Notification.create({
                        user: sub.user?._id || sub.user,
                        title: 'New Service Initiated',
                        message: `Your recurring service ${sub.serviceName} for the new period has been started.`,
                        type: 'Order'
                    });

                    // Notify Staff
                    const staffToNotify = [sub.assignedEmployee, sub.assignedMaker, sub.assignedChecker].filter(Boolean);
                    for (const staff of staffToNotify) {
                        await Notification.create({
                            user: staff._id,
                            title: 'New Assignment (Recurring)',
                            message: `You have been assigned to a new recurring order for ${sub.clientName} (${sub.serviceName}).`,
                            type: 'Order'
                        });
                    }

                    // 2. EMAIL NOTIFICATIONS
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

                    // Update Subscription
                    sub.lastRunDate = new Date();
                    sub.nextRunDate = calculateNextRunDate(sub.frequency, sub.dayOfMonth, sub.dayOfWeek, sub.nextRunDate);
                    await sub.save();

                    console.log(`[CRON] Successfully generated order and sent notifications for subscription ${sub._id}`.green);
                } catch (err) {
                    console.error(`[CRON] Error processing subscription ${sub._id}:`.red, err.message);
                }
            }
        } catch (error) {
            console.error('[CRON] Global error in recurring service check:'.red, error.message);
        }
    });

    console.log('[CRON] Recurring Services Scheduler Initialized with SMTP Alerts.'.yellow.bold);
};
