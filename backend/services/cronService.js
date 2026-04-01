import cron from 'node-cron';
import RecurringService from '../models/RecurringService.js';
import Order from '../models/Order.js';
import Notification from '../models/Notification.js';
import { calculateNextRunDate } from '../utils/dateUtils.js';

export const initCronJobs = () => {
    // Run every day at 00:01
    cron.schedule('1 0 * * *', async () => {
        console.log('[CRON] Checking for recurring services due today...'.blue);
        
        try {
            const today = new Date();
            today.setHours(23, 59, 59, 999); // End of today

            const dueSubscriptions = await RecurringService.find({
                isActive: true,
                nextRunDate: { $lte: today }
            });

            console.log(`[CRON] Found ${dueSubscriptions.length} subscriptions due.`.cyan);

            for (const sub of dueSubscriptions) {
                try {
                    // Create New Order
                    const newOrder = new Order({
                        user: sub.user,
                        clientName: sub.clientName,
                        serviceName: sub.serviceName,
                        packageName: sub.packageName,
                        price: sub.price,
                        paymentId: `RECURRING_${sub._id}_${Date.now()}`,
                        paymentStatus: 'Paid', // Assuming recurring services are pre-paid or handled via subscription
                        status: 'Pending Documents',
                        assignedEmployee: sub.assignedEmployee,
                        assignedMaker: sub.assignedMaker,
                        assignedChecker: sub.assignedChecker,
                        tasks: sub.tasksTemplate || [],
                        customerRequirements: sub.requirementsTemplate || [],
                        checklists: sub.checklistsTemplate || []
                    });

                    await newOrder.save();

                    // Notify Admin
                    await Notification.create({
                        user: '659c1a2b3c4d5e6f7a8b9c0d', // Placeholder for Admin ID - Ideally fetch from DB
                        title: 'Recurring Order Generated',
                        message: `New order for ${sub.serviceName} has been automatically created for ${sub.clientName}.`,
                        type: 'Order'
                    });

                    // Notify Client
                    await Notification.create({
                        user: sub.user,
                        title: 'New Service Initiated',
                        message: `Your recurring service ${sub.serviceName} for the new period has been started.`,
                        type: 'Order'
                    });

                    // Update Subscription
                    sub.lastRunDate = new Date();
                    sub.nextRunDate = calculateNextRunDate(sub.frequency, sub.dayOfMonth, sub.dayOfWeek, sub.nextRunDate);
                    await sub.save();

                    console.log(`[CRON] Successfully generated order for subscription ${sub._id}`.green);
                } catch (err) {
                    console.error(`[CRON] Error processing subscription ${sub._id}:`.red, err.message);
                }
            }
        } catch (error) {
            console.error('[CRON] Global error in recurring service check:'.red, error.message);
        }
    });

    console.log('[CRON] Recurring Services Scheduler Initialized.'.yellow.bold);
};
