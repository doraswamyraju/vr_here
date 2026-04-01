import cron from 'node-cron';
import RecurringService from '../models/RecurringService.js';
import { generateOrderFromSubscription } from '../utils/automationUtils.js';

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

            for (const sub of dueSubscriptions) {
                try {
                    await generateOrderFromSubscription(sub);
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
