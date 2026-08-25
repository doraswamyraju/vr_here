import cron from 'node-cron';
import RecurringService from '../models/RecurringService.js';
import Compliance from '../models/Compliance.js';
import User from '../models/User.js';
import { triggerNotification } from './notificationService.js';
import { generateOrderFromSubscription } from '../utils/automationUtils.js';

export const initCronJobs = () => {
    // 1. Run every day at 00:01 for Recurring Subscriptions
    cron.schedule('1 0 * * *', async () => {
        console.log('[CRON] Checking for recurring services due today...'.blue);
        
        try {
            const today = new Date();
            today.setHours(23, 59, 59, 999);

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

    // 2. Run every day at 09:00 AM for Compliance Deadline Reminders (T-7, T-3, T-1, Due Today)
    cron.schedule('0 9 * * *', async () => {
        console.log('[CRON] Checking for pending compliance deadlines...'.blue);
        try {
            const now = new Date();
            const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            const endOf7Days = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 7, 23, 59, 59);

            const pendingCompliances = await Compliance.find({
                status: 'Pending',
                dueDate: { $gte: startOfToday, $lte: endOf7Days }
            });

            if (pendingCompliances.length === 0) {
                console.log('[CRON] No pending compliance deadlines due in next 7 days.');
                return;
            }

            const clients = await User.find({ role: 'client', isActive: true });

            for (const comp of pendingCompliances) {
                const due = new Date(comp.dueDate);
                const diffTime = due - startOfToday;
                const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

                let reminderLabel = '';
                if (diffDays === 7) reminderLabel = 'Upcoming in 7 Days';
                else if (diffDays === 3) reminderLabel = 'Urgent: 3 Days Left';
                else if (diffDays === 1) reminderLabel = 'Final Call: Due Tomorrow';
                else if (diffDays === 0) reminderLabel = 'Action Required: DUE TODAY';
                else continue; // Only notify on milestone days (7, 3, 1, 0)

                const formattedDate = due.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
                const notifTitle = `Reminder: ${comp.category} - ${comp.taskName} (${reminderLabel})`;
                const notifMessage = `Compliance Reminder: ${comp.taskName} (${comp.category}) for ${comp.periodMonth} ${comp.periodYear} is due on ${formattedDate}. Please complete your filing and upload required documents to avoid penalties.`;

                // Notify target clients or all clients if "All Active Clients"
                const targetClients = (comp.clientName && comp.clientName !== 'All Active Clients') 
                    ? clients.filter(c => c.name.toLowerCase().includes(comp.clientName.toLowerCase()))
                    : clients;

                for (const client of targetClients) {
                    triggerNotification({
                        userId: client._id,
                        title: notifTitle,
                        message: notifMessage,
                        type: 'System',
                        emailOpts: {
                            send: true,
                            subject: `[Compliance Reminder] ${comp.category}: ${comp.taskName} (${reminderLabel})`
                        }
                    }).catch(err => console.error(`[CRON] Compliance alert error to ${client.email}:`, err.message));
                }
            }

            console.log(`[CRON] Processed ${pendingCompliances.length} compliance reminders.`.green);
        } catch (error) {
            console.error('[CRON] Error in compliance reminder scheduler:'.red, error.message);
        }
    });

    console.log('[CRON] Recurring Services & Daily Compliance Schedulers Initialized with SMTP & Push Alerts.'.yellow.bold);
};
