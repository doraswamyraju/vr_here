import Notification from '../models/Notification.js';
import User from '../models/User.js';
import sendEmail from '../utils/sendEmail.js';
import { sendPushNotification } from './firebaseService.js';

/**
 * Creates an in-app notification and optionally sends an email to the user.
 * 
 * @param {Object} params
 * @param {string} params.userId - The ID of the target user
 * @param {string} params.title - The title of the notification
 * @param {string} params.message - The detailed message body
 * @param {string} [params.type='System'] - The notification type ('Order', 'Payment', 'Ticket', 'System')
 * @param {Object} [params.emailOpts] - Optional email dispatch configurations
 * @param {boolean} params.emailOpts.send - Whether to send an email
 * @param {string} [params.emailOpts.subject] - The subject of the email (defaults to title)
 * @param {string} [params.emailOpts.html] - The HTML body of the email (defaults to formatted message)
 */
export const triggerNotification = async ({
    userId,
    title,
    message,
    type = 'System',
    emailOpts = null
}) => {
    try {
        if (!userId) {
            console.warn('Missing userId when triggering notification:', title);
            return null;
        }

        // 1. Insert in-app notification into Database
        const notification = await Notification.create({
            user: userId,
            title,
            message,
            type
        });

        console.log(`In-app notification created for User [${userId}]: ${title}`);

        // Fetch user once for push and email notifications
        const user = await User.findById(userId);

        if (user) {
            // A. Dispatch Firebase Push Notification
            if (user.fcmToken) {
                sendPushNotification(user.fcmToken, {
                    title,
                    body: message,
                    data: {
                        notificationId: notification._id.toString(),
                        type
                    }
                }).catch(err => {
                    console.error(`Push notification failure to user [${userId}]:`, err.message);
                });
            }

            // B. Dispatch email if requested
            if (emailOpts && emailOpts.send && user.email) {
                const subject = emailOpts.subject || title;
                const htmlMessage = emailOpts.html || `
                    <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border: 1.5px solid #e2e8f0; border-radius: 12px;">
                        <div style="text-align: center; margin-bottom: 20px;">
                            <div style="display: inline-block; padding: 8px 16px; background-color: #6366f1; color: white; border-radius: 8px; font-weight: bold; font-size: 16px;">VR HERE</div>
                        </div>
                        <h2 style="color: #1e293b; border-bottom: 1px solid #f1f5f9; padding-bottom: 10px;">${title}</h2>
                        <p style="font-size: 14px; color: #475569; margin-top: 15px;">Hi ${user.name || 'Valued Customer'},</p>
                        <p style="font-size: 14px; color: #475569;">${message}</p>
                        <p style="font-size: 12px; color: #94a3b8; margin-top: 30px; border-top: 1px solid #f1f5f9; padding-top: 15px;">
                            This is an automated system alert from VR HERE. You can manage your notification preferences inside your web dashboard or mobile app.
                        </p>
                    </div>
                `;

                // Fire and forget or handle asynchronously to not block execution
                sendEmail({
                    email: user.email,
                    subject,
                    message: htmlMessage
                }).catch(err => {
                    console.error(`SMTP email failure to [${user.email}]:`, err.message);
                });
            }
        }

        return notification;
    } catch (error) {
        console.error('Error in triggerNotification engine:', error);
        return null;
    }
};

/**
 * Dispatches an in-app notification and email alert to all active admins.
 */
export const notifyAdmins = async ({
    title,
    message,
    type = 'System',
    email = true
}) => {
    try {
        const admins = await User.find({ role: 'admin', isActive: true });
        const notifications = [];

        for (const admin of admins) {
            const notif = await triggerNotification({
                userId: admin._id,
                title,
                message,
                type,
                emailOpts: email ? {
                    send: true,
                    subject: `VR HERE Admin Alert: ${title}`
                } : null
            });
            if (notif) notifications.push(notif);
        }

        return notifications;
    } catch (error) {
        console.error('Error notifying admins:', error);
        return [];
    }
};

/**
 * Dispatches notification to a specific employee.
 */
export const notifyEmployee = async ({
    employeeId,
    title,
    message,
    type = 'System',
    email = true
}) => {
    try {
        if (!employeeId) return null;
        return await triggerNotification({
            userId: employeeId,
            title,
            message,
            type,
            emailOpts: email ? {
                send: true,
                subject: `VR HERE Staff Action: ${title}`
            } : null
        });
    } catch (error) {
        console.error('Error notifying employee:', error);
        return null;
    }
};
