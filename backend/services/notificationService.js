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

/**
 * Sends internal renewal alert to assigned employee / admin to review & update price (1-2 days before due date).
 */
export const sendInternalRenewalAlert = async ({
    subscriptionId,
    employeeId,
    clientName,
    serviceName,
    dueDate,
    currentPrice
}) => {
    const formattedDate = new Date(dueDate).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
    const title = `Renewal Alert: ${serviceName} - ${clientName}`;
    const message = `Service renewal for ${clientName} (${serviceName}) is due on ${formattedDate}. Current price is ₹${currentPrice}. Please review and update the renewal price if needed.`;

    const html = `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border: 1.5px solid #6366f1; border-radius: 12px;">
            <div style="text-align: center; margin-bottom: 20px;">
                <span style="padding: 8px 16px; background-color: #6366f1; color: white; border-radius: 8px; font-weight: bold; font-size: 16px;">VR HERE INTERNAL ALERT</span>
            </div>
            <h2 style="color: #1e293b; border-bottom: 1px solid #f1f5f9; padding-bottom: 10px;">Renewal Review Required</h2>
            <p style="font-size: 14px; color: #475569;">Upcoming service renewal needs your review:</p>
            <table style="width: 100%; border-collapse: collapse; margin: 15px 0;">
                <tr><td style="padding: 8px; color: #64748b; font-weight: bold;">Client:</td><td style="padding: 8px; color: #0f172a;">${clientName}</td></tr>
                <tr><td style="padding: 8px; color: #64748b; font-weight: bold;">Service:</td><td style="padding: 8px; color: #0f172a;">${serviceName}</td></tr>
                <tr><td style="padding: 8px; color: #64748b; font-weight: bold;">Due Date:</td><td style="padding: 8px; color: #0f172a;">${formattedDate}</td></tr>
                <tr><td style="padding: 8px; color: #64748b; font-weight: bold;">Current Price:</td><td style="padding: 8px; color: #0f172a; font-weight: bold;">₹${currentPrice}</td></tr>
            </table>
            <div style="text-align: center; margin-top: 25px;">
                <a href="${process.env.CLIENT_URL || 'http://localhost:5173'}/employee/renewals/${subscriptionId}" style="display: inline-block; padding: 12px 24px; background-color: #4f46e5; color: white; text-decoration: none; border-radius: 8px; font-weight: bold;">Review & Update Price</a>
            </div>
        </div>
    `;

    if (employeeId) {
        return await triggerNotification({
            userId: employeeId,
            title,
            message,
            type: 'System',
            emailOpts: {
                send: true,
                subject: `[Internal Alert] Renewal Review: ${serviceName} (${clientName})`,
                html
            }
        });
    } else {
        return await notifyAdmins({
            title,
            message,
            type: 'System',
            email: true
        });
    }
};

/**
 * Sends customer renewal reminder with direct payment link via Email and Push Notification.
 */
export const sendCustomerRenewalReminder = async ({
    subscriptionId,
    userId,
    clientName,
    serviceName,
    dueDate,
    price,
    paymentLink
}) => {
    const formattedDate = new Date(dueDate).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
    const title = `Renewal Reminder: ${serviceName}`;
    const message = `Your service renewal for ${serviceName} is due on ${formattedDate}. Amount due: ₹${price}. Click to pay securely.`;

    const html = `
        <div style="font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #1e293b; max-width: 600px; margin: 0 auto; padding: 24px; border: 1px solid #e2e8f0; border-radius: 16px; background-color: #ffffff;">
            <div style="text-align: center; margin-bottom: 24px;">
                <span style="padding: 8px 20px; background: linear-gradient(135deg, #4f46e5, #06b6d4); color: white; border-radius: 20px; font-weight: 700; font-size: 16px; letter-spacing: 0.5px;">VR HERE</span>
            </div>
            <h2 style="color: #0f172a; font-size: 20px; text-align: center; margin-bottom: 8px;">Service Renewal Notice</h2>
            <p style="text-align: center; color: #64748b; font-size: 14px; margin-bottom: 24px;">Hi ${clientName || 'Valued Customer'}, your service renewal is ready for payment.</p>
            
            <div style="background-color: #f8fafc; border: 1px solid #f1f5f9; border-radius: 12px; padding: 20px; margin-bottom: 24px;">
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 8px 0; color: #64748b; font-size: 14px;">Service Name</td>
                        <td style="padding: 8px 0; color: #0f172a; font-size: 14px; font-weight: 600; text-align: right;">${serviceName}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #64748b; font-size: 14px;">Due Date</td>
                        <td style="padding: 8px 0; color: #ef4444; font-size: 14px; font-weight: 600; text-align: right;">${formattedDate}</td>
                    </tr>
                    <tr style="border-top: 1px solid #e2e8f0;">
                        <td style="padding: 12px 0 4px 0; color: #0f172a; font-size: 16px; font-weight: 700;">Total Amount</td>
                        <td style="padding: 12px 0 4px 0; color: #16a34a; font-size: 20px; font-weight: 800; text-align: right;">₹${price}</td>
                    </tr>
                </table>
            </div>

            <div style="text-align: center; margin: 28px 0;">
                <a href="${paymentLink}" style="display: inline-block; padding: 14px 36px; background-color: #16a34a; color: #ffffff; text-decoration: none; border-radius: 10px; font-weight: 700; font-size: 16px; box-shadow: 0 4px 12px rgba(22, 163, 74, 0.3);">PAY NOW SECURELY</a>
            </div>

            <p style="font-size: 12px; color: #94a3b8; text-align: center; margin-top: 24px; border-top: 1px solid #f1f5f9; padding-top: 16px;">
                Secure payment powered by Razorpay for VR HERE Business Solutions. If you have any questions, reply to this email or reach out to your assigned account executive.
            </p>
        </div>
    `;

    return await triggerNotification({
        userId,
        title,
        message,
        type: 'Payment',
        emailOpts: {
            send: true,
            subject: `[Action Required] Renewal Notice: ${serviceName} - Due ${formattedDate}`,
            html
        }
    });
};

