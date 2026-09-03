import nodemailer from 'nodemailer';

const sendEmail = async (options) => {
    try {
        if (!process.env.SMTP_EMAIL || !process.env.SMTP_PASSWORD) {
            const reason = 'Missing SMTP credentials in environment variables (SMTP_EMAIL / SMTP_PASSWORD)';
            console.warn('[SMTP]', reason, 'skipping email to:', options?.email);
            return { success: false, reason, error: reason };
        }

        const transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST || 'smtp.gmail.com',
            port: process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587,
            secure: process.env.SMTP_SECURE === 'true' || Number(process.env.SMTP_PORT) === 465,
            auth: {
                user: process.env.SMTP_EMAIL,
                pass: process.env.SMTP_PASSWORD,
            },
            tls: {
                rejectUnauthorized: false
            }
        });

        const message = {
            from: `${process.env.FROM_NAME || 'VR HERE'} <${process.env.FROM_EMAIL || process.env.SMTP_EMAIL}>`,
            to: options.email,
            subject: options.subject,
            html: options.message || options.html,
        };

        const info = await transporter.sendMail(message);
        console.log('[SMTP] Message sent successfully to %s: %s', options.email, info.messageId);
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error(`[SMTP] Delivery failure to [${options?.email}]:`, error.message);
        return { success: false, error: error.message };
    }
};

export default sendEmail;
