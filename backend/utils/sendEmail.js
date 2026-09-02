import nodemailer from 'nodemailer';

const sendEmail = async (options) => {
    try {
        if (!process.env.SMTP_EMAIL || !process.env.SMTP_PASSWORD) {
            console.warn('[SMTP] Missing SMTP credentials, skipping email to:', options?.email);
            return { success: false, reason: 'Credentials not configured' };
        }

        const transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST || 'smtp.gmail.com',
            port: process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587,
            secure: process.env.SMTP_SECURE === 'true', // Use SMTP_SECURE=true for 465, false for 587
            auth: {
                user: process.env.SMTP_EMAIL,
                pass: process.env.SMTP_PASSWORD,
            },
        });

        const message = {
            from: `${process.env.FROM_NAME || 'VR HERE'} <${process.env.FROM_EMAIL || process.env.SMTP_EMAIL}>`,
            to: options.email,
            subject: options.subject,
            html: options.message || options.html, // Use HTML for better styling
        };

        const info = await transporter.sendMail(message);
        console.log('Message sent: %s', info.messageId);
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error(`SMTP email failure to [${options?.email}]:`, error.message);
        return { success: false, error: error.message };
    }
};

export default sendEmail;
