import asyncHandler from 'express-async-handler';
import sendEmail from '../utils/sendEmail.js';

// @desc    Submit Contact Form
// @route   POST /api/contact
// @access  Public
export const submitContactForm = asyncHandler(async (req, res) => {
    const { name, phone, email, service, message } = req.body;

    if (!name || !phone || !email) {
        res.status(400);
        throw new Error('Please provide name, email, and phone number');
    }

    // 1. Send Email to Admin (vrherebms@gmail.com)
    const adminHtml = `
        <h2>New Inquiry from Website</h2>
        <p>You have received a new contact inquiry with the following details:</p>
        <table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%; max-width: 600px;">
            <tr><th align="left">Name</th><td>${name}</td></tr>
            <tr><th align="left">Phone</th><td>${phone}</td></tr>
            <tr><th align="left">Email</th><td>${email}</td></tr>
            <tr><th align="left">Service Interested</th><td>${service || 'N/A'}</td></tr>
        </table>
        <br/>
        <h3>Message:</h3>
        <p>${message || 'No message provided.'}</p>
    `;

    try {
        await sendEmail({
            email: 'vrherebms@gmail.com',
            subject: `New Lead: ${service || 'General Inquiry'} - ${name}`,
            message: adminHtml
        });
    } catch (error) {
        console.error('Failed to send email to admin:', error);
        // We continue so the user still gets their confirmation and success response
    }

    // 2. Send Acknowledgement Email to User
    const userHtml = `
        <h2>Hello ${name},</h2>
        <p>Thank you for contacting VR HERE! We have received your inquiry regarding <b>${service ? service : 'our services'}</b>.</p>
        <p>One of our experts will get back to you shortly at ${phone}.</p>
        <br/>
        <p>Best Regards,</p>
        <p><b>Team VR HERE</b></p>
        <p><a href="https://vrhere.in">vrhere.in</a></p>
    `;

    try {
        await sendEmail({
            email,
            subject: `Thank you for contacting VR HERE`,
            message: userHtml
        });
    } catch (error) {
        console.error('Failed to send email to user:', error);
    }

    res.status(200).json({ success: true, message: 'Inquiry submitted successfully' });
});
