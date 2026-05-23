import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import path from 'path';

// Load env from backend
dotenv.config();

console.log('Testing SMTP connection with settings:');
console.log('Host:', process.env.SMTP_HOST);
console.log('Port:', process.env.SMTP_PORT);
console.log('Email:', process.env.SMTP_EMAIL);

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
        user: process.env.SMTP_EMAIL,
        pass: process.env.SMTP_PASSWORD,
    },
});

transporter.verify((error, success) => {
    if (error) {
        console.error('SMTP Connection Failed:', error);
    } else {
        console.log('SMTP Server is ready to take our messages!');
    }
});
