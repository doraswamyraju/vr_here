import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import colors from 'colors';
import { connectDB } from './config/db.js';

// Load env vars
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load env vars
dotenv.config({ path: path.join(__dirname, '.env') });

// Connect to database
connectDB();

const app = express();

// Trust proxy (required for Nginx)
app.set('trust proxy', 1);

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(cors());
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: [
                    "'self'", 
                    "'unsafe-inline'", 
                    "https://cdn.tailwindcss.com", 
                    "https://checkout.razorpay.com", 
                    "https://cdn.razorpay.com",
                    "https://www.googletagmanager.com",
                    "https://livechat.vrhere.in", 
                    "https://cdn.socket.io",
                    "https://accounts.google.com",
                    "https://ssl.gstatic.com"
                ],
                styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://accounts.google.com"],
                imgSrc: ["'self'", "data:", "https://*"],
                connectSrc: [
                    "'self'", 
                    "https://api.razorpay.com", 
                    "https://lumberjack.razorpay.com", 
                    "https://cdn.socket.io",
                    "https://www.googletagmanager.com",
                    "https://www.google-analytics.com",
                    "http://localhost:5000", 
                    "http://localhost:5002", 
                    "http://147.95.107.21:5002", 
                    "https://livechat.vrhere.in", 
                    "wss://livechat.vrhere.in",
                    "https://accounts.google.com",
                    "https://oauth2.googleapis.com",
                    "https://www.googleapis.com"
                ],
                frameSrc: ["'self'", "https://api.razorpay.com", "https://accounts.google.com"],
                upgradeInsecureRequests: null, // Disable HTTPS upgrade for successful HTTP load
            },
        },
        crossOriginEmbedderPolicy: false,
    })
);
app.use(morgan('dev')); // Logging


import authRoutes from './routes/authRoutes.js';
import orderRoutes from './routes/orderRoutes.js';
import ticketRoutes from './routes/ticketRoutes.js';
import paymentRoutes from './routes/paymentRoutes.js';
import notificationRoutes from './routes/notificationRoutes.js';
import serviceMenuRoutes from './routes/serviceMenuRoutes.js';
import attendanceRoutes from './routes/attendanceRoutes.js';
import contactRoutes from './routes/contactRoutes.js';
import todoRoutes from './routes/todoRoutes.js';
import recurringRoutes from './routes/recurringRoutes.js';
import partnerRoutes from './routes/partnerRoutes.js';
import financeRoutes from './routes/financeRoutes.js';
import complianceRoutes from './routes/complianceRoutes.js';
import webmailRoutes from './routes/webmailRoutes.js';
import hrmsRoutes from './routes/hrmsRoutes.js';
import servicePageRoutes from './routes/servicePageRoutes.js';
import cityRoutes from './routes/cityRoutes.js';
import freelancerRoutes from './routes/freelancerRoutes.js';
import incomeTaxAssessmentRoutes from './routes/incomeTaxAssessmentRoutes.js';
import accountingRoutes from './routes/accountingRoutes.js';
import leadRoutes from './routes/leadRoutes.js';
import renewalRoutes from './routes/renewalRoutes.js';
import { initCronJobs } from './services/cronService.js';

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/tickets', ticketRoutes);
app.use('/api/todos', todoRoutes);
app.use('/api/payments', paymentRoutes);
app.use('/api/notifications', notificationRoutes);
app.use('/api/services', serviceMenuRoutes);
app.use('/api/attendance', attendanceRoutes);
app.use('/api/contact', contactRoutes);
app.use('/api/recurring', recurringRoutes);
app.use('/api/renewals', renewalRoutes);
app.use('/api/partner', partnerRoutes);
app.use('/api/finance', financeRoutes);
app.use('/api/compliance', complianceRoutes);
app.use('/api/webmail', webmailRoutes);
app.use('/api/hrms', hrmsRoutes);
app.use('/api/service-pages', servicePageRoutes);
app.use('/api/cities', cityRoutes);
app.use('/api/freelancer', freelancerRoutes);
app.use('/api/income-tax-assessment', incomeTaxAssessmentRoutes);
app.use('/api/accounting', accountingRoutes);
app.use('/api/leads', leadRoutes);

// Serve Frontend in Production


// Ensure uploads folder is accessible
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.join(__dirname, '../dist')));

    app.get('*', (req, res) =>
        res.sendFile(path.resolve(__dirname, '../', 'dist', 'index.html'))
    );
} else {
    app.get('/', (req, res) => {
        res.send('API is running...');
    });
}

// Error Handling Middleware
app.use((err, req, res, next) => {
    const statusCode = res.statusCode === 200 ? 500 : res.statusCode;
    res.status(statusCode);
    res.json({
        message: err.message,
        stack: process.env.NODE_ENV === 'production' ? null : err.stack,
    });
});

initCronJobs();

const PORT = process.env.PORT || 5002;

app.listen(PORT, console.log(`Server running in ${process.env.NODE_ENV} mode on port ${PORT}`.yellow.bold));
