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
app.use(express.json());
app.use(cors());
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://checkout.razorpay.com"],
                styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
                imgSrc: ["'self'", "data:", "https://*"],
                connectSrc: ["'self'", "https://api.razorpay.com", "https://lumberjack.razorpay.com", "http://localhost:5000", "http://localhost:5002", "http://147.93.107.21:5002"],
                frameSrc: ["'self'", "https://api.razorpay.com"],
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

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/tickets', ticketRoutes);
app.use('/api/payments', paymentRoutes);
app.use('/api/notifications', notificationRoutes);
app.use('/api/services', serviceMenuRoutes);
app.use('/api/attendance', attendanceRoutes);
app.use('/api/contact', contactRoutes);

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

const PORT = process.env.PORT || 5002;

app.listen(PORT, console.log(`Server running in ${process.env.NODE_ENV} mode on port ${PORT}`.yellow.bold));
