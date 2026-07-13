import mongoose from 'mongoose';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import colors from 'colors';
import User from '../models/User.js';
import { connectDB } from '../config/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const updatePassword = async () => {
    try {
        await connectDB();

        const email = 'admin@vrhere.in';
        const newPassword = 'Rajugari@2026';

        const user = await User.findOne({ email });
        if (user) {
            user.password = newPassword;
            await user.save();
            console.log(`Successfully updated password for ${email} on VPS database`);
        } else {
            console.log(`User ${email} not found. Creating admin user...`);
            await User.create({
                name: 'Admin User',
                email: email,
                password: newPassword,
                role: 'admin',
                phone: '918008530606'
            });
            console.log(`Created new admin user with email ${email}`);
        }
        process.exit(0);
    } catch (error) {
        console.error('Error updating password:', error);
        process.exit(1);
    }
};

updatePassword();
