import mongoose from 'mongoose';
import dotenv from 'dotenv';
import colors from 'colors';
import User from './models/User.js';
import { connectDB } from './config/db.js';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, '.env') });

connectDB();

const importData = async () => {
    try {
        await User.deleteMany();

        const users = [
            {
                name: 'Admin User',
                email: 'admin@vrhere.in',
                password: 'admin123',
                role: 'admin',
                phone: '918008530606'
            },
            {
                name: 'Staff Member',
                email: 'staff@vrhere.in',
                password: 'staff123',
                role: 'employee',
                phone: '918008530606'
            },
            {
                name: 'Regular Customer',
                email: 'user@vrhere.in',
                password: 'user123',
                role: 'client',
                phone: '918008530606'
            },
        ];

        await User.create(users);

        console.log('Data Imported!'.green.inverse);
        process.exit();
    } catch (error) {
        console.error(`${error}`.red.inverse);
        process.exit(1);
    }
};

if (process.argv[2] === '-d') {
    // delete logic if needed
} else {
    importData();
}
