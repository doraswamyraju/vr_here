import mongoose from 'mongoose';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import colors from 'colors';
import User from './models/User.js';
import { connectDB } from './config/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load env
dotenv.config({ path: path.join(__dirname, '.env') });

const seedUsers = async () => {
    try {
        await connectDB();

        const usersToSeed = [
            {
                name: 'Doraswamy Raju',
                email: 'doraswamyraju.ca@gmail.com',
                password: 'BOHPM6139n@', // The password entered in the emulator
                role: 'client', // Default to client to test customer features
                phone: '918008530606',
                isActive: true
            },
            {
                name: 'Raju Gari Ventures',
                email: 'rajugariventures@gmail.com',
                password: 'BOHPM6139n@', // Standard password
                role: 'client',
                phone: '918008530606',
                isActive: true
            }
        ];

        for (const userData of usersToSeed) {
            const existingUser = await User.findOne({ email: userData.email });
            if (existingUser) {
                // Update existing user password and role
                existingUser.password = userData.password;
                existingUser.role = userData.role;
                existingUser.name = userData.name;
                await existingUser.save();
                console.log(`Updated existing user: ${userData.email}`);
            } else {
                // Create new user
                await User.create(userData);
                console.log(`Created new user: ${userData.email}`);
            }
        }

        console.log('User accounts successfully seeded into local database!');
        process.exit(0);
    } catch (error) {
        console.error('Error seeding users:', error);
        process.exit(1);
    }
};

seedUsers();
