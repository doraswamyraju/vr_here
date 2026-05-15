import mongoose from 'mongoose';
import dotenv from 'dotenv';
import colors from 'colors';
import User from './models/User.js';
import Order from './models/Order.js';
import { connectDB } from './config/db.js';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, '.env') });
connectDB();

const restoreUsers = async () => {
    try {
        const orders = await Order.find();
        let restoredCount = 0;
        
        for (let order of orders) {
            if (order.email) {
                const userExists = await User.findOne({ email: order.email });
                if (!userExists) {
                    await User.create({
                        name: order.clientName || 'Restored User',
                        email: order.email,
                        password: 'password123',
                        phone: order.phone || '',
                        role: 'client',
                        isActive: true
                    });
                    restoredCount++;
                    console.log('Restored user:', order.email);
                }
                
                // Also relink the order to the new user if user Object ID was lost
                const updatedUser = await User.findOne({ email: order.email });
                if (updatedUser && (!order.user || order.user.toString() !== updatedUser._id.toString())) {
                    order.user = updatedUser._id;
                    await order.save();
                    console.log('Linked order for:', order.email);
                }
            }
        }
        console.log('Finished. Restored ' + restoredCount + ' users.');
        process.exit();
    } catch (error) {
        console.error(error);
        process.exit(1);
    }
};

restoreUsers();
