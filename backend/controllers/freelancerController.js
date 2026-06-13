import asyncHandler from 'express-async-handler';
import User from '../models/User.js';
import Order from '../models/Order.js';
import Payout from '../models/Payout.js';
import jwt from 'jsonwebtoken';

const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: '30d',
    });
};

// @desc    Register a new freelancer
// @route   POST /api/freelancer/register
// @access  Public
const registerFreelancer = asyncHandler(async (req, res) => {
    const { name, email, password, phone, skills, yearsOfExperience, resumeUrl, bankDetails, panCard } = req.body;

    const userExists = await User.findOne({ email });

    if (userExists) {
        res.status(400);
        throw new Error('User already exists');
    }

    const user = await User.create({
        name,
        email,
        password,
        phone,
        role: 'freelancer',
        isActive: false, // Pending Admin Approval
        skills: skills || [],
        yearsOfExperience: yearsOfExperience || 0,
        resumeUrl: resumeUrl || '',
        panCard: panCard || null,
        bankDetails: bankDetails || {
            accountName: '',
            accountNumber: '',
            ifscCode: '',
            bankName: ''
        }
    });

    if (user) {
        res.status(201).json({
            _id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            isActive: user.isActive,
            token: generateToken(user._id),
        });
    } else {
        res.status(400);
        throw new Error('Invalid user data');
    }
});

// @desc    Get broadcasted orders matching freelancer skills
// @route   GET /api/freelancer/broadcasts
// @access  Private (Freelancer)
const getBroadcastedOrders = asyncHandler(async (req, res) => {
    if (req.user.role !== 'freelancer') {
        res.status(403);
        throw new Error('Access denied');
    }

    // Get broadcasted orders which are not claimed yet
    const query = {
        broadcastStatus: 'Broadcasted',
        assignedFreelancer: null
    };

    const orders = await Order.find(query)
        .select('serviceName packageName price freelancerPayout status createdAt')
        .sort({ createdAt: -1 });

    res.json(orders);
});

// @desc    Claim a broadcasted order (First-Come, First-Served)
// @route   POST /api/freelancer/claim/:id
// @access  Private (Freelancer)
const claimOrder = asyncHandler(async (req, res) => {
    if (req.user.role !== 'freelancer') {
        res.status(403);
        throw new Error('Access denied');
    }

    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (order.broadcastStatus !== 'Broadcasted' || order.assignedFreelancer) {
        res.status(400);
        throw new Error('Order has already been claimed or is not available');
    }

    order.assignedFreelancer = req.user._id;
    order.broadcastStatus = 'Claimed';
    
    // Set as assigned Employee/Maker so it shows up in their workspace if checker expects that
    order.assignedEmployee = req.user._id;

    await order.save();

    res.json({ message: 'Order claimed successfully', order });
});

// @desc    Clock-In to start work on an order
// @route   POST /api/freelancer/clock-in/:id
// @access  Private (Freelancer)
const clockIn = asyncHandler(async (req, res) => {
    if (req.user.role !== 'freelancer') {
        res.status(403);
        throw new Error('Access denied');
    }

    const order = await Order.findById(req.params.id);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (order.assignedFreelancer.toString() !== req.user._id.toString()) {
        res.status(403);
        throw new Error('Not authorized to work on this order');
    }

    const user = await User.findById(req.user._id);
    if (user.isClockedIn) {
        res.status(400);
        throw new Error('Already clocked in to another order');
    }

    user.isClockedIn = true;
    user.lastClockInTime = new Date();
    user.activeOrderId = order._id;
    await user.save();

    res.json({ message: 'Clocked in successfully', user });
});

// @desc    Clock-Out to pause/stop work on an order
// @route   POST /api/freelancer/clock-out/:id
// @access  Private (Freelancer)
const clockOut = asyncHandler(async (req, res) => {
    if (req.user.role !== 'freelancer') {
        res.status(403);
        throw new Error('Access denied');
    }

    const order = await Order.findById(req.params.id);
    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    const user = await User.findById(req.user._id);
    if (!user.isClockedIn || user.activeOrderId?.toString() !== order._id.toString()) {
        res.status(400);
        throw new Error('Not clocked in to this order');
    }

    const clockInTime = new Date(user.lastClockInTime);
    const clockOutTime = new Date();
    const durationMs = clockOutTime - clockInTime;
    const minutes = Math.max(1, Math.round(durationMs / 60000)); // Round to nearest minute, minimum 1 min

    // Save time log
    order.freelancerTimeLogs.push({
        freelancer: user._id,
        minutes
    });
    await order.save();

    user.isClockedIn = false;
    user.lastClockInTime = null;
    user.activeOrderId = null;
    await user.save();

    res.json({ message: 'Clocked out successfully', minutesLogged: minutes, user });
});

// @desc    Get current freelancer's active & completed orders
// @route   GET /api/freelancer/orders
// @access  Private (Freelancer)
const getFreelancerOrders = asyncHandler(async (req, res) => {
    if (req.user.role !== 'freelancer') {
        res.status(403);
        throw new Error('Access denied');
    }

    const orders = await Order.find({ assignedFreelancer: req.user._id })
        .populate('user', 'name email')
        .sort({ updatedAt: -1 });

    res.json(orders);
});

// @desc    Get current freelancer's payout ledger
// @route   GET /api/freelancer/ledger
// @access  Private (Freelancer)
const getFreelancerLedger = asyncHandler(async (req, res) => {
    if (req.user.role !== 'freelancer') {
        res.status(403);
        throw new Error('Access denied');
    }

    const payouts = await Payout.find({ freelancer: req.user._id })
        .populate('order', 'serviceName packageName status')
        .sort({ createdAt: -1 });

    res.json(payouts);
});

// @desc    Admin Broadcast Order to Freelancers
// @route   PUT /api/freelancer/admin/broadcast/:orderId
// @access  Private (Admin)
const adminBroadcastOrder = asyncHandler(async (req, res) => {
    const { payoutAmount } = req.body;
    const order = await Order.findById(req.params.orderId);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    order.freelancerPayout = payoutAmount || 0;
    order.broadcastStatus = 'Broadcasted';
    await order.save();

    res.json({ message: 'Order broadcasted successfully', order });
});

// @desc    Admin / Checker approve order completion and finalize payout
// @route   POST /api/freelancer/admin/approve-payout/:orderId
// @access  Private (Admin/Checker)
const checkerApproveOrderPayout = asyncHandler(async (req, res) => {
    const order = await Order.findById(req.params.orderId);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (!order.assignedFreelancer) {
        res.status(400);
        throw new Error('This order is not assigned to a freelancer');
    }

    // Check if payout already exists
    let payout = await Payout.findOne({ order: order._id, freelancer: order.assignedFreelancer });

    if (payout) {
        if (payout.status !== 'Pending Approval') {
            res.status(400);
            throw new Error('Payout has already been processed or approved');
        }
        payout.status = 'Approved';
        payout.amount = order.freelancerPayout;
        await payout.save();
    } else {
        payout = await Payout.create({
            freelancer: order.assignedFreelancer,
            order: order._id,
            amount: order.freelancerPayout,
            status: 'Approved'
        });
    }

    res.json({ message: 'Payout approved successfully', payout });
});

// @desc    Admin review and approve freelancer registration
// @route   PUT /api/freelancer/admin/approve-user/:userId
// @access  Private (Admin)
const adminApproveFreelancer = asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.userId);

    if (!user || user.role !== 'freelancer') {
        res.status(404);
        throw new Error('Freelancer not found');
    }

    user.isActive = true;
    await user.save();

    res.json({ message: 'Freelancer account approved successfully', user });
});

// @desc    Get all pending or active freelancers
// @route   GET /api/freelancer/admin/users
// @access  Private (Admin)
const adminGetFreelancers = asyncHandler(async (req, res) => {
    const freelancers = await User.find({ role: 'freelancer' }).select('-password');
    res.json(freelancers);
});

// @desc    Get all payouts for admin treasury screen
// @route   GET /api/freelancer/admin/payouts
// @access  Private (Admin)
const adminGetPayouts = asyncHandler(async (req, res) => {
    const payouts = await Payout.find({})
        .populate('freelancer', 'name email bankDetails panCard')
        .populate('order', 'serviceName packageName price status')
        .sort({ createdAt: -1 });

    res.json(payouts);
});

// @desc    Admin log processed bank payment
// @route   PUT /api/freelancer/admin/pay/:payoutId
// @access  Private (Admin)
const adminPayFreelancer = asyncHandler(async (req, res) => {
    const { method, transactionRef, notes } = req.body;
    const payout = await Payout.findById(req.params.payoutId);

    if (!payout) {
        res.status(404);
        throw new Error('Payout ledger entry not found');
    }

    payout.status = 'Paid';
    payout.method = method || 'NEFT';
    payout.transactionRef = transactionRef || '';
    payout.notes = notes || '';
    payout.paidAt = new Date();
    await payout.save();

    res.json({ message: 'Payout marked as paid successfully', payout });
});

// @desc    Get live status of all freelancers & employees clocked in
// @route   GET /api/freelancer/admin/live-attendance
// @access  Private (Admin)
const adminGetLiveAttendance = asyncHandler(async (req, res) => {
    const liveUsers = await User.find({ 
        isClockedIn: true, 
        role: { $in: ['employee', 'freelancer'] } 
    })
    .select('name email role lastClockInTime activeOrderId')
    .populate('activeOrderId', 'serviceName packageName');

    res.json(liveUsers);
});

// @desc    Admin reassign or remove freelancer from order
// @route   POST /api/freelancer/admin/reassign/:orderId
// @access  Private (Admin)
const adminReassignOrder = asyncHandler(async (req, res) => {
    const { freelancerId } = req.body;
    const order = await Order.findById(req.params.orderId);

    if (!order) {
        res.status(404);
        throw new Error('Order not found');
    }

    if (freelancerId) {
        const freelancer = await User.findById(freelancerId);
        if (!freelancer || freelancer.role !== 'freelancer') {
            res.status(404);
            throw new Error('Freelancer not found');
        }
        order.assignedFreelancer = freelancer._id;
        order.broadcastStatus = 'Claimed';
        order.assignedEmployee = freelancer._id;
    } else {
        // Unassign
        order.assignedFreelancer = null;
        order.broadcastStatus = 'Pending';
        order.assignedEmployee = null;
    }

    await order.save();
    res.json({ message: 'Freelancer assignment updated successfully', order });
});

// @desc    Admin update freelancer details
// @route   PUT /api/freelancer/admin/users/:userId
// @access  Private (Admin)
const adminUpdateFreelancer = asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.userId);

    if (!user || user.role !== 'freelancer') {
        res.status(404);
        throw new Error('Freelancer not found');
    }

    user.name = req.body.name || user.name;
    user.email = req.body.email || user.email;
    user.phone = req.body.phone || user.phone;
    user.skills = req.body.skills || user.skills;
    user.yearsOfExperience = req.body.yearsOfExperience !== undefined ? req.body.yearsOfExperience : user.yearsOfExperience;
    user.panCard = req.body.panCard !== undefined ? req.body.panCard : user.panCard;
    user.bankDetails = req.body.bankDetails || user.bankDetails;
    user.isActive = req.body.isActive !== undefined ? req.body.isActive : user.isActive;

    if (req.body.password) {
        user.password = req.body.password;
    }

    const updatedUser = await user.save();
    res.json(updatedUser);
});

// @desc    Admin delete freelancer
// @route   DELETE /api/freelancer/admin/users/:userId
// @access  Private (Admin)
const adminDeleteFreelancer = asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.userId);

    if (!user || user.role !== 'freelancer') {
        res.status(404);
        throw new Error('Freelancer not found');
    }

    await user.deleteOne();
    res.json({ message: 'Freelancer deleted successfully' });
});

export {
    registerFreelancer,
    getBroadcastedOrders,
    claimOrder,
    clockIn,
    clockOut,
    getFreelancerOrders,
    getFreelancerLedger,
    adminBroadcastOrder,
    checkerApproveOrderPayout,
    adminApproveFreelancer,
    adminGetFreelancers,
    adminGetPayouts,
    adminPayFreelancer,
    adminGetLiveAttendance,
    adminReassignOrder,
    adminUpdateFreelancer,
    adminDeleteFreelancer
};
