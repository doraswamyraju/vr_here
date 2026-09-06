import asyncHandler from 'express-async-handler';
import User from '../models/User.js';
import CustomerReferral from '../models/CustomerReferral.js';
import { triggerNotification, notifyAdmins } from '../services/notificationService.js';

// Helper to ensure customer has a referral code
const ensureReferralCode = async (user) => {
    if (!user.referralCode) {
        const cleanPhone = (user.phone || '').replace(/\D/g, '').slice(-10);
        const suffix = cleanPhone || user._id.toString().slice(-6).toUpperCase();
        let code = `VR-${suffix}`;
        
        // Ensure uniqueness
        const existing = await User.findOne({ referralCode: code });
        if (existing && String(existing._id) !== String(user._id)) {
            code = `VR-${suffix}-${Math.floor(100 + Math.random() * 900)}`;
        }
        user.referralCode = code;
        await user.save();
    }
    return user.referralCode;
};

// @desc    Get customer referral dashboard statistics and leads list
// @route   GET /api/customer/referrals/stats
// @access  Private (Client / Customer)
export const getReferralStats = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);
    if (!user) {
        res.status(404);
        throw new Error('User not found');
    }

    const referralCode = await ensureReferralCode(user);
    const referrals = await CustomerReferral.find({ referrer: user._id })
        .populate('order', 'serviceName packageName price status createdAt')
        .sort({ createdAt: -1 });

    const totalInvited = referrals.length;
    const successfulConversions = referrals.filter(r => r.status === 'Rewarded' || r.status === 'Order_Placed').length;
    const totalEarned = referrals.filter(r => r.status === 'Rewarded').reduce((sum, r) => sum + (r.rewardAmount || 500), 0);

    res.json({
        success: true,
        referralCode,
        referralLink: `https://vrhere.in/ref?code=${referralCode}`,
        walletBalance: user.walletBalance || 0,
        savedUpiId: user.savedUpiId || '',
        totalInvited,
        successfulConversions,
        totalEarned,
        rewardPerReferral: 500,
        referrals
    });
});

// @desc    Add a direct friend / contact referral lead
// @route   POST /api/customer/referrals/lead
// @access  Private (Client / Customer)
export const addReferralLead = asyncHandler(async (req, res) => {
    const { name, phone, email, interestedService } = req.body;

    if (!name || !name.trim()) {
        res.status(400);
        throw new Error('Contact Name is required');
    }

    if (!phone || !phone.trim()) {
        res.status(400);
        throw new Error('Contact Mobile Number is required');
    }

    const cleanPhone = phone.replace(/\D/g, '').slice(-10);
    if (cleanPhone.length !== 10) {
        res.status(400);
        throw new Error('Please enter a valid 10-digit mobile number');
    }

    const user = await User.findById(req.user._id);
    await ensureReferralCode(user);

    // Check if user already added this number
    const existing = await CustomerReferral.findOne({
        referrer: user._id,
        refereePhone: cleanPhone
    });

    if (existing) {
        res.status(400);
        throw new Error(`You have already referred this contact (${cleanPhone}). Current status: ${existing.status}`);
    }

    // Check if referee is already a registered user
    const existingUser = await User.findOne({ phone: { $regex: cleanPhone } });

    const referral = await CustomerReferral.create({
        referrer: user._id,
        referee: existingUser ? existingUser._id : null,
        refereeName: name.trim(),
        refereePhone: cleanPhone,
        refereeEmail: (email || '').trim().toLowerCase(),
        interestedService: interestedService || 'General Compliance / Registration',
        status: existingUser ? 'Registered' : 'Invited',
        rewardAmount: 500
    });

    // Notify admins for sales outreach
    try {
        await notifyAdmins({
            title: 'New Customer Referral Lead 🎁',
            message: `Customer ${user.name} referred ${name.trim()} (${cleanPhone}) for "${interestedService || 'Compliance'}".`,
            type: 'Order',
            email: false
        });
    } catch (err) {
        console.error('Non-blocking lead notification err:', err.message);
    }

    res.status(201).json({
        success: true,
        message: `Referral for ${name.trim()} added successfully! You will receive ₹500 once their first order is completed.`,
        referral
    });
});

// @desc    Validate referral code (phone or code)
// @route   GET /api/customer/referrals/validate/:code
// @access  Public
export const validateCustomerReferralCode = asyncHandler(async (req, res) => {
    const { code } = req.params;
    if (!code) {
        res.status(400);
        throw new Error('Referral code is required');
    }

    const cleanCode = code.trim().toUpperCase();
    const cleanPhone = code.replace(/\D/g, '').slice(-10);

    const referrer = await User.findOne({
        $or: [
            { referralCode: cleanCode },
            { phone: cleanPhone.length === 10 ? cleanPhone : 'NONE' }
        ]
    }).select('name email phone referralCode role');

    if (!referrer) {
        res.status(404);
        throw new Error('Invalid referral code. Please check and try again.');
    }

    res.json({
        success: true,
        referrerName: referrer.name,
        referralCode: referrer.referralCode || cleanCode,
        rewardMessage: '₹500 Referral Bonus applied!'
    });
});

// @desc    Request UPI Payout for referral wallet balance
// @route   POST /api/customer/referrals/payout-request
// @access  Private (Client / Customer)
export const requestUpiPayout = asyncHandler(async (req, res) => {
    const { amount, upiId } = req.body;
    const user = await User.findById(req.user._id);

    if (!user) {
        res.status(404);
        throw new Error('User not found');
    }

    if (!upiId || !upiId.trim() || !upiId.includes('@')) {
        res.status(400);
        throw new Error('Please enter a valid UPI ID (e.g. name@okhdfcbank or 9876543210@paytm)');
    }

    const payoutAmount = Number(amount) || (user.walletBalance || 0);

    if (payoutAmount < 500) {
        res.status(400);
        throw new Error('Minimum withdrawal amount is ₹500.');
    }

    if ((user.walletBalance || 0) < payoutAmount) {
        res.status(400);
        throw new Error(`Insufficient wallet balance. Available: ₹${user.walletBalance || 0}`);
    }

    user.walletBalance -= payoutAmount;
    user.savedUpiId = upiId.trim();
    await user.save();

    // Mark referral items as pending payout
    await CustomerReferral.updateMany(
        { referrer: user._id, status: 'Rewarded', payoutStatus: 'None' },
        {
            $set: {
                payoutUpi: upiId.trim(),
                payoutStatus: 'Pending',
                payoutRequestedAt: new Date(),
                rewardClaimedVia: 'UPI_Payout'
            }
        }
    );

    // Notify Admins to process payout
    try {
        await notifyAdmins({
            title: '💸 Customer Referral UPI Payout Request',
            message: `Customer ${user.name} (${user.phone}) requested payout of ₹${payoutAmount} to UPI ID: ${upiId.trim()}`,
            type: 'Financial',
            email: false
        });
    } catch (err) {
        console.error('Non-blocking payout notification err:', err.message);
    }

    res.json({
        success: true,
        message: `Payout request of ₹${payoutAmount} to UPI ID ${upiId.trim()} has been submitted. Funds will be transferred within 24 hours.`,
        remainingBalance: user.walletBalance
    });
});

// @desc    Admin: Get all customer referrals and payout requests
// @route   GET /api/customer/referrals/admin/all
// @access  Private (Admin)
export const getAllReferralsAdmin = asyncHandler(async (req, res) => {
    const referrals = await CustomerReferral.find({})
        .populate('referrer', 'name email phone walletBalance savedUpiId')
        .populate('referee', 'name email phone')
        .populate('order', 'serviceName price status createdAt')
        .sort({ createdAt: -1 });

    res.json({
        success: true,
        count: referrals.length,
        referrals
    });
});
