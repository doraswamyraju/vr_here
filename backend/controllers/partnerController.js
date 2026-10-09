import asyncHandler from 'express-async-handler';
import { randomBytes, createHash } from 'crypto';
import Order from '../models/Order.js';
import User from '../models/User.js';
import PartnerPayout from '../models/PartnerPayout.js';
import sendEmail from '../utils/sendEmail.js';
import { generateAndEmailInvoice } from '../utils/invoiceHelper.js';
import { triggerNotification, notifyAdmins } from '../services/notificationService.js';

const buildResetUrl = (token) => {
    const baseUrl = process.env.FRONTEND_URL || 'https://vrhere.in';
    return `${baseUrl.replace(/\/$/, '')}/reset-password/${token}`;
};

const sendPasswordSetupEmail = async (user, token, subject = 'Set Your VR HERE Password') => {
    const resetUrl = buildResetUrl(token);
    const message = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 24px; border: 1px solid #e2e8f0; border-radius: 16px; background-color: #ffffff;">
            <div style="text-align: center; margin-bottom: 24px;">
                <h2 style="color: #4f46e5; margin: 0; font-size: 24px; font-weight: 800;">VR HERE Business Solutions</h2>
            </div>
            <h3 style="color: #1e293b; margin-top: 0;">Hello ${user.name || 'User'},</h3>
            <p style="color: #475569; font-size: 15px; line-height: 1.6;">Your customer account on the VR HERE Platform has been created by your partner. Click the button below to set your password and access your dashboard to track service filings, invoices, and documents.</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="${resetUrl}" style="background: #4f46e5; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 10px; font-weight: bold; font-size: 15px; display: inline-block;">Set / Reset Password</a>
            </div>
            <p style="color: #64748b; font-size: 13px; margin-bottom: 6px;">If the button above does not work, copy and paste this link into your browser:</p>
            <p style="background: #f1f5f9; padding: 10px 14px; border-radius: 8px; font-size: 13px; color: #4f46e5; word-break: break-all; margin: 0;">
                <a href="${resetUrl}" style="color: #4f46e5; text-decoration: underline;">${resetUrl}</a>
            </p>
            <p style="color: #94a3b8; font-size: 12px; margin-top: 28px; border-top: 1px solid #f1f5f9; padding-top: 14px;">This security link is valid for 24 hours. If you did not request this, please ignore this email or contact support.</p>
        </div>
    `;

    return await sendEmail({
        email: user.email,
        subject,
        message
    });
};

// @desc    Get orders securely for the logged-in referral partner
// @route   GET /api/partner/orders
// @access  Private (Partner)
const getPartnerOrders = asyncHandler(async (req, res) => {
    if (req.user.role !== 'partner') {
        res.status(403);
        throw new Error('Access denied. Only partners can view this data.');
    }

    const orders = await Order.find({ referralPartner: req.user._id })
        .populate('user', 'name email phone companyName gstin')
        .select('serviceName packageName clientName email phone price status paymentStatus partnerCommissionAmount createdAt invoices')
        .sort({ createdAt: -1 });

    res.json(orders);
});

// @desc    Get detailed earnings, commissions, and payout summary for partner
// @route   GET /api/partner/earnings
// @access  Private (Partner)
const getPartnerEarnings = asyncHandler(async (req, res) => {
    if (req.user.role !== 'partner') {
        res.status(403);
        throw new Error('Access denied. Only partners can view this data.');
    }

    const orders = await Order.find({ referralPartner: req.user._id })
        .populate('user', 'name email phone companyName gstin')
        .select('serviceName packageName clientName email phone price status paymentStatus partnerCommissionAmount createdAt invoices')
        .sort({ createdAt: -1 });

    const payouts = await PartnerPayout.find({ partner: req.user._id }).sort({ createdAt: -1 });

    const lifetimeRevenue = orders.reduce((sum, o) => sum + (Number(o.price) || 0), 0);
    const totalCommissionEarned = orders
        .filter(o => o.paymentStatus === 'Paid')
        .reduce((sum, o) => sum + (Number(o.partnerCommissionAmount) || 0), 0);

    const pendingOrdersCommission = orders
        .filter(o => o.paymentStatus !== 'Paid')
        .reduce((sum, o) => sum + (Number(o.partnerCommissionAmount) || 0), 0);

    const paidPayouts = payouts
        .filter(p => p.status === 'Paid')
        .reduce((sum, p) => sum + (Number(p.amount) || 0), 0);

    const pendingPayouts = payouts
        .filter(p => p.status === 'Pending' || p.status === 'Approved')
        .reduce((sum, p) => sum + (Number(p.amount) || 0), 0);

    const availableWithdrawBalance = Math.max(0, totalCommissionEarned - paidPayouts - pendingPayouts);

    res.json({
        lifetimeRevenue,
        totalCommissionEarned,
        pendingOrdersCommission,
        paidPayouts,
        pendingPayouts,
        availableWithdrawBalance,
        commissionPercentage: req.user.commissionPercentage || 10,
        orders,
        payouts
    });
});

// @desc    Get all customers linked to this partner
// @route   GET /api/partner/customers
// @access  Private (Partner)
const getPartnerCustomers = asyncHandler(async (req, res) => {
    if (req.user.role !== 'partner') {
        res.status(403);
        throw new Error('Access denied. Only partners can view this data.');
    }

    // 1. Customers explicitly linked via referredByPartner
    const directClients = await User.find({ 
        role: 'client',
        referredByPartner: req.user._id 
    }).select('name email phone companyName gstin isActive createdAt').lean();

    // 2. Customers who placed orders with this partner
    const partnerOrders = await Order.find({ referralPartner: req.user._id })
        .select('user clientName email phone price status paymentStatus partnerCommissionAmount createdAt')
        .lean();

    const clientMap = new Map();

    directClients.forEach(c => {
        clientMap.set(c._id.toString(), {
            ...c,
            totalOrders: 0,
            totalSpend: 0,
            totalCommission: 0,
            orders: []
        });
    });

    partnerOrders.forEach(ord => {
        const uId = ord.user ? ord.user.toString() : null;
        if (uId && clientMap.has(uId)) {
            const current = clientMap.get(uId);
            current.totalOrders += 1;
            current.totalSpend += Number(ord.price || 0);
            current.totalCommission += Number(ord.partnerCommissionAmount || 0);
            current.orders.push(ord);
        } else if (uId) {
            // Found in orders but wasn't in directClients
            clientMap.set(uId, {
                _id: uId,
                name: ord.clientName || 'Client',
                email: ord.email || '',
                phone: ord.phone || '',
                companyName: '',
                gstin: '',
                isActive: true,
                createdAt: ord.createdAt,
                totalOrders: 1,
                totalSpend: Number(ord.price || 0),
                totalCommission: Number(ord.partnerCommissionAmount || 0),
                orders: [ord]
            });
        }
    });

    const customerList = Array.from(clientMap.values()).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json(customerList);
});

// @desc    Add a customer under this partner (with duplicate detection for email & phone)
// @route   POST /api/partner/customers
// @access  Private (Partner)
const addPartnerCustomer = asyncHandler(async (req, res) => {
    if (req.user.role !== 'partner') {
        res.status(403);
        throw new Error('Access denied.');
    }

    const { name, email, phone, companyName = '', gstin = '' } = req.body;

    if (!name || !email) {
        res.status(400);
        throw new Error('Name and Email are required');
    }

    const normalizedEmail = email.trim().toLowerCase();
    const normalizedPhone = phone ? phone.trim() : '';

    // Check if user already exists by email OR phone
    const searchConditions = [{ email: normalizedEmail }];
    if (normalizedPhone) {
        searchConditions.push({ phone: normalizedPhone });
    }

    const existingUser = await User.findOne({ $or: searchConditions });

    if (existingUser) {
        // Check relationship
        if (existingUser.referredByPartner && existingUser.referredByPartner.toString() === req.user._id.toString()) {
            return res.json({
                success: true,
                message: 'This customer is already in your partner portfolio.',
                customer: existingUser,
                alreadyLinked: true
            });
        }

        if (existingUser.referredByPartner && existingUser.referredByPartner.toString() !== req.user._id.toString()) {
            res.status(400);
            throw new Error('This customer (email or phone) is already associated with another active referral partner account.');
        }

        // Existing user not linked to any partner -> link them to this partner!
        existingUser.referredByPartner = req.user._id;
        if (companyName && !existingUser.companyName) existingUser.companyName = companyName;
        if (gstin && !existingUser.gstin) existingUser.gstin = gstin;
        if (normalizedPhone && !existingUser.phone) existingUser.phone = normalizedPhone;
        await existingUser.save();

        return res.json({
            success: true,
            message: 'Customer is already registered on VR HERE and has now been successfully added to your partner portfolio.',
            customer: existingUser,
            newlyLinked: true
        });
    }

    // Create brand new client user
    const newUser = await User.create({
        name: name.trim(),
        email: normalizedEmail,
        phone: normalizedPhone,
        companyName: companyName.trim(),
        gstin: gstin.trim().toUpperCase(),
        role: 'client',
        referredByPartner: req.user._id,
        isActive: true
    });

    // Generate password setup token and send welcome setup email
    try {
        const resetToken = randomBytes(20).toString('hex');
        newUser.resetPasswordToken = createHash('sha256').update(resetToken).digest('hex');
        newUser.resetPasswordExpire = Date.now() + 24 * 60 * 60 * 1000;
        await newUser.save();
        await sendPasswordSetupEmail(newUser, resetToken, 'Set Your Password - Welcome to VR HERE Customer Portal');
    } catch (emailErr) {
        console.error('Failed to send welcome email to partner customer:', emailErr.message);
    }

    res.status(201).json({
        success: true,
        message: 'Customer successfully created and login setup link emailed to client.',
        customer: newUser,
        newlyCreated: true
    });
});

// @desc    Partner places Master Order on behalf of customer
// @route   POST /api/partner/orders
// @access  Private (Partner)
const createPartnerMasterOrder = asyncHandler(async (req, res) => {
    if (req.user.role !== 'partner') {
        res.status(403);
        throw new Error('Access denied. Only partners can place master orders.');
    }

    const { customerId, serviceName, packageName = 'Partner Standard', price } = req.body;

    if (!customerId || !serviceName || !price) {
        res.status(400);
        throw new Error('Customer, Service Name, and Price are required.');
    }

    const customer = await User.findById(customerId);
    if (!customer) {
        res.status(404);
        throw new Error('Selected customer not found.');
    }

    // Automatically link customer to this partner if not linked
    if (!customer.referredByPartner) {
        customer.referredByPartner = req.user._id;
        await customer.save();
    }

    const commissionRate = req.user.commissionPercentage || 10;
    const commissionAmount = Math.round(Number(price) * (commissionRate / 100));

    const order = new Order({
        user: customer._id,
        clientName: customer.name,
        email: customer.email,
        phone: customer.phone || '',
        serviceName,
        packageName,
        price: Number(price),
        paymentId: `PARTNER_BOOKED_${Date.now()}`,
        paymentStatus: 'Pending',
        referralPartner: req.user._id,
        partnerCommissionAmount: commissionAmount,
        status: 'Pending Documents'
    });

    const createdOrder = await order.save();

    // Auto-generate invoice with Razorpay payment link sent to client
    try {
        await generateAndEmailInvoice(createdOrder, price, {
            status: 'Sent',
            actorId: req.user._id,
            notes: `Master Order booked by Referral Partner ${req.user.name}.`
        });
    } catch (invErr) {
        console.error('Invoice generation error for partner master order:', invErr.message);
    }

    // Trigger notification to customer
    try {
        await triggerNotification({
            userId: customer._id,
            title: 'New Service Engagement Booked',
            message: `A new service order for ${serviceName} (${packageName}) priced at INR ${Number(price).toLocaleString('en-IN')} has been placed on your behalf by your partner ${req.user.name}. Please review your invoice and proceed with payment.`,
            type: 'Order',
            emailOpts: {
                send: true,
                subject: `New Service Engagement: ${serviceName} - VR HERE`
            }
        });
    } catch (notifErr) {
        console.error('Customer notification failed:', notifErr.message);
    }

    // Notify admins of new partner booking
    await notifyAdmins({
        title: 'New Partner Master Order Placed',
        message: `Partner ${req.user.name} booked ${serviceName} for client ${customer.name} (INR ${Number(price).toLocaleString('en-IN')}).`,
        type: 'Order',
        email: true
    });

    res.status(201).json(createdOrder);
});

// @desc    Partner requests commission payout
// @route   POST /api/partner/payout-request
// @access  Private (Partner)
const requestPartnerPayout = asyncHandler(async (req, res) => {
    if (req.user.role !== 'partner') {
        res.status(403);
        throw new Error('Access denied.');
    }

    const { amount, payoutMethod = 'UPI', upiId, bankDetails } = req.body;
    const reqAmount = Number(amount);

    if (!reqAmount || reqAmount < 500) {
        res.status(400);
        throw new Error('Minimum withdrawal amount is ₹500.');
    }

    // Calculate available balance
    const orders = await Order.find({ referralPartner: req.user._id, paymentStatus: 'Paid' });
    const totalCommissionEarned = orders.reduce((sum, o) => sum + (Number(o.partnerCommissionAmount) || 0), 0);

    const payouts = await PartnerPayout.find({ partner: req.user._id });
    const existingPayouts = payouts
        .filter(p => p.status === 'Paid' || p.status === 'Pending' || p.status === 'Approved')
        .reduce((sum, p) => sum + (Number(p.amount) || 0), 0);

    const available = Math.max(0, totalCommissionEarned - existingPayouts);

    if (reqAmount > available) {
        res.status(400);
        throw new Error(`Insufficient available balance. You can withdraw up to ₹${available.toLocaleString('en-IN')}.`);
    }

    const effectiveUpi = upiId ? upiId.trim() : (req.user.upiId || '');
    const effectiveBank = bankDetails || req.user.bankDetails || {};

    if (payoutMethod === 'UPI' && !effectiveUpi) {
        res.status(400);
        throw new Error('UPI ID is required for UPI payout.');
    }

    const payout = await PartnerPayout.create({
        partner: req.user._id,
        amount: reqAmount,
        status: 'Pending',
        payoutMethod,
        upiId: effectiveUpi,
        bankDetails: effectiveBank
    });

    // Save upiId to profile for next time
    if (effectiveUpi && effectiveUpi !== req.user.upiId) {
        await User.findByIdAndUpdate(req.user._id, { upiId: effectiveUpi });
    }

    // Notify admins
    await notifyAdmins({
        title: '💸 Partner Commission Payout Request',
        message: `Partner ${req.user.name} (${req.user.phone}) requested commission payout of ₹${reqAmount.toLocaleString('en-IN')} via ${payoutMethod} (${effectiveUpi || effectiveBank.bankName}).`,
        type: 'Payment',
        email: true
    });

    res.status(201).json({
        success: true,
        message: `Payout request of ₹${reqAmount.toLocaleString('en-IN')} submitted successfully. Processing within 24-48 business hours.`,
        payout
    });
});

// @desc    Get partner payout history
// @route   GET /api/partner/payouts
// @access  Private (Partner)
const getPartnerPayouts = asyncHandler(async (req, res) => {
    if (req.user.role !== 'partner') {
        res.status(403);
        throw new Error('Access denied.');
    }

    const payouts = await PartnerPayout.find({ partner: req.user._id }).sort({ createdAt: -1 });
    res.json(payouts);
});

// @desc    Admin: Get all partner payout requests
// @route   GET /api/partner/admin/payouts
// @access  Private (Admin)
const adminGetPartnerPayouts = asyncHandler(async (req, res) => {
    const payouts = await PartnerPayout.find()
        .populate('partner', 'name email phone panCard bankDetails upiId commissionPercentage')
        .sort({ createdAt: -1 });
    res.json(payouts);
});

// @desc    Admin: Update partner payout status (Mark Paid / Rejected)
// @route   PUT /api/partner/admin/payouts/:id
// @access  Private (Admin)
const adminUpdatePartnerPayout = asyncHandler(async (req, res) => {
    const { status, transactionRef, adminNotes } = req.body;

    const payout = await PartnerPayout.findById(req.params.id).populate('partner', 'name email phone');
    if (!payout) {
        res.status(404);
        throw new Error('Payout request not found.');
    }

    if (status) payout.status = status;
    if (transactionRef !== undefined) payout.transactionRef = transactionRef;
    if (adminNotes !== undefined) payout.adminNotes = adminNotes;
    if (status === 'Paid') payout.paidAt = new Date();

    await payout.save();

    // Trigger notification to partner
    if (payout.partner) {
        try {
            await triggerNotification({
                userId: payout.partner._id,
                title: status === 'Paid' ? '🎉 Commission Payout Processed' : `Payout Update: ${status}`,
                message: status === 'Paid'
                    ? `Your commission payout of ₹${payout.amount.toLocaleString('en-IN')} has been transferred (Ref: ${transactionRef || 'NEFT/UPI'}).`
                    : `Your payout request of ₹${payout.amount.toLocaleString('en-IN')} status is now: ${status}.`,
                type: 'Payment',
                emailOpts: {
                    send: true,
                    subject: `VR HERE - Commission Payout ${status}`
                }
            });
        } catch (notifErr) {
            console.error('Partner payout notification failed:', notifErr.message);
        }
    }

    res.json(payout);
});

// @desc    Get partner profile details
// @route   GET /api/partner/profile
// @access  Private (Partner)
const getPartnerProfile = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id).select('-password');
    if (user) {
        res.json(user);
    } else {
        res.status(404);
        throw new Error('Partner not found');
    }
});

// @desc    Update partner profile (PAN, Bank details, UPI)
// @route   PUT /api/partner/profile
// @access  Private (Partner)
const updatePartnerProfile = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        user.name = req.body.name || user.name;
        user.panCard = req.body.panCard ? req.body.panCard.toUpperCase() : user.panCard;
        if (req.body.upiId !== undefined) user.upiId = req.body.upiId.trim();
        
        if (req.body.bankDetails) {
            user.bankDetails = {
                accountName: req.body.bankDetails.accountName || user.bankDetails.accountName,
                accountNumber: req.body.bankDetails.accountNumber || user.bankDetails.accountNumber,
                ifscCode: req.body.bankDetails.ifscCode || user.bankDetails.ifscCode,
                bankName: req.body.bankDetails.bankName || user.bankDetails.bankName,
            };
        }

        const updatedUser = await user.save();
        
        res.json({
            _id: updatedUser._id,
            name: updatedUser.name,
            email: updatedUser.email,
            role: updatedUser.role,
            phone: updatedUser.phone,
            panCard: updatedUser.panCard,
            upiId: updatedUser.upiId,
            bankDetails: updatedUser.bankDetails,
            commissionPercentage: updatedUser.commissionPercentage
        });
    } else {
        res.status(404);
        throw new Error('Partner not found');
    }
});

// @desc    Validate referral code (phone number)
// @route   GET /api/partner/validate/:code
// @access  Public
const validateReferralCode = asyncHandler(async (req, res) => {
    const { code } = req.params;
    
    if (!code) {
        res.status(400);
        throw new Error('Referral code is required');
    }

    const partner = await User.findOne({ phone: code, role: 'partner' });

    if (!partner) {
        res.status(404);
        throw new Error('Invalid referral code. No partner found with this number.');
    }

    if (!partner.isActive) {
        res.status(403);
        throw new Error('This referral partner account is pending validation and cannot be used yet.');
    }

    res.json({
        success: true,
        partnerName: partner.name
    });
});

export { 
    getPartnerOrders,
    getPartnerEarnings,
    getPartnerCustomers,
    addPartnerCustomer,
    createPartnerMasterOrder,
    requestPartnerPayout,
    getPartnerPayouts,
    adminGetPartnerPayouts,
    adminUpdatePartnerPayout,
    getPartnerProfile,
    updatePartnerProfile,
    validateReferralCode
};

