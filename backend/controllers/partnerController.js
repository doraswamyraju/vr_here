import asyncHandler from 'express-async-handler';
import Order from '../models/Order.js';
import User from '../models/User.js';

// @desc    Get orders securely for the logged-in referral partner
// @route   GET /api/partner/orders
// @access  Private (Partner)
const getPartnerOrders = asyncHandler(async (req, res) => {
    if (req.user.role !== 'partner') {
        res.status(403);
        throw new Error('Access denied. Only partners can view this data.');
    }

    const orders = await Order.find({ referralPartner: req.user._id })
        .select('serviceName clientName price status partnerCommissionAmount createdAt')
        .sort({ createdAt: -1 });

    res.json(orders);
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

// @desc    Update partner profile (PAN, Bank details)
// @route   PUT /api/partner/profile
// @access  Private (Partner)
const updatePartnerProfile = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        user.name = req.body.name || user.name;
        user.panCard = req.body.panCard ? req.body.panCard.toUpperCase() : user.panCard;
        
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
            bankDetails: updatedUser.bankDetails,
            commissionPercentage: updatedUser.commissionPercentage
        });
    } else {
        res.status(404);
        throw new Error('Partner not found');
    }
});

export { 
    getPartnerOrders,
    getPartnerProfile,
    updatePartnerProfile
};
