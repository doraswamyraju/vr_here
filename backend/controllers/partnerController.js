import asyncHandler from 'express-async-handler';
import Order from '../models/Order.js';

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

export { getPartnerOrders };
