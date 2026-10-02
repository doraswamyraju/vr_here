import Offer from '../models/Offer.js';
import asyncHandler from 'express-async-handler';

// @desc    Get all active promotional offers (Public)
// @route   GET /api/offers
// @access  Public
export const getActiveOffers = asyncHandler(async (req, res) => {
    const offers = await Offer.find({ isActive: true }).sort({ priority: -1, createdAt: -1 });
    res.json(offers);
});

// @desc    Get all offers for admin
// @route   GET /api/offers/admin/all
// @access  Admin
export const getAllOffersAdmin = asyncHandler(async (req, res) => {
    const offers = await Offer.find({}).sort({ createdAt: -1 });
    res.json(offers);
});

// @desc    Create new promotional offer
// @route   POST /api/offers
// @access  Admin
export const createOffer = asyncHandler(async (req, res) => {
    const {
        title,
        subtitle,
        badgeTag,
        badgeColor,
        bannerImageUrl,
        targetServiceKey,
        targetUrl,
        discountAmount,
        originalPrice,
        discountedPrice,
        eligibilityText,
        ctaText,
        isActive,
        priority,
        validUntil
    } = req.body;

    const offer = await Offer.create({
        title,
        subtitle,
        badgeTag: badgeTag || 'LIMITED TIME',
        badgeColor: badgeColor || '#DC2626',
        bannerImageUrl: bannerImageUrl || '',
        targetServiceKey: targetServiceKey || '',
        targetUrl: targetUrl || '',
        discountAmount: Number(discountAmount) || 0,
        originalPrice: Number(originalPrice) || 0,
        discountedPrice: Number(discountedPrice) || 0,
        eligibilityText: eligibilityText || 'Tap to view eligibility & apply',
        ctaText: ctaText || 'Register Today →',
        isActive: isActive !== undefined ? isActive : true,
        priority: Number(priority) || 0,
        validUntil: validUntil || null
    });

    res.status(201).json(offer);
});

// @desc    Update promotional offer
// @route   PUT /api/offers/:id
// @access  Admin
export const updateOffer = asyncHandler(async (req, res) => {
    const offer = await Offer.findById(req.params.id);
    if (!offer) {
        res.status(404);
        throw new Error('Offer not found');
    }

    const fields = [
        'title', 'subtitle', 'badgeTag', 'badgeColor', 'bannerImageUrl',
        'targetServiceKey', 'targetUrl', 'discountAmount', 'originalPrice',
        'discountedPrice', 'eligibilityText', 'ctaText', 'isActive',
        'priority', 'validUntil'
    ];

    fields.forEach(field => {
        if (req.body[field] !== undefined) {
            offer[field] = req.body[field];
        }
    });

    const updatedOffer = await offer.save();
    res.json(updatedOffer);
});

// @desc    Delete promotional offer
// @route   DELETE /api/offers/:id
// @access  Admin
export const deleteOffer = asyncHandler(async (req, res) => {
    const offer = await Offer.findById(req.params.id);
    if (!offer) {
        res.status(404);
        throw new Error('Offer not found');
    }

    await Offer.findByIdAndDelete(req.params.id);
    res.json({ message: 'Offer removed successfully' });
});
