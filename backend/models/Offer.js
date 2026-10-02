import mongoose from 'mongoose';

const offerSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    subtitle: { type: String, required: true },
    badgeTag: { type: String, default: 'LIMITED TIME' },
    badgeColor: { type: String, default: '#DC2626' },
    bannerImageUrl: { type: String, default: '' },
    targetServiceKey: { type: String, default: '' },
    targetUrl: { type: String, default: '' },
    discountAmount: { type: Number, default: 0 },
    originalPrice: { type: Number, default: 0 },
    discountedPrice: { type: Number, default: 0 },
    eligibilityText: { type: String, default: 'Tap to view eligibility & apply' },
    ctaText: { type: String, default: 'Register Today →' },
    isActive: { type: Boolean, default: true },
    priority: { type: Number, default: 0 },
    validUntil: { type: Date, default: null }
}, { timestamps: true });

export default mongoose.model('Offer', offerSchema);
