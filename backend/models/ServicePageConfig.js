import mongoose from 'mongoose';

const statSchema = new mongoose.Schema({
    value: { type: String, required: true },
    label: { type: String, required: true }
}, { _id: false });

const logoSchema = new mongoose.Schema({
    name: { type: String, required: true },
    iconKey: { type: String, required: true },
    colorClass: { type: String, default: 'text-slate-500' }
}, { _id: false });

const packageSchema = new mongoose.Schema({
    id: { type: String, required: true },
    name: { type: String, required: true },
    price: { type: Number, required: true },
    description: { type: String, default: '' },
    features: [{ type: String }],
    buttonText: { type: String, default: 'Select Plan' },
    isPopular: { type: Boolean, default: false },
    isAdjustable: { type: Boolean, default: false }
}, { _id: false });

const reviewSchema = new mongoose.Schema({
    name: { type: String, required: true },
    company: { type: String, default: '' },
    rating: { type: Number, default: 5 },
    date: { type: String, default: '' },
    text: { type: String, default: '' },
    avatar: { type: String, default: '' },
    verified: { type: Boolean, default: true }
}, { _id: false });

const stepSchema = new mongoose.Schema({
    number: { type: String, required: true },
    title: { type: String, required: true },
    desc: { type: String, default: '' },
    badge: { type: String, default: '' }
}, { _id: false });

const faqSchema = new mongoose.Schema({
    q: { type: String, required: true },
    a: { type: String, required: true }
}, { _id: false });

const guideSectionSchema = new mongoose.Schema({
    heading: { type: String, default: '' },
    content: { type: String, default: '' },
    bullets: [{ type: String }]
}, { _id: false });

const guideSchema = new mongoose.Schema({
    title: { type: String, default: 'Guide to Company Registration' },
    overview: { type: String, default: '' },
    sections: { type: [guideSectionSchema], default: [] },
    checklistTitle: { type: String, default: 'Checklist of Documents Needed' },
    checklist: [{ type: String }]
}, { _id: false });

const servicePageConfigSchema = new mongoose.Schema(
    {
        pageId: { type: String, required: true, unique: true, index: true },
        title: { type: String, required: true },
        description: { type: String, default: '' },
        iconKey: { type: String, default: 'Apartment' },
        hero: {
            title: { type: String, default: '' },
            subtitle: { type: String, default: '' },
            badgeText: { type: String, default: 'India\'s #1 Secure Registration Platform' },
            consultationPrice: { type: Number, default: 499 }
        },
        stats: { type: [statSchema], default: [] },
        logos: { type: [logoSchema], default: [] },
        packages: { type: [packageSchema], default: [] },
        reviews: { type: [reviewSchema], default: [] },
        steps: { type: [stepSchema], default: [] },
        faqs: { type: [faqSchema], default: [] },
        guide: { type: guideSchema, default: () => ({}) },
        popularSearches: [{ type: String }],
        seoSettings: {
            titleTag: { type: String, default: '' },
            metaDescription: { type: String, default: '' },
            focusKeywords: [{ type: String }]
        },
        trackingSettings: {
            googleAnalyticsId: { type: String, default: '' },
            metaPixelId: { type: String, default: '' }
        },
        gscTokens: {
            accessToken: { type: String, default: '' },
            refreshToken: { type: String, default: '' },
            expiryDate: { type: Date, default: null }
        },
        enableCityPages: { type: Boolean, default: false },
        citySlugList: [{ type: String }],
        headerNavSync: {
            enabled: { type: Boolean, default: false },
            category: { type: String, default: '' },
            column: { type: String, default: '' }
        },
        yoastSeo: {
            focusKeyword: { type: String, default: '' },
            score: { type: Number, default: 0 },
            issues: { type: Array, default: [] }
        },
        isPublished: { type: Boolean, default: true }
    },
    { timestamps: true }
);

const ServicePageConfig = mongoose.model('ServicePageConfig', servicePageConfigSchema);

export default ServicePageConfig;
