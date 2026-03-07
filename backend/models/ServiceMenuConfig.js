import mongoose from 'mongoose';

const offerSchema = new mongoose.Schema(
    {
        title: { type: String, required: true, trim: true },
        imageUrl: { type: String, required: true, trim: true },
        ctaLink: { type: String, default: '/contact', trim: true },
    },
    { _id: true }
);

const serviceMenuItemSchema = new mongoose.Schema(
    {
        id: { type: String, required: true, trim: true },
        title: { type: String, required: true, trim: true },
        iconKey: { type: String, required: true, trim: true },
        items: [{ type: String, required: true, trim: true }],
        offers: [offerSchema],
    },
    { _id: false }
);

const serviceMenuConfigSchema = new mongoose.Schema(
    {
        key: { type: String, required: true, unique: true, default: 'header-main-menu' },
        services: {
            type: [serviceMenuItemSchema],
            default: [
                {
                    id: 'machinery',
                    title: 'Machinery & Industrial',
                    iconKey: 'Factory',
                    items: ['Machinery Sourcing', 'Vendor Verification', 'Turnkey Setup', 'Feasibility Analysis'],
                    offers: [
                        {
                            title: 'Factory Setup Package',
                            imageUrl: 'https://images.unsplash.com/photo-1565608087341-404b25492fee?auto=format&fit=crop&w=1200&q=80',
                            ctaLink: '/contact?service=Factory%20Setup%20Package',
                        },
                    ],
                },
                {
                    id: 'iso',
                    title: 'Certification (ISO)',
                    iconKey: 'Stamp',
                    items: ['ISO 9001, 14001, 45001', 'ISO 27001 (Info Sec)', 'CE Marking & FDA', 'GMP / HACCP / Halal'],
                    offers: [
                        {
                            title: 'ISO Combo Offer',
                            imageUrl: 'https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?auto=format&fit=crop&w=1200&q=80',
                            ctaLink: '/contact?service=ISO%20Combo%20Offer',
                        },
                    ],
                },
                {
                    id: 'accounting',
                    title: 'Accounting & Tax',
                    iconKey: 'Calculator',
                    items: ['Cloud Accounting', 'GST Reg & Returns', 'Income Tax Filing', 'Statutory & Tax Audits'],
                    offers: [
                        {
                            title: 'Quarterly GST Plan',
                            imageUrl: 'https://images.unsplash.com/photo-1554224155-6726b3ff858f?auto=format&fit=crop&w=1200&q=80',
                            ctaLink: '/contact?service=Quarterly%20GST%20Plan',
                        },
                    ],
                },
                {
                    id: 'registration',
                    title: 'Business Registration',
                    iconKey: 'Briefcase',
                    items: ['Pvt Ltd / LLP / OPC', 'Section 8 (NGO)', 'Udyam (MSME)', 'FSSAI & Trade License'],
                    offers: [
                        {
                            title: 'Startup Launch Offer',
                            imageUrl: 'https://images.unsplash.com/photo-1559136555-9303baea8ebd?auto=format&fit=crop&w=1200&q=80',
                            ctaLink: '/pvt-ltd-registration',
                        },
                    ],
                },
                {
                    id: 'govt',
                    title: 'Govt. Portals',
                    iconKey: 'Globe',
                    items: ['GeM Seller/OEM Reg', 'TReDS Registration', 'RERA Registration', 'Import Export Code'],
                    offers: [
                        {
                            title: 'GeM Fast Track',
                            imageUrl: 'https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&w=1200&q=80',
                            ctaLink: '/contact?service=GeM%20Fast%20Track',
                        },
                    ],
                },
                {
                    id: 'msme',
                    title: 'Industrial Consultancy',
                    iconKey: 'IndianRupee',
                    items: ['Project Reports (DPR)', 'Term Loans & WC', 'CGTMSE & PMEGP', 'Subsidy Guidance'],
                    offers: [
                        {
                            title: 'MSME Loan Assist',
                            imageUrl: 'https://images.unsplash.com/photo-1593672715438-d88a70629abe?auto=format&fit=crop&w=1200&q=80',
                            ctaLink: '/contact?service=MSME%20Loan%20Assist',
                        },
                    ],
                },
                {
                    id: 'branding',
                    title: 'Startup Support',
                    iconKey: 'Lightbulb',
                    items: ['Business Plans', 'Pitch Decks', 'Website & Branding', 'HR Policy & SOPs'],
                    offers: [
                        {
                            title: 'Founder Branding Pack',
                            imageUrl: 'https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&w=1200&q=80',
                            ctaLink: '/contact?service=Founder%20Branding%20Pack',
                        },
                    ],
                },
                {
                    id: 'utility',
                    title: 'Utility Services',
                    iconKey: 'MoreHorizontal',
                    items: ['Trademark & IP', 'PAN / TAN Apps', 'Insurance Services', 'Digital Marketing'],
                    offers: [
                        {
                            title: 'Trademark Filing Deal',
                            imageUrl: 'https://images.unsplash.com/photo-1450101499163-c8848c66ca85?auto=format&fit=crop&w=1200&q=80',
                            ctaLink: '/contact?service=Trademark%20Filing%20Deal',
                        },
                    ],
                },
            ],
        },
    },
    { timestamps: true }
);

const ServiceMenuConfig = mongoose.model('ServiceMenuConfig', serviceMenuConfigSchema);

export default ServiceMenuConfig;
