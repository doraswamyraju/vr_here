import mongoose from 'mongoose';

const offerSchema = new mongoose.Schema(
    {
        title: { type: String, required: true, trim: true },
        imageUrl: { type: String, required: true, trim: true },
        ctaLink: { type: String, default: '/contact', trim: true },
    },
    { _id: true }
);

const columnSchema = new mongoose.Schema(
    {
        title: { type: String, required: true, trim: true },
        items: [{ type: String, required: true, trim: true }],
    },
    { _id: false }
);

const serviceMenuItemSchema = new mongoose.Schema(
    {
        id: { type: String, required: true, trim: true },
        title: { type: String, required: true, trim: true },
        iconKey: { type: String, required: true, trim: true },
        items: [{ type: String, trim: true }], // legacy fallback
        columns: { type: [columnSchema], default: [] },
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
                    id: 'accounting-compliance-taxation',
                    title: 'Accounting, Compliance & Taxation Services',
                    iconKey: 'Calculator',
                    columns: [
                        {
                            title: 'Accounting-as-a-Service (AaaS)',
                            items: ['Bookkeeping & Accounting', 'Virtual CFO', 'MIS Reporting', 'Payroll Processing'],
                        },
                        {
                            title: 'Taxation & Legal Compliance',
                            items: ['GST Registration & Returns', 'Income Tax Filing', 'TDS/TCS Compliance', 'ROC Annual Filings'],
                        },
                        {
                            title: 'Audit & Assurance',
                            items: ['Statutory Audit', 'Tax Audit', 'Internal Audit', 'Compliance Health Check'],
                        },
                    ],
                    offers: [
                        {
                            title: 'Quarterly Compliance Bundle',
                            imageUrl: 'https://images.unsplash.com/photo-1554224155-6726b3ff858f?auto=format&fit=crop&w=1200&q=80',
                            ctaLink: '/contact?service=Quarterly%20Compliance%20Bundle',
                        },
                    ],
                },
                {
                    id: 'certification-quality-management',
                    title: 'Certification & Quality Management Services',
                    iconKey: 'Stamp',
                    columns: [
                        {
                            title: 'ISO Management Systems',
                            items: ['ISO 9001', 'ISO 14001', 'ISO 45001', 'ISO 27001'],
                        },
                        {
                            title: 'Product & Export Certifications',
                            items: ['CE Marking', 'FDA Assistance', 'BIS Certification', 'IEC Support'],
                        },
                        {
                            title: 'Food & Pharma Standards',
                            items: ['HACCP', 'GMP', 'Halal Certification', 'FSSAI Compliance'],
                        },
                    ],
                    offers: [
                        {
                            title: 'ISO Combo Offer',
                            imageUrl: 'https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?auto=format&fit=crop&w=1200&q=80',
                            ctaLink: '/contact?service=ISO%20Combo%20Offer',
                        },
                    ],
                },
                {
                    id: 'business-registration-corporate',
                    title: 'Business Registration & Corporate Services',
                    iconKey: 'Briefcase',
                    columns: [
                        {
                            title: 'Entity Formation',
                            items: ['Private Limited Company', 'LLP Registration', 'OPC Registration', 'Partnership Firm'],
                        },
                        {
                            title: 'Regulatory Registrations',
                            items: ['Udyam (MSME)', 'PAN/TAN', 'Import Export Code', 'Trade License'],
                        },
                        {
                            title: 'Corporate Secretarial',
                            items: ['Board Resolutions', 'Shareholding Changes', 'DIN/DSC Services', 'MCA Compliances'],
                        },
                    ],
                    offers: [
                        {
                            title: 'Startup Launch Offer',
                            imageUrl: 'https://images.unsplash.com/photo-1559136555-9303baea8ebd?auto=format&fit=crop&w=1200&q=80',
                            ctaLink: '/pvt-ltd-registration',
                        },
                    ],
                },
                {
                    id: 'industrial-project-advisory',
                    title: 'Industrial & Project Advisory Services',
                    iconKey: 'Factory',
                    columns: [
                        {
                            title: 'Plant & Machinery',
                            items: ['Machinery Sourcing', 'Vendor Verification', 'Turnkey Setup', 'Feasibility Analysis'],
                        },
                        {
                            title: 'Project Finance',
                            items: ['DPR Preparation', 'CMA Data', 'Term Loan Assistance', 'Working Capital'],
                        },
                        {
                            title: 'Incentives & Subsidy',
                            items: ['CGTMSE Guidance', 'PMEGP Support', 'State Subsidy Advisory', 'Documentation Support'],
                        },
                    ],
                    offers: [
                        {
                            title: 'Factory Setup Package',
                            imageUrl: 'https://images.unsplash.com/photo-1565608087341-404b25492fee?auto=format&fit=crop&w=1200&q=80',
                            ctaLink: '/contact?service=Factory%20Setup%20Package',
                        },
                    ],
                },
                {
                    id: 'government-portal-registrations',
                    title: 'Government Portal & Registration Services',
                    iconKey: 'Globe',
                    columns: [
                        {
                            title: 'Government Portals',
                            items: ['GeM Registration', 'TReDS Registration', 'RERA Registration', 'Single Window Support'],
                        },
                        {
                            title: 'Licenses & Approvals',
                            items: ['Factory License', 'Pollution NOC', 'Labour Registrations', 'Professional Tax'],
                        },
                    ],
                    offers: [
                        {
                            title: 'GeM Fast Track',
                            imageUrl: 'https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&w=1200&q=80',
                            ctaLink: '/contact?service=GeM%20Fast%20Track',
                        },
                    ],
                },
                {
                    id: 'startup-branding-digital',
                    title: 'Startup Support, Branding & Digital Services',
                    iconKey: 'Lightbulb',
                    columns: [
                        {
                            title: 'Startup Readiness',
                            items: ['Business Plan', 'Pitch Deck', 'Go-to-Market Advisory', 'Founder Documentation'],
                        },
                        {
                            title: 'Brand & Digital Presence',
                            items: ['Website Development', 'Brand Identity', 'Digital Marketing', 'Social Presence'],
                        },
                        {
                            title: 'IP & Utility',
                            items: ['Trademark Filing', 'Copyright Support', 'PAN/TAN Applications', 'Insurance Advisory'],
                        },
                    ],
                    offers: [
                        {
                            title: 'Founder Branding Pack',
                            imageUrl: 'https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&w=1200&q=80',
                            ctaLink: '/contact?service=Founder%20Branding%20Pack',
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
