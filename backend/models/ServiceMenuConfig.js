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
        tickerMessages: {
            type: [{ type: String, trim: true }],
            default: [
                'New: Income Tax return filing support now available.',
                'Startup consultation fee is adjustable against package purchase.',
                'Get faster support for registrations and certifications.',
            ],
        },
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
                            items: [
                                'Cloud Accounting (Tally Prime, Zoho Books, QuickBooks, Marg)',
                                'GST Return Filing',
                                'Payroll Management (Payslips, Leave, Form 16)',
                                'Professional Tax (PT) Returns',
                                'EPF / ESI Returns',
                                'Gratuity Management',
                                'TDS/TCS Filing',
                                'Inventory & Stock Management',
                                'Invoice Generation Support',
                                'Expense Tracking Consultancy',
                                'Monthly MIS Reports',
                            ],
                        },
                        {
                            title: 'Taxation & Legal Compliance',
                            items: [
                                'GST Registration',
                                'Income Tax Return Filing (ITR 1-7)',
                                '12AA/80G Certificates',
                                'Tax Planning Support',
                                '15CA Certification',
                            ],
                        },
                        {
                            title: 'Audit Services',
                            items: ['Internal Audit', 'GST Audit', 'SOX Audit', 'Stock & Compliance Audit', 'Other Audits (Need Basis)'],
                        },
                    ],
                    offers: [],
                },
                {
                    id: 'certification-quality-management',
                    title: 'Certification & Quality Management Services',
                    iconKey: 'Stamp',
                    columns: [
                        {
                            title: 'ISO Services',
                            items: [
                                'ISO 9001:2015 - Quality Management',
                                'ISO 14001:2015 - Environmental Management',
                                'ISO 45001:2018 - Occupational Health & Safety',
                                'ISO 22000:2018 - Food Safety',
                                'ISO 27001:2022 - Information Security',
                                'ISO 50001:2018 - Energy Management',
                                'ISO 13485:2016 - Medical Devices',
                                'ISO 20000-1:2018 - IT Service Management',
                                'ISO 22301:2019 - Business Continuity',
                            ],
                        },
                        {
                            title: 'Quality & Compliance',
                            items: ['GMP / HACCP', 'CE Marking', 'ISI / BIS Certification', 'FDA Compliance Support'],
                        },
                        {
                            title: 'Product & System Certifications',
                            items: ['BRCGS', 'Kosher Certification', 'Halal Certification'],
                        },
                    ],
                    offers: [],
                },
                {
                    id: 'business-registration-licensing-corporate',
                    title: 'Business Registrations, Licensing & Corporate Services',
                    iconKey: 'Briefcase',
                    columns: [
                        {
                            title: 'Company / Business Entity Registrations',
                            items: [
                                'Private Limited / Public Limited Company',
                                'LLP Registration',
                                'Partnership Firm Registration',
                                'Proprietorship Setup',
                                'Section 8 Company (NGO)',
                                'One Person Company',
                                'Society / Trust Registration',
                            ],
                        },
                        {
                            title: 'Mandatory Registrations',
                            items: [
                                'Udyam Registration (MSME)',
                                'Shops & Establishment Registration',
                                'EPFO (PF) Registration',
                                'ESIC Registration',
                                'Professional Tax Registration',
                                'Startup India Registration',
                                'Import Export Code (IEC)',
                            ],
                        },
                        {
                            title: 'Licensing Services',
                            items: [
                                'FSSAI Registration / License',
                                'LEI Certificate',
                                'Trade License',
                                'Labour / Contract Labour License',
                                'Pollution Control Board NOC / CFE / CFO',
                                'Factory License',
                                'FCRA',
                                'DARPAN for NGO',
                            ],
                        },
                        {
                            title: 'Corporate Compliances',
                            items: [
                                'ROC Annual Filings (AOC-4, MGT-7)',
                                'Director KYC (DIR-3 KYC)',
                                'ROC Search Certificate',
                                'Charge Creation',
                                'Change in Shareholding',
                                'Change in Directorship',
                                'Merger / Demerger / Winding Up Compliance',
                                'Bonus / Loans / Buyback Compliance',
                                'Share Allotment & Transfer',
                                'Increase in Share Capital',
                                'Change in Name, Address, Objective',
                                'Digital Signatures (DSC Class 3)',
                            ],
                        },
                    ],
                    offers: [],
                },
                {
                    id: 'government-portal-registrations',
                    title: 'Government Portal Registrations',
                    iconKey: 'Globe',
                    columns: [
                        {
                            title: 'GeM (Government e-Marketplace)',
                            items: [
                                'GeM Seller Registration',
                                'OEM Panel Registration',
                                'Brand Approval',
                                'Product Listing',
                                'Bid Participation & Tender Management',
                            ],
                        },
                        {
                            title: 'Other Modern Platforms',
                            items: [
                                'TReDS Registration',
                                'RERA Registration',
                                'AP/TS Single Window',
                                'NPCI Registrations',
                                'Amazon/Flipkart Seller Registration Support',
                            ],
                        },
                    ],
                    offers: [],
                },
                {
                    id: 'industrial-msme-consultancy',
                    title: 'Industrial & MSME Consultancy',
                    iconKey: 'IndianRupee',
                    columns: [
                        {
                            title: 'Project & Finance Support',
                            items: [
                                'DPR Preparation',
                                'CMA Data Preparation',
                                'Bank Loans - Term Loan + Working Capital',
                                'CGTMSE Loan Support',
                                'PMEGP Loan Support',
                                'Mudra Loans',
                                'Stand-Up India Loan Assistance',
                            ],
                        },
                        {
                            title: 'MSME & Industrial Subsidy Guidance',
                            items: [
                                'Updated MSME & Industrial Subsidy Guidance',
                                'CLCSS / ZED Scheme Support',
                                'PMFME (Food Processing Units)',
                                'NSIC Schemes',
                                'NABARD Schemes',
                                'Cold Chain & Food Processing Subsidy',
                                'AP/TS State Industrial Subsidy Schemes',
                            ],
                        },
                    ],
                    offers: [],
                },
                {
                    id: 'branding-documentation-startup-support',
                    title: 'Branding, Documentation & Startup Support',
                    iconKey: 'Lightbulb',
                    columns: [
                        {
                            title: 'Startup Support',
                            items: [
                                'Business Plan Preparation',
                                'Pitch Decks for Funding',
                                'Website & Branding Consulting',
                                'Vendor Empanelment Documentation',
                                'HR Policy Documentation',
                                'SOP Creation',
                            ],
                        },
                        {
                            title: 'Additional Services',
                            items: [
                                'Loan File Documentation & Follow-up',
                                'Insurance Services (Business, Fire, Marine)',
                                'Digital Marketing Support',
                                'PAN / TAN Applications',
                                'Trademark & IP Services',
                                'Wealth Portfolio Management',
                            ],
                        },
                    ],
                    offers: [],
                },
                {
                    id: 'machinery-industrial-support',
                    title: 'Machinery & Industrial Support',
                    iconKey: 'Factory',
                    columns: [
                        {
                            title: 'Industrial Support Services',
                            items: [
                                'Machinery Sourcing & Imports',
                                'Vendor Identification & Supplier Verification',
                                'Turnkey Machinery Setup Assistance',
                                'Technology Upgradation Consulting',
                                'Industry Selection & Feasibility Analysis',
                            ],
                        },
                    ],
                    offers: [],
                },
            ],
        },
    },
    { timestamps: true }
);

const ServiceMenuConfig = mongoose.model('ServiceMenuConfig', serviceMenuConfigSchema);

export default ServiceMenuConfig;
