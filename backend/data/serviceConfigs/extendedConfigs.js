// Helper function to generate clean slugs from menu item titles
export const slugify = (text) => {
    return text
        .toLowerCase()
        .replace(/\(.*?\)/g, '') // remove parentheses
        .replace(/[^a-z0-9]+/g, '-') // replace non-alphanumerics with hyphens
        .replace(/^-+|-+$/g, ''); // trim leading/trailing hyphens
};

export const generateConfig = (item) => {
    const title = item.title;
    const slug = item.slug || slugify(title);
    const price = item.price || 2999;
    const category = item.category || 'Business Services';

    // Domain-specific requirements & inclusions generator
    let requirements = [
        'PAN Card of Business / Applicant',
        'Aadhaar Card linked with active Mobile No.',
        'Registered Address Proof (Electricity Bill / Rent Agreement)',
        'Bank Account Statement / Cancelled Cheque'
    ];

    let heroGraphicItems = [
        'Dedicated CA/CS Specialist Assigned',
        'End-to-End Government / Statutory Filing',
        'Digital Document Verification & Quality Audit',
        'Official Certificate & Filing Receipts Delivered',
        'Lifetime Compliance & Advisory Support'
    ];

    let benefits = [
        { t: '100% Online & Paperless', d: `Complete ${title} from the comfort of your home or office.` },
        { t: 'Verified CA/CS Oversight', d: 'Every document and application is verified by senior practitioners.' },
        { t: 'Zero Penalty Guarantee', d: 'Timely filing ensuring complete statutory compliance and protection.' },
        { t: 'Transparent Pricing', d: 'Clear itemized billing with no hidden fees or surprise charges.' }
    ];

    // Specific domain customizations
    if (slug.includes('cma') || slug.includes('dpr') || slug.includes('bank-loan') || slug.includes('loan')) {
        requirements = [
            'Last 3 Years Audited Financial Statements (P&L, Balance Sheet)',
            'Sanction Letters of Existing Bank Limits (if any)',
            'Provisional Balance Sheet & Current Year Estimates',
            'Project Quotations / Machinery Invoices',
            'Business Profile & Promoters Biodata'
        ];
        heroGraphicItems = [
            '7 Standard Banking CMA Statements',
            'Holding Period & MPBF Calculations',
            'DSCR & Key Financial Ratio Modeling',
            'SBI / PSU & Private Bank Format Compliant',
            'Chartered Accountant Certified CMA File'
        ];
        benefits = [
            { t: 'Bank Underwriting Compliant', d: 'Structured strictly according to RBI & commercial bank credit norms.' },
            { t: 'Higher Loan Sanction Probability', d: 'Professional financial ratios that satisfy credit managers.' },
            { t: 'Fast 48-72 Hour Delivery', d: 'Expedited turnaround to meet bank loan processing deadlines.' },
            { t: 'CA Attested Reports', d: 'Signed and certified CMA reports accepted across all nationalized banks.' }
        ];
    } else if (slug.includes('iso')) {
        requirements = [
            'Company Registration Certificate (COI / GST / Udyam)',
            'Business Process Description & Flowcharts',
            'Organization Hierarchy & Scope of Operations',
            'Identity Proof of Authorized Signatory'
        ];
        heroGraphicItems = [
            'IAF / Non-IAF Recognized Accreditation',
            'Quality Manual & SOP Documentation Kit',
            'Internal Audit & Gap Analysis Assistance',
            'Official Registrar Portal Listing',
            '3-Year Certificate Validity with QR Code'
        ];
    } else if (slug.includes('udyam') || slug.includes('msme')) {
        requirements = [
            'Aadhaar Card of Business Owner / Director',
            'PAN Card of Enterprise / Applicant',
            'GSTIN Details (if applicable)',
            'Bank Account Number & IFSC Code'
        ];
        heroGraphicItems = [
            'Ministry of MSME Official Certificate',
            '5-Digit NIC Code Classification',
            'Priority Sector Bank Lending Benefits',
            'Subsidized Government Tender Access',
            'Lifetime Validity with Digital QR'
        ];
    } else if (slug.includes('fssai') || slug.includes('food')) {
        requirements = [
            'Photo ID & Address Proof of Food Business Operator',
            'Premises Possession Proof (Rental Deed / Utility Bill)',
            'List of Food Categories / Products Manufactured',
            'Kitchen / Plant Layout & Equipment List'
        ];
        heroGraphicItems = [
            '14-Digit FSSAI Registration / License No.',
            'FoSCoS Portal Application & Real-time Tracking',
            'Swiggy / Zomato Onboarding Ready',
            'Food Safety & Hygiene Standard Compliance',
            '1 to 5 Year Validity Options'
        ];
    } else if (slug.includes('trademark') || slug.includes('brand') || slug.includes('ip')) {
        requirements = [
            'Brand Logo / Slogan / Wordmark Image',
            'Identity Proof of Trademark Applicant',
            'User Date Affidavit (if TM already in use)',
            'Power of Attorney (Form TM-48) signed'
        ];
        heroGraphicItems = [
            'Comprehensive Trademark Search Report',
            'Form TM-A Filing by Certified TM Attorney',
            'Instant Right to Use ™ Symbol in 24 Hours',
            '1 to 45 Nice Classification Mapping',
            '10-Year Government Protection Period'
        ];
    }

    return {
        pageId: slug,
        title: title,
        description: `Professional ${title} services in India. 100% online legal execution with verified CA/CS oversight and statutory compliance guarantee.`,
        iconKey: 'Briefcase',
        hero: {
            title: `${title} Online in {city}`,
            subtitle: `Fast, transparent, 100% online ${title} with dedicated CA/CS assistance across {city}, {state}.`,
            badgeText: 'GOVT & STATUTORY VERIFIED',
            consultationPrice: 499,
            inclusions: heroGraphicItems
        },
        stats: [
            { value: '3-5 Days', label: 'AVG. TURNAROUND' },
            { value: '100%', label: 'STATUTORY COMPLIANT' },
            { value: '4.9/5', label: 'CLIENT RATING' },
            { value: 'CA/CS', label: 'VERIFIED' }
        ],
        heroGraphicItems: heroGraphicItems,
        whyChoose: {
            title: `Why Choose VR Here for ${title}?`,
            subtitle: `Get certified legal execution, dedicated financial modeling, and end-to-end statutory assistance from senior chartered accountants.`,
            benefits: benefits,
            requirements: requirements
        },
        packages: [
            {
                id: `${slug}-basic`,
                name: 'Standard Package',
                price: price,
                isPopular: true,
                description: `Complete ${title} execution with official filings and verification.`,
                features: heroGraphicItems.slice(0, 4),
                creativeButtonText: `Select Standard`
            },
            {
                id: `${slug}-premium`,
                name: 'Premium Enterprise Retainer',
                price: Math.round(price * 1.8),
                description: `End-to-end priority compliance, annual renewals, and legal consultation.`,
                features: [...heroGraphicItems, 'Priority 24-48 Hr Fast-Track Delivery', 'Dedicated Senior Partner Advisory', 'Direct WhatsApp & Phone Access'],
                creativeButtonText: 'Select Premium'
            }
        ],
        reviews: [
            {
                name: "Rajesh Kulkarni",
                company: "Kulkarni Enterprises",
                avatar: "RK",
                rating: 5,
                date: "12 June 2026",
                text: `VR Here handled our ${title} with supreme professionalism. The team delivered all documents on schedule with zero hassles.`,
                verified: true
            },
            {
                name: "Pooja Sharma",
                company: "Apex Tech Innovations",
                avatar: "PS",
                rating: 5,
                date: "25 May 2026",
                text: `Very fast and transparent service for ${title}. Their CA guided us step-by-step through the requirements. Highly recommended!`,
                verified: true
            },
            {
                name: "Suresh Menon",
                company: "Menon Logistics & Supply",
                avatar: "SM",
                rating: 5,
                date: "04 July 2026",
                text: `Top-tier customer support. We got our ${title} completed without any office visits. Superb experience!`,
                verified: true
            }
        ],
        steps: [
            { number: '01', title: 'KYC & Data Upload', desc: 'Securely submit required business details and identity documents.', badge: 'Step 1' },
            { number: '02', title: 'Legal & Dept Drafting', desc: 'Practicing Chartered Accountants draft and verify applications.', badge: 'Step 2' },
            { number: '03', title: 'Statutory Portal Filing', desc: 'Application filed on official central or state government portals.', badge: 'Step 3' },
            { number: '04', title: 'Delivery & Advisory', desc: 'Official government certificate and filing receipt delivered digitally.', badge: 'Step 4' }
        ],
        guide: {
            title: `Guide to ${title}`,
            overview: `Professional ${title} ensures strict compliance with Indian statutory authorities while saving valuable business time.`,
            checklistTitle: 'Required Documents',
            checklist: requirements
        },
        faqs: [
            { q: `How long does the ${title} process take?`, a: 'Standard turnaround is 3 to 5 business days subject to departmental approval queues.' },
            { q: 'Can I adjust the consultation fee against the final package?', a: 'Yes! If you book an expert CA/CS consultation at ₹499, the full ₹499 is credited and deducted when you upgrade to any full registration plan.' }
        ],
        popularSearches: [title, `${title} Online`, `${title} Fees in India`, `${title} Consultant`, `${title} in {city}`]
    };
};

export const MENU_ITEMS_LIST = [
    // 1. Accounting-as-a-Service (AaaS)
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Accounting-as-a-Service (AaaS)', title: 'Cloud Accounting (Tally Prime, Zoho Books, QuickBooks, Marg)', slug: 'cloud-accounting', price: 2999 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Accounting-as-a-Service (AaaS)', title: 'GST Return Filing', slug: 'gst-return-filing', price: 499 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Accounting-as-a-Service (AaaS)', title: 'Payroll Management (Payslips, Leave, Form 16)', slug: 'payroll-management', price: 2499 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Accounting-as-a-Service (AaaS)', title: 'Professional Tax (PT) Returns', slug: 'professional-tax', price: 1999 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Accounting-as-a-Service (AaaS)', title: 'EPF / ESI Returns', slug: 'epf-esi-returns', price: 1999 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Accounting-as-a-Service (AaaS)', title: 'Gratuity Management', slug: 'gratuity-management', price: 3499 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Accounting-as-a-Service (AaaS)', title: 'TDS/TCS Filing', slug: 'tds-tcs-filing', price: 1999 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Accounting-as-a-Service (AaaS)', title: 'Inventory & Stock Management', slug: 'inventory-stock-management', price: 2999 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Accounting-as-a-Service (AaaS)', title: 'Invoice Generation Support', slug: 'invoice-generation-support', price: 1499 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Accounting-as-a-Service (AaaS)', title: 'Expense Tracking Consultancy', slug: 'expense-tracking-consultancy', price: 1999 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Accounting-as-a-Service (AaaS)', title: 'Monthly MIS Reports', slug: 'mis-reporting', price: 3999 },

    // 2. Taxation & Legal Compliance
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Taxation & Legal Compliance', title: 'Companies Compliance Scheme 2026 (CCFS)', slug: 'compliance-scheme-2026', price: 4999 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Taxation & Legal Compliance', title: 'GST Registration', slug: 'gst-registration', price: 2569 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Taxation & Legal Compliance', title: 'Income Tax Return Filing (ITR 1-7)', slug: 'income-tax-return', price: 1499 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Taxation & Legal Compliance', title: '12AA/80G Certificates', slug: '12aa-80g-certificates', price: 6999 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Taxation & Legal Compliance', title: 'Tax Planning Support', slug: 'tax-planning-support', price: 2999 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Taxation & Legal Compliance', title: '15CA Certification', slug: '15ca-certification', price: 2499 },

    // 3. Audit Services
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Audit Services', title: 'Internal Audit', slug: 'internal-audit', price: 9999 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Audit Services', title: 'GST Audit', slug: 'gst-audit', price: 9999 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Audit Services', title: 'SOX Audit', slug: 'sox-audit', price: 19999 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Audit Services', title: 'Stock & Compliance Audit', slug: 'stock-compliance-audit', price: 7999 },
    { category: 'Accounting, Compliance & Taxation Services', subCategory: 'Audit Services', title: 'Other Audits (Need Basis)', slug: 'audit-services', price: 9999 },

    // 4. ISO Services
    { category: 'Certification & Quality Management Services', subCategory: 'ISO Services', title: 'ISO 9001:2015 - Quality Management', slug: 'iso-9001-certification', price: 3499 },
    { category: 'Certification & Quality Management Services', subCategory: 'ISO Services', title: 'ISO 14001:2015 - Environmental Management', slug: 'iso-14001-certification', price: 5499 },
    { category: 'Certification & Quality Management Services', subCategory: 'ISO Services', title: 'ISO 45001:2018 - Occupational Health & Safety', slug: 'iso-45001-certification', price: 5999 },
    { category: 'Certification & Quality Management Services', subCategory: 'ISO Services', title: 'ISO 22000:2018 - Food Safety', slug: 'iso-22000-certification', price: 6999 },
    { category: 'Certification & Quality Management Services', subCategory: 'ISO Services', title: 'ISO 27001:2022 - Information Security', slug: 'iso-27001-certification', price: 8999 },
    { category: 'Certification & Quality Management Services', subCategory: 'ISO Services', title: 'ISO 50001:2018 - Energy Management', slug: 'iso-50001-certification', price: 7999 },
    { category: 'Certification & Quality Management Services', subCategory: 'ISO Services', title: 'ISO 13485:2016 - Medical Devices', slug: 'iso-13485-certification', price: 9999 },
    { category: 'Certification & Quality Management Services', subCategory: 'ISO Services', title: 'ISO 20000-1:2018 - IT Service Management', slug: 'iso-20000-certification', price: 8999 },
    { category: 'Certification & Quality Management Services', subCategory: 'ISO Services', title: 'ISO 22301:2019 - Business Continuity', slug: 'iso-22301-certification', price: 8999 },

    // 5. Quality & Compliance
    { category: 'Certification & Quality Management Services', subCategory: 'Quality & Compliance', title: 'GMP / HACCP', slug: 'gmp-haccp-certification', price: 6499 },
    { category: 'Certification & Quality Management Services', subCategory: 'Quality & Compliance', title: 'CE Marking', slug: 'ce-marking-certification', price: 12499 },
    { category: 'Certification & Quality Management Services', subCategory: 'Quality & Compliance', title: 'ISI / BIS Certification', slug: 'isi-bis-certification', price: 14999 },
    { category: 'Certification & Quality Management Services', subCategory: 'Quality & Compliance', title: 'FDA Compliance Support', slug: 'fda-compliance-support', price: 14999 },

    // 6. Product & System Certifications
    { category: 'Certification & Quality Management Services', subCategory: 'Product & System Certifications', title: 'BRCGS', slug: 'brcgs-certification', price: 14999 },
    { category: 'Certification & Quality Management Services', subCategory: 'Product & System Certifications', title: 'Kosher Certification', slug: 'kosher-certification', price: 11999 },
    { category: 'Certification & Quality Management Services', subCategory: 'Product & System Certifications', title: 'Halal Certification', slug: 'halal-kosher-certification', price: 7999 },

    // 7. Mandatory Registrations
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Mandatory Registrations', title: 'Udyam Registration (MSME)', slug: 'udyam-registration', price: 999 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Mandatory Registrations', title: 'Shops & Establishment Registration', slug: 'shops-establishment-license', price: 1499 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Mandatory Registrations', title: 'EPFO (PF) Registration', slug: 'epfo-pf-registration', price: 2999 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Mandatory Registrations', title: 'ESIC Registration', slug: 'esic-registration', price: 2999 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Mandatory Registrations', title: 'Professional Tax Registration', slug: 'professional-tax-registration', price: 1999 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Mandatory Registrations', title: 'Startup India Registration', slug: 'startup-india-registration', price: 3499 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Mandatory Registrations', title: 'Import Export Code (IEC)', slug: 'import-export-code', price: 2199 },

    // 8. Licensing Services
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Licensing Services', title: 'FSSAI Registration / License', slug: 'fssai-license', price: 1999 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Licensing Services', title: 'LEI Certificate', slug: 'lei-certificate', price: 4999 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Licensing Services', title: 'Trade License', slug: 'trade-license', price: 2499 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Licensing Services', title: 'Labour / Contract Labour License', slug: 'labour-license', price: 5499 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Licensing Services', title: 'Pollution Control Board NOC / CFE / CFO', slug: 'pollution-noc', price: 9999 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Licensing Services', title: 'Factory License', slug: 'factory-license', price: 11999 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Licensing Services', title: 'FCRA', slug: 'fcra-registration', price: 14999 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Licensing Services', title: 'DARPAN for NGO', slug: 'ngo-darpan-registration', price: 2499 },

    // 9. Corporate Compliances
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Corporate Compliances', title: 'ROC Annual Filings (AOC-4, MGT-7)', slug: 'roc-annual-filings', price: 4999 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Corporate Compliances', title: 'Director KYC (DIR-3 KYC)', slug: 'director-kyc', price: 499 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Corporate Compliances', title: 'ROC Search Certificate', slug: 'roc-search-certificate', price: 2999 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Corporate Compliances', title: 'Charge Creation', slug: 'roc-charge-creation', price: 3999 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Corporate Compliances', title: 'Change in Shareholding', slug: 'change-in-shareholding', price: 3499 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Corporate Compliances', title: 'Change in Directorship', slug: 'change-in-directorship', price: 2499 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Corporate Compliances', title: 'Merger / Demerger / Winding Up Compliance', slug: 'merger-demerger-winding-up', price: 24999 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Corporate Compliances', title: 'Bonus / Loans / Buyback Compliance', slug: 'bonus-loans-buyback', price: 4999 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Corporate Compliances', title: 'Share Allotment & Transfer', slug: 'share-allotment-transfer', price: 3499 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Corporate Compliances', title: 'Increase in Share Capital', slug: 'increase-share-capital', price: 3999 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Corporate Compliances', title: 'Change in Name, Address, Objective', slug: 'company-name-address-change', price: 3499 },
    { category: 'Business Registrations, Licensing & Corporate Services', subCategory: 'Corporate Compliances', title: 'Digital Signatures (DSC Class 3)', slug: 'dsc-registration', price: 1499 },

    // 10. GeM (Govt e-Marketplace)
    { category: 'Government & MSME Services', subCategory: 'GeM (Govt e-Marketplace)', title: 'GeM Seller Registration', slug: 'gem-registration', price: 2999 },
    { category: 'Government & MSME Services', subCategory: 'GeM (Govt e-Marketplace)', title: 'OEM Panel Registration', slug: 'gem-oem-panel', price: 7999 },
    { category: 'Government & MSME Services', subCategory: 'GeM (Govt e-Marketplace)', title: 'Brand Approval', slug: 'gem-brand-approval', price: 3999 },
    { category: 'Government & MSME Services', subCategory: 'GeM (Govt e-Marketplace)', title: 'Product Listing', slug: 'gem-product-listing', price: 2499 },
    { category: 'Government & MSME Services', subCategory: 'GeM (Govt e-Marketplace)', title: 'Bid Participation & Tender Management', slug: 'gem-tender-bidding', price: 9999 },

    // 11. Other Portal Registrations
    { category: 'Government & MSME Services', subCategory: 'Other Portal Registrations', title: 'TReDS Registration', slug: 'treds-registration', price: 3499 },
    { category: 'Government & MSME Services', subCategory: 'Other Portal Registrations', title: 'RERA Registration', slug: 'rera-registration', price: 3999 },
    { category: 'Government & MSME Services', subCategory: 'Other Portal Registrations', title: 'AP/TS Single Window', slug: 'single-window-registration', price: 4999 },
    { category: 'Government & MSME Services', subCategory: 'Other Portal Registrations', title: 'NPCI Registrations', slug: 'npci-registration', price: 9999 },
    { category: 'Government & MSME Services', subCategory: 'Other Portal Registrations', title: 'Amazon/Flipkart Seller Registration Support', slug: 'ecommerce-seller-registration', price: 2499 },

    // 12. Project & Finance Support
    { category: 'Government & MSME Services', subCategory: 'Project & Finance Support', title: 'DPR Preparation', slug: 'dpr-cma-preparation', price: 4999 },
    { category: 'Government & MSME Services', subCategory: 'Project & Finance Support', title: 'CMA Data Preparation', slug: 'cma-data-preparation', price: 4999 },
    { category: 'Government & MSME Services', subCategory: 'Project & Finance Support', title: 'Bank Loans - Term Loan + Working Capital', slug: 'bank-loans-support', price: 7999 },
    { category: 'Government & MSME Services', subCategory: 'Project & Finance Support', title: 'CGTMSE Loan Support', slug: 'cgtmse-loan-support', price: 6999 },
    { category: 'Government & MSME Services', subCategory: 'Project & Finance Support', title: 'PMEGP Loan Support', slug: 'pmegp-loan-support', price: 6999 },
    { category: 'Government & MSME Services', subCategory: 'Project & Finance Support', title: 'Mudra Loans', slug: 'mudra-loans-support', price: 3499 },
    { category: 'Government & MSME Services', subCategory: 'Project & Finance Support', title: 'Stand-Up India Loan Assistance', slug: 'standup-india-loans', price: 6999 },

    // 13. MSME & Subsidy Schemes
    { category: 'Government & MSME Services', subCategory: 'MSME & Subsidy Schemes', title: 'CLCSS / ZED Scheme Support', slug: 'zed-scheme-support', price: 7999 },
    { category: 'Government & MSME Services', subCategory: 'MSME & Subsidy Schemes', title: 'PMFME (Food Processing Units)', slug: 'pmfme-subsidy-scheme', price: 9999 },
    { category: 'Government & MSME Services', subCategory: 'MSME & Subsidy Schemes', title: 'NSIC Schemes', slug: 'nsic-schemes-registration', price: 4999 },
    { category: 'Government & MSME Services', subCategory: 'MSME & Subsidy Schemes', title: 'NABARD Schemes', slug: 'nabard-subsidy-schemes', price: 11999 },
    { category: 'Government & MSME Services', subCategory: 'MSME & Subsidy Schemes', title: 'Cold Chain & Food Processing Subsidy', slug: 'cold-chain-subsidy', price: 14999 },
    { category: 'Government & MSME Services', subCategory: 'MSME & Subsidy Schemes', title: 'AP/TS State Industrial Subsidy Schemes', slug: 'msme-subsidies-loans', price: 14999 },

    // 14. Startup & Branding Support
    { category: 'Branding & Industrial Setup', subCategory: 'Startup & Branding Support', title: 'Business Plan Preparation', slug: 'business-plan-preparation', price: 7999 },
    { category: 'Branding & Industrial Setup', subCategory: 'Startup & Branding Support', title: 'Pitch Decks for Funding', slug: 'pitch-deck-preparation', price: 9999 },
    { category: 'Branding & Industrial Setup', subCategory: 'Startup & Branding Support', title: 'Website & Branding Consulting', slug: 'website-branding-consulting', price: 6999 },
    { category: 'Branding & Industrial Setup', subCategory: 'Startup & Branding Support', title: 'Vendor Empanelment Documentation', slug: 'vendor-empanelment-docs', price: 4999 },
    { category: 'Branding & Industrial Setup', subCategory: 'Startup & Branding Support', title: 'HR Policy Documentation', slug: 'hr-policy-documentation', price: 4999 },
    { category: 'Branding & Industrial Setup', subCategory: 'Startup & Branding Support', title: 'SOP Creation', slug: 'sop-creation-services', price: 6999 },

    // 15. Additional Services
    { category: 'Branding & Industrial Setup', subCategory: 'Additional Services', title: 'Loan File Documentation & Follow-up', slug: 'loan-file-documentation', price: 4999 },
    { category: 'Branding & Industrial Setup', subCategory: 'Additional Services', title: 'Insurance Services (Business, Fire, Marine)', slug: 'commercial-business-insurance', price: 2999 },
    { category: 'Branding & Industrial Setup', subCategory: 'Additional Services', title: 'Digital Marketing Support', slug: 'digital-marketing-support', price: 4999 },
    { category: 'Branding & Industrial Setup', subCategory: 'Additional Services', title: 'PAN / TAN Applications', slug: 'pan-tan-applications', price: 999 },
    { category: 'Branding & Industrial Setup', subCategory: 'Additional Services', title: 'Trademark & IP Services', slug: 'trademark-registration', price: 1999 },
    { category: 'Branding & Industrial Setup', subCategory: 'Additional Services', title: 'Wealth Portfolio Management', slug: 'wealth-portfolio-management', price: 9999 },

    // 16. Industrial Support
    { category: 'Branding & Industrial Setup', subCategory: 'Industrial Support', title: 'Machinery Sourcing & Imports', slug: 'machinery-sourcing', price: 9999 },
    { category: 'Branding & Industrial Setup', subCategory: 'Industrial Support', title: 'Vendor Identification & Supplier Verification', slug: 'vendor-verification-services', price: 4999 },
    { category: 'Branding & Industrial Setup', subCategory: 'Industrial Support', title: 'Turnkey Machinery Setup Assistance', slug: 'turnkey-plant-engineering', price: 19999 },
    { category: 'Branding & Industrial Setup', subCategory: 'Industrial Support', title: 'Technology Upgradation Consulting', slug: 'technology-upgradation-consulting', price: 11999 },
    { category: 'Branding & Industrial Setup', subCategory: 'Industrial Support', title: 'Industry Selection & Feasibility Analysis', slug: 'industrial-feasibility-analysis', price: 14999 }
];

export const EXTENDED_SERVICE_CONFIGS = {};

MENU_ITEMS_LIST.forEach(item => {
    const config = generateConfig(item);
    EXTENDED_SERVICE_CONFIGS[item.slug] = config;
    // Also map title variations so exact names resolve directly
    EXTENDED_SERVICE_CONFIGS[slugify(item.title)] = config;
    EXTENDED_SERVICE_CONFIGS[encodeURIComponent(item.title)] = config;
    EXTENDED_SERVICE_CONFIGS[item.title.toLowerCase()] = config;
});
