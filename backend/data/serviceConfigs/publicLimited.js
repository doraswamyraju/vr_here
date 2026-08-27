export const publicLimitedConfig = {
    pageId: 'public-limited-company',
    title: 'Public Limited Company Registration',
    description: 'Incorporate a Public Limited Company in India for massive scalability, public share capital, and enterprise credibility. 100% online MCA filing.',
    iconKey: 'Building2',
    hero: {
        title: 'Register Public Limited Company Online in {city}',
        subtitle: 'Launch an enterprise-grade public corporation with unlimited shareholders, debentures & capital access in {city}, {state}.',
        badgeText: 'Enterprise-Grade Incorporation',
        consultationPrice: 999
    },
    stats: [
        { value: '12-15 Days', label: 'Turnaround' },
        { value: '7+ Members', label: 'Requirement' },
        { value: '3 Directors', label: 'Min. Board' },
        { value: '100%', label: 'MCA Approved' }
    ],
    logos: [
        { name: 'Stripe for Startups', iconKey: 'Briefcase', colorClass: 'text-indigo-600' },
        { name: 'Razorpay Partner', iconKey: 'Zap', colorClass: 'text-blue-500' },
        { name: 'Google Cloud Program', iconKey: 'Globe', colorClass: 'text-red-500' },
        { name: 'AWS Activate', iconKey: 'Factory', colorClass: 'text-orange-500' },
        { name: 'Microsoft Founders Hub', iconKey: 'Building2', colorClass: 'text-blue-600' },
        { name: 'Shopify Partners', iconKey: 'ShieldCheck', colorClass: 'text-emerald-500' },
        { name: 'HubSpot Ecosystem', iconKey: 'Award', colorClass: 'text-orange-600' }
    ],
    packages: [
        {
            id: 'consultation',
            name: 'Enterprise Advisory Call',
            price: 999,
            description: 'Pre-incorporation structural guidance with senior Corporate Secretary (CS).',
            features: ['45 Mins CS/CA Consultation', 'Public Share Capital Structuring', 'Statutory Board Composition Advice', 'Name Eligibility & Trademark Check', 'Complete Regulatory Roadmap'],
            buttonText: 'Book Public Co Consultation',
            isAdjustable: true
        },
        {
            id: 'standard',
            name: 'Standard Public Incorporation',
            price: 14999,
            description: 'Complete legal formation under Companies Act 2013.',
            features: ['Name Approval (RUN)', 'Certificate of Incorporation (COI)', '3 DIN & 3 Class 3 DSC', 'Drafting Custom MOA & AOA', 'PAN & TAN Issuance', 'PF & ESI Registration', 'MSME / Udyam Registration', 'Shareholder Ledger Template'],
            buttonText: 'Select Standard'
        },
        {
            id: 'premium',
            name: 'Premium Compliance Suite',
            price: 24999,
            description: 'Complete corporate launch with statutory approvals & tax setup.',
            features: ['Everything in Standard', 'GST Registration', 'Auditor Appointment (ADT-1)', 'Commencement of Business (INC-20A)', 'Share Certificate Issuance (SH-1)', 'Statutory Registers Setup', 'First Board Meeting Documentation', '1 Yr Corporate Compliance Advisory'],
            buttonText: 'Select Premium',
            isPopular: true
        },
        {
            id: 'enterprise',
            name: 'Enterprise Full Scale Suite',
            price: 39999,
            description: 'Turnkey public entity suite with corporate secretarial manager.',
            features: ['Everything in Premium', 'Import Export Code (IEC)', 'Professional Corporate Website (1 Yr Hosting)', 'Corporate Domain & Webmails', 'Secretarial Audit Assistance', 'ROC Annual Filing Support', 'Dedicated Corporate Legal Manager'],
            buttonText: 'Select Enterprise'
        }
    ],
    reviews: [
        {
            name: 'Suresh Singhania',
            company: 'Apex Infrastructure Holdings Ltd',
            avatar: 'SS',
            rating: 5,
            date: '18 June 2026',
            text: 'Converting our vision into a Public Limited Company was seamless. VR Here handled 7 shareholders documentation, 3 DSCs, and complex AOA clauses effortlessly in 14 days.',
            verified: true
        },
        {
            name: 'Meenakshi Sundaram',
            company: 'Vedic BioPharma Limited',
            avatar: 'MS',
            rating: 5,
            date: '02 June 2026',
            text: 'Top tier corporate secretarial team. Their guidance on capital clauses and statutory board setup saved us weeks of regulatory back-and-forth.',
            verified: true
        }
    ],
    steps: [
        { number: '01', title: 'Enterprise Consultation', desc: 'Discuss capital structure, 7 subscribers, and board composition with senior corporate legal counsel.', badge: 'Day 1' },
        { number: '02', title: 'DSC & Name Reservation', desc: 'Generate Class-3 DSCs for directors and reserve unique name via MCA RUN portal.', badge: 'Days 2-4' },
        { number: '03', title: 'SPICe+ Part B & MoA/AoA', desc: 'File integrated SPICe+ forms along with specialized public company MoA and AoA articles.', badge: 'Days 5-10' },
        { number: '04', title: 'COI & Business Commencement', desc: 'Receive Certificate of Incorporation, PAN, TAN, and file Form INC-20A for operations.', badge: 'Days 12-15' }
    ],
    faqs: [
        { q: 'What is the minimum number of members required for a Public Limited Company in {city}?', a: 'A Public Limited Company requires a minimum of 7 shareholders (members) with no upper limit, and at least 3 directors.' },
        { q: 'Is there a minimum capital requirement for Public Limited Company?', a: 'As per recent MCA amendments, there is no mandatory minimum paid-up capital requirement, although authorized capital typically starts at ₹1 Lakh.' },
        { q: 'Can a Public Limited Company raise funds from the general public?', a: 'Yes! A Public Limited Company has the legal right to invite public deposits, issue debentures, and raise equity from institutional investors or the public through IPOs.' },
        { q: 'What is the key difference between Private and Public Limited Companies?', a: 'Private Limited restricts share transfers and limits members to 200. Public Limited allows free transfer of shares, unlimited members, and greater capital mobilization capacity.' }
    ],
    guide: {
        title: 'Guide to Public Limited Company Registration',
        overview: 'A Public Limited Company is the gold standard for large-scale enterprise businesses in India, offering unlimited shareholder participation, easy transferability of shares, and superior market credibility.',
        sections: [
            {
                heading: 'Eligibility Criteria for Public Limited Company',
                content: 'To incorporate a Public Limited Company under the Companies Act, 2013, the following statutory criteria must be fulfilled:',
                bullets: [
                    'Minimum 7 Shareholders (No maximum limit).',
                    'Minimum 3 Directors (At least 1 Indian resident director).',
                    'Class 3 Digital Signature Certificates (DSC) for all directors and subscribers.',
                    'The company name must strictly end with the word "Limited".',
                    'Registered office address proof with owner NOC.'
                ]
            },
            {
                heading: 'Key Benefits of Public Limited Structure',
                content: '',
                bullets: [
                    'Capital Mobilization: Ability to issue equity shares, preference shares, and debentures.',
                    'Free Transferability of Shares: Easy exit and entry for investors and institutional funds.',
                    'Superior Credibility: Enhanced trust from banks, financial institutions, and global partners.',
                    'Perpetual Succession: Uninterrupted existence regardless of changes in directors or shareholders.'
                ]
            }
        ],
        checklistTitle: 'Documents Checklist for Public Limited Incorporation',
        checklist: [
            'PAN and Aadhaar card of 3 Directors & 7 Subscribers',
            'Passport-size photographs of all directors',
            'Recent Bank Statement / Utility Bill of all directors (within 2 months)',
            'Registered office address electricity/water bill with owner NOC',
            'Signed INC-9 declaration & DIR-2 consent forms'
        ]
    },
    popularSearches: [
        'Public Limited Company Registration', 'Public Ltd Registration Fees', 'Incorporate Public Company India',
        'SPICe+ MCA Public Company', 'Public vs Private Limited', 'MCA RUN Name Approval',
        'Public Company Compliance', 'Director DIN Online', 'Best CA for Public Company Setup'
    ],
    seoSettings: {
        titleTag: 'Public Limited Company Registration Online in India | VR Here',
        metaDescription: 'Register a Public Limited Company in India in 12-15 days. Get 100% online legal incorporation, SPICe+ MCA filing, MoA/AoA, 3 DINs, DSC & CA/CS consultation.',
        focusKeywords: ['Public Limited Company', 'Public Company Registration', 'Incorporate Public Ltd']
    }
};
