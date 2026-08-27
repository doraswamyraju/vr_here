export const partnershipConfig = {
    pageId: 'partnership-firm-registration',
    title: 'Partnership Firm Registration',
    description: 'Register your Partnership Firm under the Indian Partnership Act, 1932. Get expert deed drafting, notary, and Registrar of Firms (ROF) certificate.',
    iconKey: 'Briefcase',
    hero: {
        title: 'Register Partnership Firm Online in {city}',
        subtitle: 'Fast and legally sound partnership firm setup with customized partnership deed drafting in {city}, {state}.',
        badgeText: 'Indian Partnership Act 1932',
        consultationPrice: 499
    },
    stats: [
        { value: '3-5 Days', label: 'Deed & Notary' },
        { value: '2+ Partners', label: 'Minimum' },
        { value: '100% Legal', label: 'Protection' },
        { value: '3000+', label: 'Firms Formed' }
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
            name: 'Partnership Advisory',
            price: 499,
            description: 'Legal advice on partner clauses, dispute resolution, and capital ratios.',
            features: ['30 Mins Legal Expert Call', 'Partnership Act 1932 Guidance', 'Deed Customization Advice', 'Profit/Loss Sharing Ratio Check', 'ROF vs Notary Advisory'],
            buttonText: 'Book Partnership Call',
            isAdjustable: true
        },
        {
            id: 'deed',
            name: 'Custom Deed Drafting',
            price: 1999,
            description: 'Legally vetted partnership deed drafted by expert advocate.',
            features: ['Custom Partnership Deed Drafting', 'Capital Contribution Clauses', 'Profit & Loss Sharing Ratios', 'Dispute Resolution & Exit Clauses', 'Banking & Signing Authority Clauses'],
            buttonText: 'Select Deed Only'
        },
        {
            id: 'notarized',
            name: 'Notarized Setup Package',
            price: 3499,
            description: 'Complete notarized deed with PAN, TAN and MSME registration.',
            features: ['Everything in Deed Package', 'Non-Judicial Stamp Paper Processing', 'Notary Attestation & Execution', 'Firm PAN & TAN Application', 'MSME / Udyam Certificate', 'Current Bank Account Kit'],
            buttonText: 'Select Notarized',
            isPopular: true
        },
        {
            id: 'rof',
            name: 'Full ROF Registered Package',
            price: 5999,
            description: 'Formal registration with Registrar of Firms (ROF).',
            features: ['Everything in Notarized Package', 'Form A & Form B Application to ROF', 'Registrar of Firms (ROF) Certificate', 'GST Registration', '1 Month Accounting Support', 'Dedicated Legal Consultant'],
            buttonText: 'Select ROF Registered'
        }
    ],
    reviews: [
        {
            name: 'Prakash Rao',
            company: 'Rao & Brothers Trading Co',
            avatar: 'PR',
            rating: 5,
            date: '08 May 2026',
            text: 'Got our partnership deed drafted, stamped, and firm PAN delivered in 4 days. The lawyer explained all clauses clearly. Very satisfied!',
            verified: true
        },
        {
            name: 'Deepak Joshi',
            company: 'Apex Logistics Partners',
            avatar: 'DJ',
            rating: 5,
            date: '20 April 2026',
            text: 'We opted for the ROF Registered package. VR Here took care of all state registrar filings without us having to visit any government office.',
            verified: true
        }
    ],
    steps: [
        { number: '01', title: 'Terms Alignment', desc: 'Decide partner names, capital contribution, and profit/loss sharing ratios with our legal team.', badge: 'Day 1' },
        { number: '02', title: 'Deed Drafting', desc: 'Our corporate lawyers draft a comprehensive, airtight Partnership Deed customized for your business.', badge: 'Day 2' },
        { number: '03', title: 'Stamp Duty & Notary', desc: 'Print on state-specific non-judicial stamp paper and execute notary attestation with partner signatures.', badge: 'Day 3' },
        { number: '04', title: 'PAN, TAN & ROF Filing', desc: 'Obtain Firm PAN, TAN, MSME registration, and submit Form A to the state Registrar of Firms.', badge: 'Days 4-5' }
    ],
    faqs: [
        { q: 'Is it mandatory to register a Partnership Firm with the Registrar of Firms (ROF)?', a: 'Under the Indian Partnership Act 1932, registration with ROF is optional but highly recommended because an unregistered firm cannot file a lawsuit against third parties to enforce contractual rights.' },
        { q: 'What is the difference between a Partnership Firm and an LLP?', a: 'In a traditional Partnership Firm, partners have unlimited personal liability. In an LLP, liability is strictly limited to their capital contribution and it is governed by the MCA.' },
        { q: 'How is a Partnership Firm taxed in India?', a: 'Partnership Firms are taxed at a flat rate of 30% on total net profits plus applicable surcharge and cess.' },
        { q: 'What documents are required to open a partnership bank account?', a: 'Notarized Partnership Deed, Firm PAN card, Address proof of registered office (electricity bill/rent agreement), and KYC documents of all partners.' }
    ],
    guide: {
        title: 'Guide to Partnership Firm Registration in India',
        overview: 'A Partnership Firm is a popular form of business organization in India where two or more persons come together to carry on a business and share profits and losses under the Indian Partnership Act, 1932.',
        sections: [
            {
                heading: 'Essential Elements of a Partnership Firm',
                content: 'To constitute a legal partnership in India:',
                bullets: [
                    'Minimum 2 Partners & Maximum 50 Partners.',
                    'An agreement (oral or written, written deed highly recommended).',
                    'Agreement must be to carry on a lawful business.',
                    'Sharing of profits and losses among partners.',
                    'Business carried on by all or any of them acting for all (Mutual Agency).'
                ]
            },
            {
                heading: 'Registered vs Unregistered Partnership Firm',
                content: '',
                bullets: [
                    'Right to Sue: A registered firm can sue third parties and partners in court; an unregistered firm cannot file legal claims above ₹100.',
                    'Set-off Claims: Registered firms can claim set-offs in court proceedings.',
                    'Bank & Government Credibility: Government tenders and premier enterprise clients require ROF registration.'
                ]
            }
        ],
        checklistTitle: 'Documents Needed for Partnership Firm Setup',
        checklist: [
            'PAN Card and Aadhaar Card of all Partners',
            'Passport Size Photographs of all Partners',
            'Electricity / Water bill of the business address',
            'Rent Agreement and Landlord NOC',
            'State non-judicial stamp paper for Deed printing'
        ]
    },
    popularSearches: [
        'Partnership Firm Registration', 'Partnership Deed Drafting Online', 'ROF Registration India',
        'Partnership Firm vs LLP', 'Partnership PAN Card Application', 'Indian Partnership Act 1932',
        'Partnership Firm Bank Account Kit', 'Notarized Partnership Deed Format'
    ],
    seoSettings: {
        titleTag: 'Partnership Firm Registration Online in India | VR Here',
        metaDescription: 'Register your Partnership Firm in 3-5 days. Get expert Partnership Deed drafting, Stamp Paper Notary, ROF registration, PAN, TAN & GST registration.',
        focusKeywords: ['Partnership Firm Registration', 'Partnership Deed Online', 'Register Partnership Firm']
    }
};
