export const societyTrustConfig = {
    pageId: 'society-trust-registration',
    title: 'Society & Trust Registration',
    description: 'Register a Public Charitable Trust under the Indian Trusts Act, 1882 or Society under the Societies Registration Act, 1860. Complete deed drafting, sub-registrar execution, and 12A/80G support.',
    iconKey: 'Award',
    hero: {
        title: 'Register Society or Charitable Trust Online in {city}',
        subtitle: 'Establish your charitable, educational, or religious organization with legal trust deed drafting and government registration in {city}, {state}.',
        badgeText: 'Indian Trusts Act 1882 / Societies Act',
        consultationPrice: 999
    },
    stats: [
        { value: '10-15 Days', label: 'Registration Time' },
        { value: 'Trust / Society', label: 'Custom Structure' },
        { value: '12A & 80G', label: 'Eligible' },
        { value: '100% Legal', label: 'Govt Approved' }
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
            name: 'Trust / Society Advisory',
            price: 999,
            description: 'Legal advisory on choosing between Public Trust, Society, or Section 8 NGO.',
            features: ['45 Mins Legal Expert Call', 'Trust vs Society Comparative Study', 'Settlor & Trustee Roles Structuring', '12A/80G Eligibility Assessment', 'State Sub-Registrar Process Flow'],
            buttonText: 'Book Trust Advisory',
            isAdjustable: true
        },
        {
            id: 'trust',
            name: 'Charitable Trust Setup',
            price: 8499,
            description: 'Complete Trust Deed drafting and Sub-Registrar execution guidance.',
            features: ['Custom Public Charitable Trust Deed Drafting', 'Settlor, Trustee & Beneficiary Clauses', 'State-Specific Stamp Paper Guidance', 'Sub-Registrar Registration Support', 'Trust PAN & TAN Application', 'Bank Current Account Resolution Kit'],
            buttonText: 'Select Trust Package'
        },
        {
            id: 'society',
            name: 'Society Registration Package',
            price: 12999,
            description: 'Registration under Societies Registration Act 1860.',
            features: ['Drafting Memorandum of Association (MoA)', 'Drafting Rules & Regulations / By-laws', '7+ Governing Body Member Documentation', 'State Registrar of Societies Filing', 'Society Registration Certificate', 'Society PAN & TAN Issuance'],
            buttonText: 'Select Society Package',
            isPopular: true
        },
        {
            id: 'fullsuite',
            name: 'Full 12A/80G & DARPAN NGO Suite',
            price: 24999,
            description: 'Complete Trust/Society setup with full tax exemption and portal registration.',
            features: ['Everything in Trust or Society Package', 'Provisional 12A Tax Exemption on IT Portal', 'Provisional 80G Tax Exemption for Donors', 'NITI Aayog DARPAN Portal Registration', '1 Yr Legal & Compliance Advisory', 'Dedicated NGO Legal Advisor'],
            buttonText: 'Select Full NGO Suite'
        }
    ],
    reviews: [
        {
            name: 'Swami Vidyananda',
            company: 'Ananda Charitable & Educational Trust',
            avatar: 'SV',
            rating: 5,
            date: '22 June 2026',
            text: 'We registered our educational trust with VR Here. Their lawyers drafted comprehensive trust clauses covering school management, 12A, and 80G seamlessly.',
            verified: true
        },
        {
            name: 'M. K. Narayanan',
            company: 'Vibrant Youth Welfare Society',
            avatar: 'MN',
            rating: 5,
            date: '10 June 2026',
            text: 'Setting up a society with 7 members across state districts was daunting, but VR Here managed all documentation and registrar submissions with extreme perfection.',
            verified: true
        }
    ],
    steps: [
        { number: '01', title: 'Structure Selection', desc: 'Select whether a Public Charitable Trust (2+ trustees) or Society (7+ members) fits your objective.', badge: 'Day 1' },
        { number: '02', title: 'Deed / By-laws Drafting', desc: 'Our senior advocates draft the detailed Trust Deed or Society Memorandum and By-laws.', badge: 'Days 2-4' },
        { number: '03', title: 'Sub-Registrar / ROF Execution', desc: 'Execute on non-judicial stamp paper and register before the local Sub-Registrar / Registrar of Societies.', badge: 'Days 5-10' },
        { number: '04', title: 'PAN, TAN & 12A/80G Filing', desc: 'Obtain entity PAN, TAN, and apply for 12A & 80G tax exemptions on the Income Tax Portal.', badge: 'Days 10-15' }
    ],
    faqs: [
        { q: 'What is the main difference between a Trust and a Society?', a: 'A Trust requires a minimum of 2 trustees and is created by a Trust Deed registered before the Sub-Registrar. A Society requires at least 7 members and is governed by a Memorandum and By-laws registered under the Societies Registration Act.' },
        { q: 'Is registration under 12A and 80G necessary for a Trust or Society?', a: 'Yes! Without 12A registration, the trust or society income will be taxed at maximum marginal rates. 80G registration allows donors to claim 50% income tax deductions on their donations.' },
        { q: 'Can a family trust be registered online?', a: 'We handle both Private Family Trusts (for wealth and succession planning) and Public Charitable Trusts (for social, educational, and religious causes).' },
        { q: 'How many members are required to form a Society in {city}?', a: 'A minimum of 7 members are required to form a Society under the Societies Registration Act, 1860.' }
    ],
    guide: {
        title: 'Guide to Society & Trust Registration in India',
        overview: 'Charitable Trusts and Societies are time-tested legal vehicles in India for running schools, colleges, temples, healthcare centers, sports clubs, and cultural organizations.',
        sections: [
            {
                heading: 'Comparative Analysis: Trust vs Society',
                content: '',
                bullets: [
                    'Public Charitable Trust: Formed under Indian Trusts Act; Minimum 2 trustees; Simple management via Board of Trustees; Registered at local Sub-Registrar office.',
                    'Registered Society: Formed under Societies Registration Act 1860; Minimum 7 governing members; Democratic election of President, Secretary, and Treasurer; Registered at Registrar of Societies.'
                ]
            },
            {
                heading: 'Tax Exemptions for Trusts and Societies',
                content: '',
                bullets: [
                    'Section 12A Exemption: Total exemption from tax on donation income, voluntary contributions, and interest.',
                    'Section 80G Certificate: Generates 50% tax benefit receipts for all donors.',
                    'NITI Aayog DARPAN: Mandatory unique NGO ID to receive central and state government welfare grants.'
                ]
            }
        ],
        checklistTitle: 'Documents Required for Trust / Society Registration',
        checklist: [
            'PAN Card and Aadhaar Card of all Trustees / Society Members',
            'Passport Size Photographs of all Members',
            'Registered office electricity bill and Property Owner NOC',
            'State non-judicial stamp paper (as per state stamp duty acts)',
            'Two witnesses with KYC proofs for Sub-Registrar execution'
        ]
    },
    popularSearches: [
        'Trust Registration Online', 'Society Registration Act 1860', 'Charitable Trust Deed Drafting',
        'Trust vs Society vs Section 8', '12A 80G Exemption Online', 'NITI Aayog DARPAN Registration',
        'Public Charitable Trust India', 'How to Register a Society'
    ],
    seoSettings: {
        titleTag: 'Society & Trust Registration Online in India | VR Here',
        metaDescription: 'Register your Charitable Trust or Society in 10-15 days. Get expert Trust Deed drafting, Sub-Registrar / Societies Registrar registration, PAN, TAN & 12A/80G tax exemptions.',
        focusKeywords: ['Trust Registration', 'Society Registration', 'Charitable Trust Setup']
    }
};
