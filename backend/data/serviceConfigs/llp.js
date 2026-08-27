export const llpConfig = {
    pageId: 'llp-registration',
    title: 'LLP Registration (Limited Liability Partnership)',
    description: 'Register your Limited Liability Partnership (LLP) online with MCA. Enjoy limited liability protection with lower compliance burden compared to Pvt Ltd.',
    iconKey: 'Briefcase',
    hero: {
        title: 'Register Your LLP Online in {city}',
        subtitle: 'The perfect blend of a partnership and private limited company for professionals and partners in {city}, {state}.',
        badgeText: 'Zero Audit Under ₹40 Lakh Turnover',
        consultationPrice: 499
    },
    stats: [
        { value: '8-10 Days', label: 'Avg. Turnaround' },
        { value: '2 Partners', label: 'Minimum' },
        { value: 'No Min Capital', label: 'Requirement' },
        { value: '4.9/5', label: 'Rating' }
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
            name: 'LLP Advisory Call',
            price: 499,
            description: 'Expert call with CA/CS to structure profit-sharing and capital contribution.',
            features: ['30 Mins LLP Specialist Call', 'LLP vs Pvt Ltd Comparison', 'Name Availability Search', 'Capital Ratio & Partner Clauses', 'Compliance Checklist'],
            buttonText: 'Book LLP Consultation',
            isAdjustable: true
        },
        {
            id: 'basic',
            name: 'Basic LLP Setup',
            price: 3999,
            description: 'Essential incorporation under LLP Act 2008.',
            features: ['Name Approval (RUN-LLP)', '2 DPIN & 2 Class 3 DSC', 'FiLLiP Incorporation Filing', 'Certificate of Incorporation (COI)', 'LLP PAN & TAN Issuance', 'MSME / Udyam Certificate'],
            buttonText: 'Select Basic'
        },
        {
            id: 'standard',
            name: 'Standard LLP + Agreement',
            price: 7499,
            description: 'Complete legal setup including Form 3 agreement execution.',
            features: ['Everything in Basic', 'Custom LLP Agreement Drafting', 'Form 3 Filing with MCA/ROC', 'Stamp Duty Guidance', 'GST Registration', 'Bank Current Account Kit', '1 Month Accounts Support'],
            buttonText: 'Select Standard',
            isPopular: true
        },
        {
            id: 'complete',
            name: 'Complete Business Ready LLP',
            price: 11999,
            description: 'Full startup package with tax filing and web presence.',
            features: ['Everything in Standard', 'Import Export Code (IEC)', 'GST Return Filing (2 Months)', 'Professional Business Website', '1 Yr Domain & Hosting', 'Dedicated Relationship Manager'],
            buttonText: 'Select Complete'
        }
    ],
    reviews: [
        {
            name: 'Kavita Reddy',
            company: 'Vanguard Legal Partners LLP',
            avatar: 'KR',
            rating: 5,
            date: '11 May 2026',
            text: 'We set up our consulting practice as an LLP. VR Here completed everything from name approval to Form 3 Agreement drafting in 8 days flat. Super smooth service!',
            verified: true
        },
        {
            name: 'Aditya Verma',
            company: 'NextGen Robotics LLP',
            avatar: 'AV',
            rating: 5,
            date: '25 April 2026',
            text: 'Saved us thousands in annual compliance fees by recommending LLP over Pvt Ltd for our service firm. Highly transparent pricing.',
            verified: true
        }
    ],
    steps: [
        { number: '01', title: 'Partner Consultation', desc: 'Finalize partner profit-sharing ratio and book consultation for ₹499 (fully adjustable).', badge: '15 Mins' },
        { number: '02', title: 'DSC & Name Reservation', desc: 'Generate Designated Partner DSCs and reserve name via RUN-LLP on MCA.', badge: 'Days 1-3' },
        { number: '03', title: 'FiLLiP Incorporation', desc: 'File the FiLLiP integrated form for incorporation and obtain Certificate of Incorporation.', badge: 'Days 4-7' },
        { number: '04', title: 'LLP Agreement (Form 3)', desc: 'Draft, notarize, and file your customized LLP Agreement in Form 3 within 30 days.', badge: 'Days 8-10' }
    ],
    faqs: [
        { q: 'What is an LLP and how does it differ from a Private Limited Company?', a: 'An LLP provides limited liability protection to partners like a company, but has simpler compliance rules, no mandatory audit if turnover is under ₹40 Lakhs (or contribution under ₹25 Lakhs), and no dividend distribution tax.' },
        { q: 'How many partners are required to register an LLP in {city}?', a: 'A minimum of 2 designated partners are required. At least one must be a resident of India.' },
        { q: 'Why is filing the LLP Agreement (Form 3) mandatory?', a: 'Under the LLP Act 2008, the signed and notarized LLP Agreement must be filed in Form 3 with the ROC within 30 days of incorporation to avoid heavy daily penalties.' },
        { q: 'Is audit mandatory for an LLP in India?', a: 'No! Audit is exempted for LLPs unless their annual turnover exceeds ₹40 Lakhs or total partner contribution exceeds ₹25 Lakhs.' }
    ],
    guide: {
        title: 'Guide to LLP Registration in India',
        overview: 'Limited Liability Partnership (LLP) is an ideal business structure for professionals, consultancies, and small-to-medium businesses who want limited liability protection without the complex compliance burden of a Private Limited Company.',
        sections: [
            {
                heading: 'Eligibility Criteria for LLP Formation',
                content: 'To form an LLP under the Limited Liability Partnership Act, 2008:',
                bullets: [
                    'Minimum 2 Designated Partners (At least one Indian resident).',
                    'Digital Signature Certificate (DSC) for all designated partners.',
                    'Designated Partner Identification Number (DPIN).',
                    'Registered office address in India with owner consent.',
                    'Execution of LLP Agreement on state-specific stamp paper.'
                ]
            },
            {
                heading: 'Key Advantages of LLP Structure',
                content: '',
                bullets: [
                    'Limited Liability: Partners are not personally liable for wrongful acts of other partners.',
                    'Lower Compliance Cost: No mandatory board meetings, statutory register maintenance, or secretarial audits.',
                    'Tax Benefits: Profits can be distributed to partners without Dividend Distribution Tax (DDT).',
                    'No Capital Restriction: Start with any amount of capital contribution.'
                ]
            }
        ],
        checklistTitle: 'Documents Needed for LLP Registration',
        checklist: [
            'PAN Card and Aadhaar Card of all Designated Partners',
            'Passport Size Photographs of Partners',
            'Bank Statement / Utility Bill (within 2 months) as partner address proof',
            'Registered office electricity bill / property tax receipt',
            'No Objection Certificate (NOC) from landlord'
        ]
    },
    popularSearches: [
        'LLP Registration Online', 'LLP Agreement Form 3', 'LLP vs Private Limited',
        'LLP Registration Fees', 'Limited Liability Partnership India', 'Designated Partner DPIN',
        'LLP Tax Audit Exemption', 'RUN-LLP MCA Name Search', 'LLP Annual Filing Form 11'
    ],
    seoSettings: {
        titleTag: 'LLP Registration Online in India | Limited Liability Partnership | VR Here',
        metaDescription: 'Register your Limited Liability Partnership (LLP) online in 8-10 days. Get MCA Certificate of Incorporation, LLP Agreement drafting, DPIN, DSC & PAN/TAN.',
        focusKeywords: ['LLP Registration', 'Limited Liability Partnership', 'Register LLP Online']
    }
};
