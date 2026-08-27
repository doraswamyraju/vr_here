export const proprietorshipConfig = {
    pageId: 'proprietorship-setup',
    title: 'Proprietorship Setup (Sole Proprietorship)',
    description: 'Start your individual business as a Sole Proprietor in India. Get Udyam MSME, GST, Shop Act registration, and business bank account opening support in 48 hours.',
    iconKey: 'Store',
    hero: {
        title: 'Sole Proprietorship Registration Online in {city}',
        subtitle: 'Fastest way to start your business as a single owner with zero compliance burden in {city}, {state}.',
        badgeText: 'Ready in 48 Hours',
        consultationPrice: 299
    },
    stats: [
        { value: '2 Days', label: 'Setup Time' },
        { value: '1 Owner', label: 'Full Control' },
        { value: 'Minimal Cost', label: 'Low Investment' },
        { value: '100%', label: 'Digital Process' }
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
            name: 'Proprietor Quick Advisory',
            price: 299,
            description: 'Instant call to choose the right licenses and bank account documentation.',
            features: ['20 Mins Business Advisory Call', 'Trade Name Selection Advice', 'GST vs MSME Requirement Check', 'Bank Current Account Readiness', 'Tax Planning Guidance'],
            buttonText: 'Book Quick Call',
            isAdjustable: true
        },
        {
            id: 'starter',
            name: 'Starter Proprietorship',
            price: 1499,
            description: 'Essential business registrations to open a current bank account.',
            features: ['Udyam / MSME Registration Certificate', 'Current Bank Account Resolution Kit', 'Government Business ID Generation', 'Professional Invoicing Template'],
            buttonText: 'Select Starter'
        },
        {
            id: 'growth',
            name: 'Growth Proprietorship Setup',
            price: 2999,
            description: 'Complete registration with GST & Shop Act license.',
            features: ['Everything in Starter', 'GST Registration (TRN & ARN to Final GSTIN)', 'Shop & Establishment Certificate / Trade License', 'Bank Verification Support', '1 Month Accounting Advisory'],
            buttonText: 'Select Growth',
            isPopular: true
        },
        {
            id: 'allinone',
            name: 'All-in-One Business Launch',
            price: 4999,
            description: 'Full commercial launch with web presence and tax support.',
            features: ['Everything in Growth', 'Import Export Code (IEC)', '2 Months GST Return Filing Support', 'Single Page Business Landing Website', 'Dedicated Tax Advisor'],
            buttonText: 'Select All-in-One'
        }
    ],
    reviews: [
        {
            name: 'Rajesh Sharma',
            company: 'Sharma Retail Ventures',
            avatar: 'RS',
            rating: 5,
            date: '19 May 2026',
            text: 'Applied in the morning, received my Udyam certificate and GST ARN within 24 hours. Opened my ICICI Bank current account without any hassle!',
            verified: true
        },
        {
            name: 'Sneha Patel',
            company: 'StyleCraft Studio',
            avatar: 'SP',
            rating: 5,
            date: '04 May 2026',
            text: 'Best service for freelancers and solo traders. No hidden charges and direct WhatsApp support from their CA team.',
            verified: true
        }
    ],
    steps: [
        { number: '01', title: 'Submit Basic KYC', desc: 'Provide your PAN, Aadhaar, business trade name, and office address proof.', badge: '10 Mins' },
        { number: '02', title: 'Udyam MSME Registration', desc: 'We file your application on the Ministry of MSME portal to generate your official government Udyam number.', badge: 'Day 1' },
        { number: '03', title: 'GST / Shop Act Licensing', desc: 'Submit and verify GSTIN / Shop Act license to provide the second proof required by RBI for bank accounts.', badge: 'Days 1-2' },
        { number: '04', title: 'Current Account Opening', desc: 'Receive your complete business registration kit ready for bank account opening and operations.', badge: 'Day 2' }
    ],
    faqs: [
        { q: 'What is a Sole Proprietorship in India?', a: 'A Sole Proprietorship is an unregistered business entity owned, managed, and controlled by a single individual with no legal distinction between the owner and the business.' },
        { q: 'How is a Sole Proprietorship officially recognized by banks?', a: 'Banks require at least two government registration certificates (such as Udyam MSME, GSTIN, or Shop & Establishment Act license) in the trade name to open a current account.' },
        { q: 'Is GST mandatory for a Sole Proprietorship?', a: 'GST is mandatory if your annual turnover exceeds ₹40 Lakhs for goods (₹20 Lakhs for services) or if you sell across state borders (e-commerce like Amazon/Flipkart).' },
        { q: 'Can a Sole Proprietorship be converted to a Private Limited Company later?', a: 'Yes! As your business expands and raises capital, you can seamlessly convert your proprietorship into a Private Limited Company or LLP.' }
    ],
    guide: {
        title: 'Guide to Sole Proprietorship Setup in India',
        overview: 'Sole Proprietorship is the simplest, most affordable, and fastest way to start a business in India for individual entrepreneurs, retailers, freelancers, and consultants.',
        sections: [
            {
                heading: 'Why Choose Sole Proprietorship?',
                content: '',
                bullets: [
                    '100% Control: Single decision-maker with complete autonomy.',
                    'Minimal Compliance: No MCA filings, annual secretarial audits, or board meetings.',
                    'Direct Tax Benefits: Profits are taxed at individual income tax slab rates.',
                    'Ease of Closure: Quick and hassle-free winding up without bureaucratic red tape.'
                ]
            },
            {
                heading: 'RBI Guidelines for Current Bank Account',
                content: 'According to RBI KYC norms, banks require two of the following identity documents in the trade name:',
                bullets: [
                    'Udyam / MSME Registration Certificate.',
                    'GST Registration Certificate.',
                    'Shop and Establishment Act License.',
                    'Professional Tax Registration Certificate.'
                ]
            }
        ],
        checklistTitle: 'Documents Required for Proprietorship Setup',
        checklist: [
            'PAN Card and Aadhaar Card of the Proprietor',
            'Passport Size Photograph of Owner',
            'Electricity / Water bill of the business address',
            'NOC from property owner or Rent Agreement',
            'Cancelled Cheque / Bank Statement of Savings Account'
        ]
    },
    popularSearches: [
        'Proprietorship Registration Online', 'Sole Proprietorship Setup', 'Udyam MSME Certificate',
        'Proprietorship Current Bank Account', 'GST for Sole Proprietor', 'Shop Act License Online',
        'Sole Proprietorship vs OPC', 'Cheapest Way to Start Business India'
    ],
    seoSettings: {
        titleTag: 'Sole Proprietorship Registration Online in India | VR Here',
        metaDescription: 'Start your Sole Proprietorship in 2 days. Get Udyam MSME certificate, GST registration, Shop Act license and business bank account opening kit.',
        focusKeywords: ['Sole Proprietorship Registration', 'Proprietorship Setup', 'Start Proprietorship Online']
    }
};
