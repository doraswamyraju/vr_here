export const privateLimitedConfig = {
    pageId: 'private-limited',
    title: 'Private Limited Registration',
    description: 'Launch your startup with the most credible legal structure. Get Certificate of Incorporation, MOA, AOA, PAN & TAN in 7 days.',
    iconKey: 'Apartment',
    hero: {
        title: 'Register Your Private Limited Company Online in {city}',
        subtitle: 'Launch your startup legally with expert CA/CS guidance in {city}, {state}.',
        badgeText: "India's #1 Secure Registration Platform",
        consultationPrice: 499
    },
    stats: [
        { value: '7 Days', label: 'Avg. Turnaround' },
        { value: '5000+', label: 'Happy Founders' },
        { value: '4.9/5', label: 'Google Rating' },
        { value: '100%', label: 'Online Process' }
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
            name: 'Expert Consultation',
            price: 499,
            description: 'Start here if you are unsure. Fee fully adjusted against registration.',
            features: ['30 Mins CA/CS Call', 'Business Structure Advice', 'Name Availability Check', 'Capital Structure Guidance', 'Compliance Roadmap'],
            buttonText: 'Book Consultation',
            isAdjustable: true
        },
        {
            id: 'basic',
            name: 'Basic',
            price: 5499,
            description: 'Essential registration for verified startups.',
            features: ['Name Approval (RUN)', 'Certificate of Incorporation', 'PAN & TAN', 'MOA & AOA', '2 DIN & 2 DSC', 'PF & ESI Registration', 'MSME Registration', '1 Month Accounts Support'],
            buttonText: 'Select Basic'
        },
        {
            id: 'advance',
            name: 'Advance',
            price: 11399,
            description: 'Complete compliance & web presence.',
            features: ['Everything in Basic', 'GST Registration', 'Import Export Code (IEC)', 'ISO Certification', 'GST Returns (2 Months)', 'Auditor Appointment', 'Business Commencement', 'Professional Website', '1 Yr Domain & Hosting'],
            buttonText: 'Select Advance',
            isPopular: true
        },
        {
            id: 'expert',
            name: 'Expert',
            price: 17699,
            description: 'Comprehensive package with IT filing.',
            features: ['Everything in Advance', 'Individual IT Filing', 'Google Analytics', 'Web Mails', 'Basic On-page SEO', 'Website Support (1 Yr)', 'Dedicated Relationship Mgr'],
            buttonText: 'Select Expert'
        }
    ],
    reviews: [
        {
            name: 'Vikram Malhotra',
            company: 'Trident Tech Solutions Pvt Ltd',
            avatar: 'VM',
            rating: 5,
            date: '14 May 2026',
            text: 'The Pvt Ltd registration was amazingly fast! We paid the consultation fee of 499, and it was fully adjusted in our final payment. We got our COI, PAN, and TAN in exactly 6 days without any follow-ups.',
            verified: true
        },
        {
            name: 'Ananya Iyer',
            company: 'Aura CleanTech Pvt Ltd',
            avatar: 'AI',
            rating: 5,
            date: '28 April 2026',
            text: 'Excellent service. The dashboard was super simple to upload documents, and their CA walked us through the name approval rules which saved us from rejection. Highly recommended for first-time founders!',
            verified: true
        },
        {
            name: 'Ritesh Deshmukh',
            company: 'Pixel Labs Pvt Ltd',
            avatar: 'RD',
            rating: 5,
            date: '03 May 2026',
            text: 'Top-notch professionalism. I got my company incorporated, PF/ESI registration, and even a premium business website set up through their Advance Package. Everything was delivered transparently.',
            verified: true
        }
    ],
    steps: [
        { number: '01', title: '1-Tap Expert Consultation', desc: 'Book a consultation for just ₹499. Our CAs and CS specialists analyze your business idea, recommend the ideal package, and check name availability.', badge: 'Takes 15 Mins' },
        { number: '02', title: 'Secure Document Vault Upload', desc: 'Upload basic KYC details (Aadhaar, PAN, and address proof) to our secure vault. Your information is protected by industry-leading security.', badge: 'Takes 10 Mins' },
        { number: '03', title: 'Name Approval & SPICe+ Filing', desc: 'Our legal experts prepare the MOA/AOA, generate DSCs, and file the comprehensive SPICe+ form with the Ministry of Corporate Affairs.', badge: 'Takes 2-3 Days' },
        { number: '04', title: 'Certificate & Kit Delivery', desc: 'Receive your Certificate of Incorporation (COI), PAN, TAN, and master company kit instantly in your dashboard to commence operations.', badge: 'Takes 5-7 Days' }
    ],
    faqs: [
        { q: 'How much time does it take to register a Private Limited Company in {city}?', a: 'On average, the entire process takes about 5 to 7 working days, subject to government processing times in {state}.' },
        { q: 'What are the minimum requirements to start a Pvt Ltd Company?', a: 'You need at least 2 directors (one must be an Indian resident), 2 shareholders (directors can be shareholders), and a registered office address in India.' },
        { q: 'Is physical presence required in {city} during the process?', a: 'No, the entire process is 100% online. You do not need to visit any government office.' },
        { q: 'Is the ₹499 consultation fee adjustable in my final package?', a: 'Yes! The ₹499 consultation fee is 100% adjustable against any commercial incorporation package you purchase.' },
        { q: 'What documents are required from directors?', a: 'PAN Card (mandatory), Aadhaar Card or Passport/Voter ID for identity proof, and a recent bank statement or electricity bill for address proof.' },
        { q: 'Will I get PAN, TAN, and Bank Account along with Incorporation?', a: 'Yes, PAN and TAN are automatically generated with your Certificate of Incorporation, and we assist in opening an instant zero-balance current account.' }
    ],
    guide: {
        title: 'Guide to Company Registration',
        overview: 'Incorporating a Private Limited Company in India is the most widely recognized and preferred corporate structure for startups, offering credibility, structured governance, and investor-friendly access.',
        sections: [
            {
                heading: 'What is Private Limited Company Registration?',
                content: 'It is the legal process of incorporating a business entity under the Companies Act, 2013, governed by the Ministry of Corporate Affairs (MCA). A private limited company restricts share transfers and limits members to 200. It becomes a separate legal entity distinct from directors and shareholders.',
                bullets: []
            },
            {
                heading: 'Forms of Private Limited Company',
                content: '',
                bullets: [
                    'Company Limited by Shares: The liability of members is limited to the unpaid amount on their shares.',
                    'Company Limited by Guarantee: The liability of members is limited to the amount they agree to contribute in winding up.',
                    'Unlimited Company: Members have unlimited liability for debts and obligations.'
                ]
            },
            {
                heading: 'Private Limited Minimum Requirements',
                content: '',
                bullets: [
                    'Minimum 2 Directors & maximum 15 directors.',
                    'Minimum 2 Shareholders & maximum 200 shareholders.',
                    'At least 1 Indian Resident Director.',
                    'Proposed directors must obtain DIN & DSC.',
                    'No minimum paid-up capital requirement.'
                ]
            },
            {
                heading: 'Incorporation Step-by-Step Process',
                content: '',
                bullets: [
                    'Step 1: Obtain DSC: Proposed directors apply for Digital Signature Certificate from a government certified agency.',
                    'Step 2: Reserve Unique Name (RUN): Reserving the company name through the MCA RUN portal.',
                    'Step 3: SPICe+ Form: Filing the integrated electronic form covering PAN, TAN, GSTIN, EPFO, ESIC, and Profession Tax.',
                    'Step 4: MoA & AoA: Drafting Memorandum of Association and Articles of Association to establish rules and objectives.',
                    'Step 5: COI Issuance: ROC issues the official Certificate of Incorporation.'
                ]
            }
        ],
        checklistTitle: 'Checklist of Documents Needed',
        checklist: [
            'PAN & Aadhaar of all Directors',
            'Passport Size Photograph of Directors',
            'Electricity/Water Bill (Registered Address)',
            'NOC from property owner',
            'Bank Statement / Utility Bill of Proposed Directors'
        ]
    },
    popularSearches: [
        'Register Company Online', 'Private Limited Company Registration', 'Pvt Ltd Registration Fees',
        'Company Incorporation India', 'How to register startup', 'CA Consultation Online',
        'Pvt Ltd vs LLP', 'Name Approval RUN Process', 'Director Identification Number (DIN)',
        'Digital Signature Certificate', 'MSME Certificate Online', 'Startup India Registration',
        'GST Registration CA Services', 'Cheapest Company Registration'
    ],
    seoSettings: {
        titleTag: 'Register Private Limited Company Online in India | VR Here',
        metaDescription: 'Launch your startup legally with Pvt Ltd company registration in 7 Days. Get expert CA/CS guidance, MOA/AOA, DIN, DSC, PAN, TAN & Udyam certification.',
        focusKeywords: ['Private Limited Company', 'Company Registration', 'Pvt Ltd Online']
    }
};
