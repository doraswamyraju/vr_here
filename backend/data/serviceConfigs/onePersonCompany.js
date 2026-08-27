export const onePersonCompanyConfig = {
    pageId: 'one-person-company',
    title: 'One Person Company (OPC Registration)',
    description: 'Incorporate a One Person Company (OPC) under the Companies Act, 2013. Enjoy 100% solo ownership with corporate limited liability protection.',
    iconKey: 'UserCheck',
    hero: {
        title: 'Register One Person Company (OPC) Online in {city}',
        subtitle: 'Full control for solo founders with corporate status, limited liability, and zero partner dependency in {city}, {state}.',
        badgeText: 'Solo Founder Limited Liability',
        consultationPrice: 499
    },
    stats: [
        { value: '7 Days', label: 'Turnaround' },
        { value: '1 Founder', label: '100% Equity' },
        { value: 'Limited Liability', label: 'Asset Protection' },
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
            name: 'OPC Legal Advisory',
            price: 499,
            description: 'Consultation to evaluate OPC vs Proprietorship vs Pvt Ltd for your business.',
            features: ['30 Mins Corporate Lawyer Call', 'Nominee Director Selection Advice', 'Capital & Tax Planning', 'Name Availability Check', 'Compliance Roadmap'],
            buttonText: 'Book OPC Consultation',
            isAdjustable: true
        },
        {
            id: 'basic',
            name: 'Basic OPC Package',
            price: 4999,
            description: 'Full incorporation with MCA SPICe+ filing.',
            features: ['Name Approval (RUN)', '1 DIN & 1 Class 3 DSC', 'MoA & AoA Drafting with Nominee Clause', 'SPICe+ Integration Filing', 'Certificate of Incorporation (COI)', 'PAN & TAN Issuance', 'MSME / Udyam Certificate'],
            buttonText: 'Select Basic'
        },
        {
            id: 'advance',
            name: 'Advance OPC Launch',
            price: 9999,
            description: 'Complete startup package with tax registration and business launch.',
            features: ['Everything in Basic', 'GST Registration', 'Auditor Appointment (ADT-1)', 'Commencement of Business (INC-20A)', 'Professional Business Website', 'Bank Current Account Kit', '1 Month Accounts Support'],
            buttonText: 'Select Advance',
            isPopular: true
        },
        {
            id: 'complete',
            name: 'Complete OPC Scale Suite',
            price: 14999,
            description: 'Full compliance suite with annual IT filings and web presence.',
            features: ['Everything in Advance', 'Import Export Code (IEC)', 'Individual & Corporate IT Filing Support', '6 Months GST Return Filing', '1 Yr Corporate Domain & Hosting', 'Dedicated Relationship Manager'],
            buttonText: 'Select Complete'
        }
    ],
    reviews: [
        {
            name: 'Gaurav Kulkarni',
            company: 'ByteCraft Technologies OPC Pvt Ltd',
            avatar: 'GK',
            rating: 5,
            date: '17 May 2026',
            text: 'As a solo software engineer, OPC gave me the exact corporate structure needed to sign contracts with US clients without needing a co-founder. Great job by VR Here!',
            verified: true
        },
        {
            name: 'Tarun Mehra',
            company: 'Verve Logistics OPC Pvt Ltd',
            avatar: 'TM',
            rating: 5,
            date: '30 April 2026',
            text: 'Incorporated my OPC in 6 days. The team helped with nominee director consent documentation seamlessly.',
            verified: true
        }
    ],
    steps: [
        { number: '01', title: 'Solo Consultation', desc: 'Select your trade name, nominee director, and book consultation for ₹499.', badge: '15 Mins' },
        { number: '02', title: 'DSC & Nominee Consent', desc: 'Obtain DSC for founder and prepare Form INC-3 Nominee Director Consent.', badge: 'Days 1-2' },
        { number: '03', title: 'SPICe+ Incorporation', desc: 'File integrated SPICe+ form with MCA covering DIN, PAN, TAN, EPFO, and ESIC.', badge: 'Days 3-5' },
        { number: '04', title: 'Certificate Delivery', desc: 'Receive your Certificate of Incorporation and master corporate kit in your dashboard.', badge: 'Days 6-7' }
    ],
    faqs: [
        { q: 'What is a One Person Company (OPC)?', a: 'An OPC is a company that can be formed with just 1 director and 1 shareholder (both can be the same person), giving solo entrepreneurs limited liability protection and corporate status.' },
        { q: 'Why is a Nominee Director required for an OPC?', a: 'Under the Companies Act 2013, the sole member must nominate a person in Form INC-3 who will become the member of the OPC in the event of death or incapacity of the original subscriber.' },
        { q: 'Can an NRI (Non-Resident Indian) incorporate an OPC in India?', a: 'Yes! As per recent MCA budget amendments, NRIs and foreign citizens of Indian origin are allowed to incorporate an OPC in India.' },
        { q: 'Can an OPC be converted to a Private Limited Company later?', a: 'Yes! An OPC can easily convert into a Private Limited Company by adding another director/shareholder as the business scales.' }
    ],
    guide: {
        title: 'Guide to One Person Company (OPC) Registration',
        overview: 'One Person Company (OPC) allows solo founders to operate a full-fledged corporate entity with limited liability, independent legal identity, and complete equity ownership.',
        sections: [
            {
                heading: 'Key Characteristics of OPC',
                content: '',
                bullets: [
                    'Single Member: Only 1 individual required as shareholder and director.',
                    'Limited Liability: Founder personal assets (home, car, savings) are 100% protected.',
                    'Separate Legal Entity: Can own assets, enter contracts, and incur debt in the company name.',
                    'Perpetual Existence: Uninterrupted existence ensured via designated Nominee Director.'
                ]
            },
            {
                heading: 'OPC vs Sole Proprietorship',
                content: '',
                bullets: [
                    'Liability: OPC has limited liability; Proprietorship has unlimited personal liability.',
                    'Legal Status: OPC is a recognized juristic person under Companies Act 2013; Proprietorship is not a separate legal entity.',
                    'Global Contracts: Multi-national enterprises prefer contracting with registered corporate entities.'
                ]
            }
        ],
        checklistTitle: 'Documents Checklist for OPC Registration',
        checklist: [
            'PAN Card and Aadhaar Card of Sole Director / Shareholder',
            'PAN Card and Aadhaar Card of Nominee Director',
            'Passport-size photographs of Director and Nominee',
            'Bank Statement / Utility Bill (within 2 months) of Director & Nominee',
            'Registered office electricity bill and Landlord NOC'
        ]
    },
    popularSearches: [
        'One Person Company Registration', 'OPC Registration Fees', 'OPC vs Sole Proprietorship',
        'OPC Nominee Director INC-3', 'Incorporate OPC India', 'Single Founder Startup Registration',
        'MCA SPICe+ OPC Filing', 'Cheapest OPC Registration'
    ],
    seoSettings: {
        titleTag: 'One Person Company (OPC) Registration Online in India | VR Here',
        metaDescription: 'Register your One Person Company (OPC) in 7 days. 100% online SPICe+ MCA filing, MoA/AoA with Nominee Director, DIN, DSC, PAN, TAN & Udyam certification.',
        focusKeywords: ['One Person Company', 'OPC Registration', 'Register OPC Online']
    }
};
