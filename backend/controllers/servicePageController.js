import asyncHandler from 'express-async-handler';
import ServicePageConfig from '../models/ServicePageConfig.js';

// @desc    Get all service page configs
// @route   GET /api/service-pages
// @access  Public
const getAllServicePages = asyncHandler(async (req, res) => {
    const pages = await ServicePageConfig.find({});
    res.json(pages);
});

// @desc    Get service page config by ID
// @route   GET /api/service-pages/:pageId
// @access  Public
const getServicePageById = asyncHandler(async (req, res) => {
    const { pageId } = req.params;
    let page = await ServicePageConfig.findOne({ pageId });

    if (!page) {
        // Fallback default configurations for the main pages if they are requested but not in DB yet
        const defaultConfigs = {
            'private-limited': {
                pageId: 'private-limited',
                title: 'Private Limited Registration',
                description: 'Launch your startup with the most credible legal structure. Get Certificate of Incorporation, MOA, AOA, PAN & TAN in 7 days.',
                iconKey: 'Apartment',
                hero: {
                    title: 'Register Your Private Limited Company Online',
                    subtitle: 'Launch your startup with the most credible legal structure. Get Certificate of Incorporation, PAN, TAN & MOA/AOA in just 7 days.',
                    badgeText: 'India\'s #1 Secure Registration Platform',
                    consultationPrice: 499
                },
                stats: [
                    { value: '7 Days', label: 'Avg. Turnaround' },
                    { value: '5000+', label: 'Happy Founders' },
                    { value: '4.9/5', label: 'Google Rating' },
                    { value: '100%', label: 'Online Process' }
                ],
                logos: [
                    { name: 'Stripe for Startups', iconKey: 'SuiteIcon', colorClass: 'text-indigo-600' },
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
                    {
                        number: '01',
                        title: '1-Tap Expert Consultation',
                        desc: 'Book a consultation for just ₹499. Our CAs and CS specialists analyze your business idea, recommend the ideal package, and check name availability.',
                        badge: 'Takes 15 Mins'
                    },
                    {
                        number: '02',
                        title: 'Secure Document Vault Upload',
                        desc: 'Upload basic KYC details (Aadhaar, PAN, and address proof) to our secure vault. Your information is protected by industry-leading security.',
                        badge: 'Takes 10 Mins'
                    },
                    {
                        number: '03',
                        title: 'Government Filing & Incorporation',
                        desc: 'We file the RUN name approval, SPICe+ incorporation forms, PAN/TAN, and MSME registrations. You receive the Certificate of Incorporation by email!',
                        badge: 'Delivered in 7 Days'
                    }
                ],
                faqs: [
                    {
                        q: 'How much time does it take to register a Private Limited Company?',
                        a: 'On average, the entire process takes about 5 to 7 working days, subject to state-wise government processing times. This includes obtaining DSC, DIN, name approval, and the final Certificate of Incorporation (COI).'
                    },
                    {
                        q: 'Is the ₹499 consultation fee really refundable?',
                        a: 'Yes, 100%! When you book a CA/CS consultation for ₹499, the full amount is converted into a coupon credit. Once you proceed to purchase any of our packages (Basic, Advance, or Expert), the ₹499 is automatically deducted from your final package price.'
                    },
                    {
                        q: 'What are the minimum requirements to register a Pvt Ltd company?',
                        a: 'You need a minimum of 2 directors (who can also be the shareholders), at least one of whom must be an Indian resident, and a registered address in India (which can be a residential or rented address).'
                    },
                    {
                        q: 'Do I need a commercial office address to register my business?',
                        a: 'No. The MCA allows you to register your company using a residential address. You only need to provide a recent utility bill (electricity/gas bill) and a No Objection Certificate (NOC) from the owner.'
                    }
                ],
                seoSettings: {
                    titleTag: 'Register Private Limited Company Online in India | VR Here',
                    metaDescription: 'Launch your startup legally with Pvt Ltd company registration in 7 Days. Get expert CA/CS guidance, MOA/AOA, DIN, DSC, PAN, TAN & Udyam certification.',
                    focusKeywords: ['Private Limited Company', 'Company Registration', 'Pvt Ltd Online']
                }
            }
        };

        if (defaultConfigs[pageId]) {
            // Seed dynamic document on first request so it's fully editable thereafter
            page = await ServicePageConfig.create(defaultConfigs[pageId]);
        } else {
            // Return empty shell for totally new custom pages
            page = await ServicePageConfig.create({
                pageId,
                title: pageId.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' '),
                description: `Dynamic compliance and setup services for ${pageId}.`,
                packages: [],
                faqs: [],
                reviews: [],
                steps: []
            });
        }
    }

    res.json(page);
});

// @desc    Create or update service page config
// @route   POST /api/service-pages/:pageId
// @access  Private (Admin & Employee)
const updateServicePage = asyncHandler(async (req, res) => {
    const { pageId } = req.params;
    const updateData = req.body;

    let page = await ServicePageConfig.findOne({ pageId });

    if (page) {
        // Exclude specific token credentials if not explicitly modified
        if (!updateData.gscTokens) {
            delete updateData.gscTokens;
        }
        page = await ServicePageConfig.findOneAndUpdate(
            { pageId },
            { $set: updateData },
            { new: true, runValidators: true }
        );
        res.json({ message: 'Service page updated successfully', page });
    } else {
        updateData.pageId = pageId;
        page = await ServicePageConfig.create(updateData);
        res.status(201).json({ message: 'Service page created successfully', page });
    }
});

export {
    getAllServicePages,
    getServicePageById,
    updateServicePage
};
