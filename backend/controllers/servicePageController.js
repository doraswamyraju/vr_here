import asyncHandler from 'express-async-handler';
import ServicePageConfig from '../models/ServicePageConfig.js';
import City from '../models/City.js';
import { ALL_SERVICE_CONFIGS, privateLimitedConfig } from '../data/serviceConfigs/index.js';

// Helper to replace {city}, {state}, {landmark}, {pincode} tokens in page object
const replaceCityTokens = (obj, cityData) => {
    if (!obj || !cityData) return obj;
    let str = JSON.stringify(obj);
    str = str.replace(/\{city\}/gi, cityData.name || 'Online');
    str = str.replace(/\{state\}/gi, cityData.state || 'India');
    str = str.replace(/\{landmark\}/gi, cityData.landmark || cityData.name || '');
    str = str.replace(/\{pincode\}/gi, cityData.pincode || '');
    str = str.replace(/\{district\}/gi, cityData.district || cityData.name || '');
    return JSON.parse(str);
};

// Helper to clean {city} and {state} tokens when viewing primary generic page
const sanitizeCityTokens = (obj) => {
    if (!obj) return obj;
    let str = JSON.stringify(obj);
    str = str.replace(/in\s*\{city\},\s*\{state\}/gi, 'across India');
    str = str.replace(/in\s*\{city\}/gi, 'Online in India');
    str = str.replace(/\{city\},\s*\{state\}/gi, 'India');
    str = str.replace(/\{city\}/gi, 'Online');
    str = str.replace(/\{state\}/gi, 'India');
    str = str.replace(/\{landmark\}/gi, '');
    str = str.replace(/\{pincode\}/gi, '');
    str = str.replace(/\{district\}/gi, '');
    return JSON.parse(str);
};

// @desc    Get all service page configs
// @route   GET /api/service-pages
// @access  Public
const getAllServicePages = asyncHandler(async (req, res) => {
    // Clean up redundant duplicate test pages if found
    await ServicePageConfig.deleteMany({ pageId: { $in: ['custom-new', 'private-limited-registration'] } });
    
    // Seed default configs if missing
    for (const [key, config] of Object.entries(ALL_SERVICE_CONFIGS)) {
        if (!key.includes('-in-')) {
            const exists = await ServicePageConfig.findOne({ pageId: config.pageId });
            if (!exists) {
                await ServicePageConfig.create(config);
            }
        }
    }

    const pages = await ServicePageConfig.find({});
    const sanitizedPages = pages.map(p => sanitizeCityTokens(p.toObject ? p.toObject() : p));
    res.json(sanitizedPages);
});

// @desc    Get service page config by ID (supports base slugs and -in-:city slugs)
// @route   GET /api/service-pages/:pageId
// @access  Public
const getServicePageById = asyncHandler(async (req, res) => {
    const rawPageId = decodeURIComponent(req.params.pageId || '');
    const queryCity = req.query.city;

    const normalizeSlug = (s) => String(s || '').toLowerCase().replace(/\(.*?\)/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');

    let baseSlug = rawPageId;
    let citySlug = queryCity || null;

    if (!citySlug && rawPageId.includes('-in-')) {
        const parts = rawPageId.split('-in-');
        baseSlug = parts[0];
        citySlug = parts.slice(1).join('-in-');
    }

    const normKey = normalizeSlug(baseSlug);

    let page = await ServicePageConfig.findOne({ pageId: baseSlug });
    if (!page && normKey !== baseSlug) {
        page = await ServicePageConfig.findOne({ pageId: normKey });
    }
    if (!page) {
        page = await ServicePageConfig.findOne({ pageId: rawPageId });
    }

    let seedConfig = ALL_SERVICE_CONFIGS[baseSlug] || ALL_SERVICE_CONFIGS[normKey] || ALL_SERVICE_CONFIGS[rawPageId];
    if (!seedConfig) {
        const humanTitle = normKey.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
        seedConfig = {
            pageId: normKey,
            title: humanTitle,
            hero: {
                title: `${humanTitle} Online in {city}`,
                subtitle: `Fast, transparent, 100% online ${humanTitle} with dedicated CA/CS assistance across {city}, {state}.`,
                badgeText: 'GOVT & STATUTORY VERIFIED',
                consultationPrice: 499,
                inclusions: ['Dedicated CA/CS Specialist Assigned', 'Full Government Portal Drafting', 'Document Verification & Quality Audit', 'Official Certificate / Receipts Delivered', 'Lifetime Compliance Support']
            },
            stats: [
                { value: '3-5 Days', label: 'AVG. TURNAROUND' },
                { value: '100%', label: 'STATUTORY COMPLIANT' },
                { value: '4.9/5', label: 'CLIENT RATING' },
                { value: 'CA/CS', label: 'VERIFIED' }
            ],
            packages: [
                { id: `${normKey}-standard`, name: 'Standard Plan', price: 2999, isPopular: true, features: ['Document Review & Vetting', 'Online Portal Submission', 'Statutory Certificate / Return Filing', 'Dedicated Relationship Manager'] }
            ],
            reviews: [
                { name: 'Rajesh Kulkarni', company: 'Kulkarni Enterprises', avatar: 'RK', rating: 5, date: '12 June 2026', text: `VR Here handled our ${humanTitle} with supreme professionalism. Delivered on schedule with zero hassles.`, verified: true }
            ],
            steps: [
                { number: '01', title: 'KYC & Data Upload', desc: 'Securely submit required business details and identity documents.', badge: 'Step 1' },
                { number: '02', title: 'Legal Drafting', desc: 'Practicing Chartered Accountants draft and verify applications.', badge: 'Step 2' },
                { number: '03', title: 'Portal Filing', desc: 'Application filed on official central or state government portals.', badge: 'Step 3' },
                { number: '04', title: 'Certificate Delivery', desc: 'Official government certificate and filing receipt delivered digitally.', badge: 'Step 4' }
            ],
            whyChoose: {
                title: `Why Choose VR Here for ${humanTitle}?`,
                subtitle: `Get certified legal execution and end-to-end statutory assistance from senior chartered accountants.`,
                benefits: [
                    { t: '100% Online & Paperless', d: `Complete ${humanTitle} from anywhere in India.` },
                    { t: 'Verified CA/CS Oversight', d: 'Every document and application is verified by senior practitioners.' },
                    { t: 'Zero Penalty Guarantee', d: 'Timely filing ensuring complete statutory compliance and protection.' }
                ],
                requirements: [
                    'PAN Card of Business / Applicant',
                    'Aadhaar Card linked with active Mobile No.',
                    'Registered Address Proof (Electricity Bill / Rent Agreement)',
                    'Bank Account Statement / Cancelled Cheque'
                ]
            },
            guide: {
                title: `Guide to ${humanTitle}`,
                overview: `Professional ${humanTitle} ensures strict compliance with Indian statutory authorities while saving valuable business time.`,
                checklistTitle: 'Required Documents',
                checklist: ['PAN Card of Business / Applicant', 'Aadhaar Card linked with Mobile', 'Registered Address Proof', 'Bank Statement / Cancelled Cheque']
            },
            faqs: [
                { q: `How long does the ${humanTitle} process take?`, a: 'Standard turnaround is 3 to 5 business days subject to departmental approval queues.' },
                { q: 'Can I adjust the consultation fee against the final package?', a: 'Yes! If you book an expert CA/CS consultation at ₹499, the full ₹499 is credited and deducted when you upgrade to any full registration plan.' }
            ],
            popularSearches: [humanTitle, `${humanTitle} Online`, `${humanTitle} Fees in India`, `${humanTitle} Consultant`]
        };
    }

    // Auto-heal / overwrite if database record had mismatched "Private Limited" template
    const isPvtLtdSlug = normKey.includes('private-limited') || normKey.includes('pvt-ltd');
    const hasPvtLtdLeak = page && !isPvtLtdSlug && ((page.title && page.title.includes('Private Limited')) || (page.hero?.title && page.hero.title.includes('Private Limited')));

    if (!page || hasPvtLtdLeak) {
        if (page && hasPvtLtdLeak) {
            await ServicePageConfig.deleteOne({ _id: page._id });
        }
        page = await ServicePageConfig.create({ ...seedConfig, pageId: normKey });
    }

    let pageObj = page.toObject ? page.toObject() : page;

    // Apply defaults for any missing or mismatched fields
    if (!pageObj.stats || pageObj.stats.length === 0) pageObj.stats = seedConfig.stats;
    if (!pageObj.logos || pageObj.logos.length === 0) pageObj.logos = seedConfig.logos;
    if (!pageObj.packages || pageObj.packages.length === 0) pageObj.packages = seedConfig.packages;
    if (!pageObj.reviews || pageObj.reviews.length === 0 || (!isPvtLtdSlug && pageObj.reviews[0]?.text?.includes('Pvt Ltd'))) {
        pageObj.reviews = seedConfig.reviews;
    }
    if (!pageObj.steps || pageObj.steps.length === 0) pageObj.steps = seedConfig.steps;
    if (!pageObj.faqs || pageObj.faqs.length === 0) pageObj.faqs = seedConfig.faqs;
    if (!pageObj.whyChoose || (!isPvtLtdSlug && pageObj.whyChoose?.title?.includes('Private Limited'))) {
        pageObj.whyChoose = seedConfig.whyChoose;
    }
    if (!pageObj.guide || (!isPvtLtdSlug && pageObj.guide?.title?.includes('Company Registration'))) {
        pageObj.guide = seedConfig.guide;
    }
    if (!pageObj.heroGraphicItems || pageObj.heroGraphicItems.length === 0) {
        pageObj.heroGraphicItems = seedConfig.heroGraphicItems || seedConfig.hero?.inclusions;
    }
    if (!pageObj.popularSearches || pageObj.popularSearches.length === 0) {
        pageObj.popularSearches = seedConfig.popularSearches;
    }

    if (citySlug) {
        const cityData = await City.findOne({ slug: citySlug.toLowerCase(), isActive: true });
        if (cityData) {
            pageObj = replaceCityTokens(pageObj, cityData);
            pageObj.isCityVariant = true;
            pageObj.city = cityData.name;
            pageObj.state = cityData.state;
            pageObj.canonicalUrl = `https://vrhere.in/${baseSlug}-in-${cityData.slug}`;

            // Generate Schema.org JSON-LD structured data for Google SEO
            pageObj.schemaJsonLd = {
                "@context": "https://schema.org",
                "@graph": [
                    {
                        "@type": "LocalBusiness",
                        "name": `VR Here Business Management Solutions - ${cityData.name}`,
                        "description": pageObj.seoSettings?.metaDescription || pageObj.description,
                        "address": {
                            "@type": "PostalAddress",
                            "streetAddress": cityData.landmark || "VR Here Branch Office",
                            "addressLocality": cityData.name,
                            "addressRegion": cityData.state,
                            "postalCode": cityData.pincode,
                            "addressCountry": "IN"
                        },
                        "url": pageObj.canonicalUrl
                    },
                    {
                        "@type": "Service",
                        "name": pageObj.title,
                        "provider": {
                            "@type": "LocalBusiness",
                            "name": `VR Here ${cityData.name}`
                        },
                        "areaServed": cityData.name
                    }
                ]
            };
        } else {
            pageObj = sanitizeCityTokens(pageObj);
        }
    } else {
        pageObj = sanitizeCityTokens(pageObj);
    }

    res.json(pageObj);
});

// @desc    Create or update service page config
// @route   POST /api/service-pages/:pageId
// @access  Private (Admin & Employee)
const updateServicePage = asyncHandler(async (req, res) => {
    const { pageId } = req.params;
    const updateData = req.body;
    updateData.pageId = pageId;

    if (!updateData.gscTokens) {
        delete updateData.gscTokens;
    }

    const page = await ServicePageConfig.findOneAndUpdate(
        { pageId },
        { $set: updateData },
        { new: true, upsert: true, runValidators: true }
    );

    res.json({ message: 'Service page saved successfully', page });
});

// @desc    Delete a service page config
// @route   DELETE /api/service-pages/:pageId
// @access  Private (Admin & Employee)
const deleteServicePage = asyncHandler(async (req, res) => {
    const { pageId } = req.params;
    const page = await ServicePageConfig.findOne({ pageId });

    if (!page) {
        res.status(404);
        throw new Error('Service page not found');
    }

    await page.deleteOne();
    res.json({ message: 'Service page deleted successfully' });
});

export {
    getAllServicePages,
    getServicePageById,
    updateServicePage,
    deleteServicePage
};
