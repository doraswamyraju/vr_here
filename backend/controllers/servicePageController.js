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
    const { pageId } = req.params;
    const queryCity = req.query.city;

    let baseSlug = pageId;
    let citySlug = queryCity || null;

    if (!citySlug && pageId.includes('-in-')) {
        const parts = pageId.split('-in-');
        baseSlug = parts[0];
        citySlug = parts.slice(1).join('-in-');
    }

    let page = await ServicePageConfig.findOne({ pageId: baseSlug });
    if (!page) {
        page = await ServicePageConfig.findOne({ pageId });
    }

    const seedConfig = ALL_SERVICE_CONFIGS[baseSlug] || ALL_SERVICE_CONFIGS[pageId] || privateLimitedConfig;

    if (!page) {
        page = await ServicePageConfig.create({ ...seedConfig, pageId: baseSlug || pageId });
    }

    let pageObj = page.toObject ? page.toObject() : page;

    // Apply defaults for any missing fields
    if (!pageObj.stats || pageObj.stats.length === 0) {
        pageObj.stats = seedConfig.stats;
    }
    if (!pageObj.logos || pageObj.logos.length === 0) {
        pageObj.logos = seedConfig.logos;
    }
    if (!pageObj.packages || pageObj.packages.length === 0) {
        pageObj.packages = seedConfig.packages;
    }
    if (!pageObj.reviews || pageObj.reviews.length === 0) {
        pageObj.reviews = seedConfig.reviews;
    }
    if (!pageObj.steps || pageObj.steps.length === 0) {
        pageObj.steps = seedConfig.steps;
    }
    if (!pageObj.faqs || pageObj.faqs.length === 0) {
        pageObj.faqs = seedConfig.faqs;
    }
    if (!pageObj.guide || !pageObj.guide.sections || pageObj.guide.sections.length === 0) {
        pageObj.guide = seedConfig.guide;
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
