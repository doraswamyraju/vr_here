import asyncHandler from 'express-async-handler';
import ServiceMenuConfig from '../models/ServiceMenuConfig.js';

const MENU_KEY = 'header-main-menu';
const EXPECTED_CATEGORY_IDS = [
    'accounting-compliance-taxation',
    'certification-quality-management',
    'business-registration-licensing-corporate',
    'government-portal-registrations',
    'industrial-msme-consultancy',
    'branding-documentation-startup-support',
    'machinery-industrial-support',
];

const sanitizeServicesPayload = (services = []) =>
    services.map((service, idx) => ({
        id: String(service.id || `service-${idx + 1}`).trim(),
        title: String(service.title || '').trim(),
        iconKey: String(service.iconKey || 'Briefcase').trim(),
        columns: Array.isArray(service.columns)
            ? service.columns
                .map((column) => ({
                    title: String(column.title || '').trim(),
                    items: Array.isArray(column.items)
                        ? column.items.map((item) => String(item).trim()).filter(Boolean)
                        : [],
                }))
                .filter((column) => column.title && column.items.length > 0)
            : Array.isArray(service.items)
                ? [{
                    title: 'Services',
                    items: service.items.map((item) => String(item).trim()).filter(Boolean),
                }]
            : [],
        offers: Array.isArray(service.offers)
            ? service.offers
                .map((offer) => ({
                    title: String(offer.title || '').trim(),
                    imageUrl: String(offer.imageUrl || '').trim(),
                    ctaLink: String(offer.ctaLink || '/contact').trim(),
                }))
                .filter((offer) => offer.title && offer.imageUrl)
            : [],
    })).filter((service) => service.title);

const sanitizeTickerMessages = (messages = []) =>
    Array.isArray(messages)
        ? messages.map((msg) => String(msg || '').trim()).filter(Boolean)
        : [];

const sanitizeCapsulesPayload = (capsules = []) =>
    Array.isArray(capsules)
        ? capsules.map((capsule) => ({
            text: String(capsule.text || '').trim(),
            link: String(capsule.link || '').trim(),
        })).filter((c) => c.text && c.link)
        : [];

const getOrCreateConfig = async () => {
    let config = await ServiceMenuConfig.findOne({ key: MENU_KEY });
    if (!config) {
        config = await ServiceMenuConfig.create({ key: MENU_KEY });
        return config;
    }

    const hasColumnShape = (config.services || []).some(
        (service) => Array.isArray(service.columns) && service.columns.length > 0
    );
    const hasLatestCategorySet = EXPECTED_CATEGORY_IDS.every((id) =>
        (config.services || []).some((service) => service.id === id)
    );

    let needsSave = false;

    if (!hasColumnShape || !hasLatestCategorySet) {
        const defaultsDoc = new ServiceMenuConfig();
        config.services = defaultsDoc.services;
        config.tickerMessages = defaultsDoc.tickerMessages;
        needsSave = true;
    }

    if (!config.capsules || config.capsules.length === 0) {
        const defaultsDoc = new ServiceMenuConfig();
        config.capsules = defaultsDoc.capsules;
        needsSave = true;
    }

    if (needsSave) {
        await config.save();
    }

    return config;
};

const getHeaderMenuConfig = asyncHandler(async (req, res) => {
    const config = await getOrCreateConfig();
    res.json(config);
});

const updateHeaderMenuConfig = asyncHandler(async (req, res) => {
    const { services, tickerMessages, capsules } = req.body;

    if (!Array.isArray(services) || services.length === 0) {
        res.status(400);
        throw new Error('Services payload is required');
    }

    const cleanServices = sanitizeServicesPayload(services);
    if (cleanServices.length === 0) {
        res.status(400);
        throw new Error('At least one valid service is required');
    }

    if (capsules !== undefined) {
        if (!Array.isArray(capsules)) {
            res.status(400);
            throw new Error('Capsules payload must be an array');
        }
        if (capsules.length > 10) {
            res.status(400);
            throw new Error('Maximum of 10 capsules are allowed');
        }
    }

    const config = await getOrCreateConfig();
    config.services = cleanServices;
    if (tickerMessages !== undefined) {
        config.tickerMessages = sanitizeTickerMessages(tickerMessages);
    }
    if (capsules !== undefined) {
        config.capsules = sanitizeCapsulesPayload(capsules);
    }
    const updated = await config.save();

    res.json(updated);
});

const uploadServiceOfferImage = asyncHandler(async (req, res) => {
    const { serviceId, offerId } = req.params;

    if (!req.file) {
        res.status(400);
        throw new Error('Image file is required');
    }

    if (!req.file.mimetype?.startsWith('image/')) {
        res.status(400);
        throw new Error('Only image uploads are allowed for offers');
    }

    const config = await getOrCreateConfig();
    const service = config.services.find((s) => s.id === serviceId);
    if (!service) {
        res.status(404);
        throw new Error('Service not found');
    }

    const offer = service.offers.id(offerId);
    if (!offer) {
        res.status(404);
        throw new Error('Offer not found');
    }

    offer.imageUrl = `/uploads/${req.file.filename}`;
    await config.save();

    res.json({
        message: 'Offer image uploaded',
        imageUrl: offer.imageUrl,
    });
});

export {
    getHeaderMenuConfig,
    updateHeaderMenuConfig,
    uploadServiceOfferImage,
};
