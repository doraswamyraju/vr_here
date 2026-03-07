import asyncHandler from 'express-async-handler';
import ServiceMenuConfig from '../models/ServiceMenuConfig.js';

const MENU_KEY = 'header-main-menu';

const sanitizeServicesPayload = (services = []) =>
    services.map((service, idx) => ({
        id: String(service.id || `service-${idx + 1}`).trim(),
        title: String(service.title || '').trim(),
        iconKey: String(service.iconKey || 'Briefcase').trim(),
        items: Array.isArray(service.items)
            ? service.items.map((item) => String(item).trim()).filter(Boolean)
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

const getOrCreateConfig = async () => {
    let config = await ServiceMenuConfig.findOne({ key: MENU_KEY });
    if (!config) {
        config = await ServiceMenuConfig.create({ key: MENU_KEY });
    }
    return config;
};

const getHeaderMenuConfig = asyncHandler(async (req, res) => {
    const config = await getOrCreateConfig();
    res.json(config);
});

const updateHeaderMenuConfig = asyncHandler(async (req, res) => {
    const { services } = req.body;

    if (!Array.isArray(services) || services.length === 0) {
        res.status(400);
        throw new Error('Services payload is required');
    }

    const cleanServices = sanitizeServicesPayload(services);
    if (cleanServices.length === 0) {
        res.status(400);
        throw new Error('At least one valid service is required');
    }

    const config = await getOrCreateConfig();
    config.services = cleanServices;
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
