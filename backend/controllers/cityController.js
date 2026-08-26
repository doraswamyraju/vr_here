import asyncHandler from 'express-async-handler';
import City from '../models/City.js';

// @desc    Get all active cities (or all cities for admin)
// @route   GET /api/cities
// @access  Public
const getAllCities = asyncHandler(async (req, res) => {
    const filter = req.query.all === 'true' ? {} : { isActive: true };
    const cities = await City.find(filter).sort({ name: 1 });
    res.json(cities);
});

// @desc    Get single city by slug or ID
// @route   GET /api/cities/:identifier
// @access  Public
const getCityByIdentifier = asyncHandler(async (req, res) => {
    const { identifier } = req.params;
    const city = await City.findOne({
        $or: [{ slug: identifier.toLowerCase() }, { _id: identifier }]
    });

    if (!city) {
        res.status(404);
        throw new Error('City not found');
    }

    res.json(city);
});

// @desc    Create a new city
// @route   POST /api/cities
// @access  Private (Admin / Employee)
const createCity = asyncHandler(async (req, res) => {
    const { name, slug, state, district, landmark, pincode, phone, isActive } = req.body;

    if (!name || !state) {
        res.status(400);
        throw new Error('City name and state are required');
    }

    const generatedSlug = (slug || name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');

    const existingCity = await City.findOne({ slug: generatedSlug });
    if (existingCity) {
        res.status(400);
        throw new Error('A city with this slug already exists');
    }

    const city = await City.create({
        name,
        slug: generatedSlug,
        state,
        district: district || name,
        landmark: landmark || '',
        pincode: pincode || '',
        phone: phone || '',
        isActive: isActive !== undefined ? isActive : true
    });

    res.status(201).json({ message: 'City created successfully', city });
});

// @desc    Update a city
// @route   PUT /api/cities/:id
// @access  Private (Admin / Employee)
const updateCity = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const city = await City.findById(id);

    if (!city) {
        res.status(404);
        throw new Error('City not found');
    }

    if (req.body.name && !req.body.slug) {
        req.body.slug = req.body.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
    }

    const updatedCity = await City.findByIdAndUpdate(
        id,
        { $set: req.body },
        { new: true, runValidators: true }
    );

    res.json({ message: 'City updated successfully', city: updatedCity });
});

// @desc    Delete a city
// @route   DELETE /api/cities/:id
// @access  Private (Admin / Employee)
const deleteCity = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const city = await City.findById(id);

    if (!city) {
        res.status(404);
        throw new Error('City not found');
    }

    await city.deleteOne();
    res.json({ message: 'City deleted successfully' });
});

export {
    getAllCities,
    getCityByIdentifier,
    createCity,
    updateCity,
    deleteCity
};
