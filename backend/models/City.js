import mongoose from 'mongoose';

const citySchema = new mongoose.Schema(
    {
        name: { type: String, required: true, trim: true },
        slug: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
        state: { type: String, required: true, trim: true },
        district: { type: String, default: '', trim: true },
        landmark: { type: String, default: '', trim: true },
        pincode: { type: String, default: '', trim: true },
        phone: { type: String, default: '', trim: true },
        isActive: { type: Boolean, default: true }
    },
    { timestamps: true }
);

const City = mongoose.model('City', citySchema);

export default City;
