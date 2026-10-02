import mongoose from 'mongoose';

const blogSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    slug: { type: String, required: true, unique: true, lowercase: true, trim: true },
    summary: { type: String, required: true },
    category: { 
        type: String, 
        required: true, 
        default: 'Corporate & Legal'
    },
    categoryColor: { type: String, default: '#3B82F6' },
    readTime: { type: String, default: '4 min read' },
    coverImageUrl: { type: String, default: '' },
    keyTakeaways: [{ type: String }],
    fullArticle: { type: String, required: true },
    isPublished: { type: Boolean, default: true },
    priority: { type: Number, default: 0 },
    author: { type: String, default: 'VR HERE Editorial Board' },
    publishedAt: { type: Date, default: Date.now }
}, { timestamps: true });

export default mongoose.model('Blog', blogSchema);
