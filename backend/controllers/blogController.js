import Blog from '../models/Blog.js';
import asyncHandler from 'express-async-handler';

// @desc    Get all published blogs (Public)
// @route   GET /api/blogs
// @access  Public
export const getPublishedBlogs = asyncHandler(async (req, res) => {
    const { category, search } = req.query;
    let query = { isPublished: true };

    if (category && category !== 'All') {
        query.category = category;
    }

    if (search) {
        query.$or = [
            { title: { $regex: search, $options: 'i' } },
            { summary: { $regex: search, $options: 'i' } }
        ];
    }

    const blogs = await Blog.find(query).sort({ priority: -1, publishedAt: -1 });
    res.json(blogs);
});

// @desc    Get single blog by slug
// @route   GET /api/blogs/:slug
// @access  Public
export const getBlogBySlug = asyncHandler(async (req, res) => {
    const blog = await Blog.findOne({ slug: req.params.slug });
    if (!blog) {
        res.status(404);
        throw new Error('Blog article not found');
    }
    res.json(blog);
});

// @desc    Get all blogs for admin
// @route   GET /api/blogs/admin/all
// @access  Admin
export const getAllBlogsAdmin = asyncHandler(async (req, res) => {
    const blogs = await Blog.find({}).sort({ createdAt: -1 });
    res.json(blogs);
});

// @desc    Create new blog post
// @route   POST /api/blogs
// @access  Admin
export const createBlog = asyncHandler(async (req, res) => {
    const {
        title,
        slug,
        summary,
        category,
        categoryColor,
        readTime,
        coverImageUrl,
        keyTakeaways,
        fullArticle,
        isPublished,
        priority,
        author
    } = req.body;

    const generatedSlug = (slug || title)
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/(^-|-$)+/g, '');

    const existing = await Blog.findOne({ slug: generatedSlug });
    const finalSlug = existing ? `${generatedSlug}-${Date.now().toString().slice(-4)}` : generatedSlug;

    const blog = await Blog.create({
        title,
        slug: finalSlug,
        summary,
        category: category || 'Corporate & Legal',
        categoryColor: categoryColor || '#3B82F6',
        readTime: readTime || '4 min read',
        coverImageUrl: coverImageUrl || '',
        keyTakeaways: Array.isArray(keyTakeaways) ? keyTakeaways : [],
        fullArticle,
        isPublished: isPublished !== undefined ? isPublished : true,
        priority: Number(priority) || 0,
        author: author || 'VR HERE Editorial Board',
        publishedAt: new Date()
    });

    res.status(201).json(blog);
});

// @desc    Update blog post
// @route   PUT /api/blogs/:id
// @access  Admin
export const updateBlog = asyncHandler(async (req, res) => {
    const blog = await Blog.findById(req.params.id);
    if (!blog) {
        res.status(404);
        throw new Error('Blog article not found');
    }

    const fields = [
        'title', 'slug', 'summary', 'category', 'categoryColor',
        'readTime', 'coverImageUrl', 'keyTakeaways', 'fullArticle',
        'isPublished', 'priority', 'author'
    ];

    fields.forEach(field => {
        if (req.body[field] !== undefined) {
            blog[field] = req.body[field];
        }
    });

    const updatedBlog = await blog.save();
    res.json(updatedBlog);
});

// @desc    Delete blog post
// @route   DELETE /api/blogs/:id
// @access  Admin
export const deleteBlog = asyncHandler(async (req, res) => {
    const blog = await Blog.findById(req.params.id);
    if (!blog) {
        res.status(404);
        throw new Error('Blog article not found');
    }

    await Blog.findByIdAndDelete(req.params.id);
    res.json({ message: 'Blog article removed successfully' });
});
