import express from 'express';
import {
    getPublishedBlogs,
    getBlogBySlug,
    getAllBlogsAdmin,
    createBlog,
    updateBlog,
    deleteBlog
} from '../controllers/blogController.js';
import { protect, admin } from '../middleware/authMiddleware.js';

const router = express.Router();

// Public routes
router.get('/', getPublishedBlogs);
router.get('/:slug', getBlogBySlug);

// Admin routes
router.get('/admin/all', protect, admin, getAllBlogsAdmin);
router.post('/', protect, admin, createBlog);
router.put('/:id', protect, admin, updateBlog);
router.delete('/:id', protect, admin, deleteBlog);

export default router;
