import express from 'express';
import { createTodo, getTodos, updateTodo, deleteTodo } from '../controllers/todoController.js';
import { protect, admin } from '../middleware/authMiddleware.js';

const router = express.Router();

router.route('/')
    .post(protect, admin, createTodo)
    .get(protect, getTodos);

router.route('/:id')
    .put(protect, updateTodo)
    .delete(protect, admin, deleteTodo);

export default router;
