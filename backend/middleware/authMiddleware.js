import jwt from 'jsonwebtoken';
import asyncHandler from 'express-async-handler';
import User from '../models/User.js';

const attachUserFromToken = async (req) => {
    if (
        req.headers.authorization &&
        req.headers.authorization.startsWith('Bearer')
    ) {
        const token = req.headers.authorization.split(' ')[1];
        const secret = process.env.JWT_SECRET || 'secret';
        const decoded = jwt.verify(token, secret);
        req.user = await User.findById(decoded.id).select('-password');
        return token;
    }

    return null;
};

const protect = asyncHandler(async (req, res, next) => {
    try {
        const token = await attachUserFromToken(req);

        if (!token || !req.user) {
            res.status(401);
            throw new Error('Not authorized, no token');
        }

        if (req.user.isActive === false) {
            res.status(403);
            throw new Error('User account is inactive');
        }

        next();
    } catch (error) {
        console.error(error);
        res.status(401);
        throw new Error('Not authorized, token failed');
    }
});

const protectOptional = asyncHandler(async (req, res, next) => {
    try {
        await attachUserFromToken(req);
    } catch (error) {
        req.user = null;
    }

    next();
});

const admin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(401);
        throw new Error('Not authorized as an admin');
    }
};

const staff = (req, res, next) => {
    if (req.user && (req.user.role === 'admin' || req.user.role === 'employee')) {
        next();
    } else {
        res.status(403);
        throw new Error('Not authorized as staff member');
    }
};

const canManageCompliance = (req, res, next) => {
    if (req.user && (req.user.role === 'admin' || req.user.canManageCompliance === true)) {
        next();
    } else {
        res.status(403);
        throw new Error('Not authorized to manage compliance records');
    }
};

export { protect, protectOptional, admin, staff, canManageCompliance };


