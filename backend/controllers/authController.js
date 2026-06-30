import asyncHandler from 'express-async-handler';
import { randomBytes, createHash } from 'crypto';
import generateToken from '../utils/generateToken.js';
import User from '../models/User.js';
import sendEmail from '../utils/sendEmail.js';
import { generateFirebaseToken } from '../services/firebaseService.js';

const buildResetUrl = (token) => {
    const baseUrl = process.env.FRONTEND_URL || 'https://vrhere.in';
    return `${baseUrl.replace(/\/$/, '')}/reset-password/${token}`;
};

const issueResetToken = async (user, expiryMs = 24 * 60 * 60 * 1000) => {
    const resetToken = randomBytes(20).toString('hex');
    user.resetPasswordToken = createHash('sha256').update(resetToken).digest('hex');
    user.resetPasswordExpire = Date.now() + expiryMs;
    await user.save();
    return resetToken;
};

const sendPasswordSetupEmail = async (user, token, subject = 'Set Your VR HERE Password') => {
    const resetUrl = buildResetUrl(token);
    const message = `
        <h2>Welcome ${user.name}</h2>
        <p>Your account is ready. Click below to set your password and start using the dashboard.</p>
        <p><a href="${resetUrl}" clicktracking="off">Set Password</a></p>
        <p>If the button does not work, copy this URL:</p>
        <p>${resetUrl}</p>
        <p>This link will expire soon for security.</p>
    `;

    await sendEmail({
        email: user.email,
        subject,
        message
    });
};

// @desc    Auth user & get token
// @route   POST /api/auth/login
// @access  Public
const authUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user || !(await user.matchPassword(password))) {
        res.status(401);
        throw new Error('Invalid email or password');
    }

    if (!user.isActive) {
        res.status(403);
        const message = user.role === 'partner' 
            ? 'Your partner account is pending validation. Please wait for admin approval.' 
            : 'User account is inactive. Contact admin.';
        throw new Error(message);
    }

    const firebaseCustomToken = await generateFirebaseToken(user._id);

    res.json({
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isActive: user.isActive,
        isClockedIn: user.isClockedIn || false,
        activeOrderId: user.activeOrderId || null,
        token: generateToken(user._id),
        firebaseCustomToken
    });
});

// @desc    Register a new user
// @route   POST /api/auth/register
// @access  Public
const registerUser = asyncHandler(async (req, res) => {
    const { name, email, password, phone, role } = req.body;

    const userExists = await User.findOne({ email });

    if (userExists) {
        res.status(400);
        throw new Error('User already exists');
    }

    const user = await User.create({
        name,
        email,
        password,
        phone,
        role: role || 'client',
        isActive: true
    });

    if (user) {
        try {
            await sendEmail({
                email: user.email,
                subject: 'Welcome to VR HERE Business Solutions',
                message: `<h1>Welcome ${user.name}!</h1><p>Thank you for registering with VR HERE.</p>`
            });
        } catch (error) {
            console.error('Email send failure:', error);
        }

        const firebaseCustomToken = await generateFirebaseToken(user._id);

        res.status(201).json({
            _id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            isActive: user.isActive,
            token: generateToken(user._id),
            firebaseCustomToken
        });
    } else {
        res.status(400);
        throw new Error('Invalid user data');
    }
});

// @desc    Register a new referral partner
// @route   POST /api/auth/register-partner
// @access  Public
const registerPartner = asyncHandler(async (req, res) => {
    const { name, email, password, phone, panCard } = req.body;

    if (!name || !email || !password || !phone || !panCard) {
        res.status(400);
        throw new Error('Name, Email, Password, Phone, and PAN Card are strictly required for partners.');
    }

    const emailExists = await User.findOne({ email });
    if (emailExists) {
        res.status(400);
        throw new Error('Email already registered');
    }

    const phoneExists = await User.findOne({ phone, role: 'partner' });
    if (phoneExists) {
        res.status(400);
        throw new Error('This phone number is already registered as a partner');
    }

    const panExists = await User.findOne({ panCard, role: 'partner' });
    if (panExists) {
        res.status(400);
        throw new Error('This PAN Card is already registered to a partner');
    }

    const user = await User.create({
        name,
        email,
        password,
        phone,
        panCard,
        role: 'partner',
        isActive: false, // Changed to false for validation workflow
        commissionPercentage: 10
    });

    if (user) {
        try {
            await sendEmail({
                email: user.email,
                subject: 'VR HERE Partner Program Registration - Pending Validation',
                message: `
                    <h1>Welcome ${user.name}!</h1>
                    <p>Thank you for joining our Referral Partner Program.</p>
                    <p><b>Status: Pending Validation</b></p>
                    <p>Our team is currently reviewing your application and KYC details. You will receive another notification once your account is activated.</p>
                    <p>In the meantime, you can log in to your dashboard to complete your bank details, but your referral code (<b>${user.phone}</b>) will only be active after validation.</p>
                `
            });
        } catch (error) {
            console.error('Email send failure:', error);
        }

        const firebaseCustomToken = await generateFirebaseToken(user._id);

        res.status(201).json({
            _id: user._id,
            name: user.name,
            email: user.email,
            phone: user.phone,
            role: user.role,
            isActive: user.isActive,
            token: generateToken(user._id),
            firebaseCustomToken
        });
    } else {
        res.status(400);
        throw new Error('Invalid partner data');
    }
});

// @desc    Forgot Password
// @route   POST /api/auth/forgotpassword
// @access  Public
const forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
        res.status(404);
        throw new Error('User not found');
    }

    const resetToken = await issueResetToken(user, 10 * 60 * 1000);

    try {
        await sendPasswordSetupEmail(user, resetToken, 'Password Reset Request');
        res.status(200).json({ success: true, data: 'Email sent' });
    } catch (error) {
        console.error(error);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;
        await user.save();
        res.status(500);
        throw new Error('Email could not be sent');
    }
});

// @desc    Reset Password
// @route   PUT /api/auth/resetpassword/:resetToken
// @access  Public
const resetPassword = asyncHandler(async (req, res) => {
    const resetPasswordToken = createHash('sha256')
        .update(req.params.resetToken)
        .digest('hex');

    const user = await User.findOne({
        resetPasswordToken,
        resetPasswordExpire: { $gt: Date.now() }
    });

    if (!user) {
        res.status(400);
        throw new Error('Invalid token');
    }

    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    user.isActive = true;

    await user.save();

    const firebaseCustomToken = await generateFirebaseToken(user._id);

    res.status(201).json({
        success: true,
        data: 'Password reset success',
        token: generateToken(user._id),
        firebaseCustomToken
    });
});

// @desc    Get user profile
// @route   GET /api/auth/profile
// @access  Private
const getUserProfile = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        const firebaseCustomToken = await generateFirebaseToken(user._id);

        res.json({
            _id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            isActive: user.isActive,
            isClockedIn: user.isClockedIn || false,
            activeOrderId: user.activeOrderId || null,
            skills: user.skills,
            yearsOfExperience: user.yearsOfExperience,
            resumeUrl: user.resumeUrl,
            panCard: user.panCard,
            bankDetails: user.bankDetails,
            pendingProfileUpdate: user.pendingProfileUpdate,
            firebaseCustomToken
        });
    } else {
        res.status(404);
        throw new Error('User not found');
    }
});

// @desc    Update FCM Token for user
// @route   PUT /api/auth/fcm-token
// @access  Private
const updateFcmToken = asyncHandler(async (req, res) => {
    const { fcmToken } = req.body;
    const user = await User.findById(req.user._id);

    if (user) {
        user.fcmToken = fcmToken || null;
        await user.save();
        res.json({ success: true, message: 'FCM token updated successfully' });
    } else {
        res.status(404);
        throw new Error('User not found');
    }
});

// @desc    Get all employees
// @route   GET /api/auth/employees
// @access  Private/Admin
const getEmployees = asyncHandler(async (req, res) => {
    const includeInactive = String(req.query.includeInactive || 'false').toLowerCase() === 'true';
    const query = includeInactive ? { role: 'employee' } : { role: 'employee', isActive: true };
    const employees = await User.find(query).select('-password').sort({ createdAt: -1 });
    res.json(employees);
});

// @desc    Get all users
// @route   GET /api/auth/users
// @access  Private/Admin
const getUsers = asyncHandler(async (req, res) => {
    const { role = '', active = '' } = req.query;
    const query = {};

    if (role) query.role = role;
    if (active) query.isActive = String(active).toLowerCase() === 'true';

    const users = await User.find(query).select('-password').sort({ createdAt: -1 });
    res.json(users);
});

// @desc    Admin creates user and triggers set-password email
// @route   POST /api/auth/users
// @access  Private/Admin
const createUserByAdmin = asyncHandler(async (req, res) => {
    const { name, email, phone = '', role = 'employee' } = req.body;

    if (!name || !email) {
        res.status(400);
        throw new Error('Name and email are required');
    }

    const existing = await User.findOne({ email });
    if (existing) {
        res.status(400);
        throw new Error('User with this email already exists');
    }

    const tempPassword = randomBytes(12).toString('hex');

    const user = await User.create({
        name,
        email,
        phone,
        role,
        password: tempPassword,
        isActive: true
    });

    const resetToken = await issueResetToken(user, 24 * 60 * 60 * 1000);
    await sendPasswordSetupEmail(user, resetToken, 'Set Your VR HERE Password');

    res.status(201).json({
        message: 'User created and password setup email sent',
        user: {
            _id: user._id,
            name: user.name,
            email: user.email,
            phone: user.phone,
            role: user.role,
            isActive: user.isActive,
            createdAt: user.createdAt
        }
    });
});

// @desc    Update user details
// @route   PUT /api/auth/users/:id
// @access  Private/Admin
const updateUserByAdmin = asyncHandler(async (req, res) => {
    const { name, email, phone, role, isActive, commissionPercentage, panCard } = req.body;
    const user = await User.findById(req.params.id);

    if (!user) {
        res.status(404);
        throw new Error('User not found');
    }

    if (name !== undefined) user.name = name;
    if (email !== undefined) user.email = email;
    if (phone !== undefined) user.phone = phone;
    if (role !== undefined) user.role = role;
    if (isActive !== undefined) user.isActive = Boolean(isActive);
    if (commissionPercentage !== undefined) user.commissionPercentage = Number(commissionPercentage);
    if (panCard !== undefined) user.panCard = panCard;

    await user.save();

    res.json({
        message: 'User updated',
        user: {
            _id: user._id,
            name: user.name,
            email: user.email,
            phone: user.phone,
            role: user.role,
            isActive: user.isActive,
            commissionPercentage: user.commissionPercentage,
            panCard: user.panCard,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
        }
    });
});

// @desc    Toggle user active status
// @route   PATCH /api/auth/users/:id/toggle-active
// @access  Private/Admin
const toggleUserActiveByAdmin = asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id);

    if (!user) {
        res.status(404);
        throw new Error('User not found');
    }

    if (user.role === 'admin' && user._id.toString() === req.user._id.toString()) {
        res.status(400);
        throw new Error('You cannot deactivate your own admin account');
    }

    user.isActive = !user.isActive;
    await user.save();

    res.json({
        message: `User ${user.isActive ? 'activated' : 'deactivated'}`,
        user: {
            _id: user._id,
            isActive: user.isActive
        }
    });
});

// @desc    Resend set-password email
// @route   POST /api/auth/users/:id/send-password-link
// @access  Private/Admin
const sendPasswordLinkByAdmin = asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id);

    if (!user) {
        res.status(404);
        throw new Error('User not found');
    }

    const resetToken = await issueResetToken(user, 24 * 60 * 60 * 1000);
    await sendPasswordSetupEmail(user, resetToken, 'Set or Reset Your VR HERE Password');

    res.json({ message: 'Password setup email sent' });
});

// @desc    Delete user
// @route   DELETE /api/auth/users/:id
// @access  Private/Admin
const deleteUserByAdmin = asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id);

    if (!user) {
        res.status(404);
        throw new Error('User not found');
    }

    if (user.role === 'admin' && user._id.toString() === req.user._id.toString()) {
        res.status(400);
        throw new Error('You cannot delete your own admin account');
    }

    await User.deleteOne({ _id: req.params.id });

    res.json({ message: 'User removed' });
});

export {
    authUser,
    registerUser,
    registerPartner,
    forgotPassword,
    resetPassword,
    getUserProfile,
    getEmployees,
    getUsers,
    createUserByAdmin,
    updateUserByAdmin,
    toggleUserActiveByAdmin,
    sendPasswordLinkByAdmin,
    deleteUserByAdmin,
    updateFcmToken
};
