import asyncHandler from 'express-async-handler';
import { randomBytes, createHash } from 'crypto';
import { OAuth2Client } from 'google-auth-library';
import https from 'https';
import generateToken from '../utils/generateToken.js';
import User from '../models/User.js';
import sendEmail from '../utils/sendEmail.js';
import { uploadBufferToDrive } from '../services/googleDriveService.js';

const googleClient = new OAuth2Client();

const httpGetJson = async (url, headers = {}) => {
    const fullHeaders = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ...headers
    };
    if (typeof fetch === 'function') {
        try {
            const res = await fetch(url, { headers: fullHeaders });
            if (!res.ok) {
                console.error(`httpGetJson fetch failed for ${url} with status: ${res.status}`);
                return null;
            }
            return await res.json();
        } catch (e) {
            console.error(`httpGetJson fetch error for ${url}:`, e.message);
            return null;
        }
    }
    return new Promise((resolve) => {
        const req = https.get(url, { headers: fullHeaders }, (res) => {
            if (res.statusCode < 200 || res.statusCode >= 300) {
                console.error(`httpGetJson https.get failed for ${url} with status: ${res.statusCode}`);
                return resolve(null);
            }
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => {
                try { resolve(JSON.parse(data)); } catch (e) { resolve(null); }
            });
        });
        req.on('error', (err) => {
            console.error(`httpGetJson https error for ${url}:`, err.message);
            resolve(null);
        });
    });
};

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

    res.json({
        _id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone || '',
        role: user.role,
        profilePhoto: user.profilePhoto || null,
        companyLogo: user.companyLogo || null,
        companyName: user.companyName || '',
        businessType: user.businessType || '',
        gstin: user.gstin || '',
        panNumber: user.panNumber || '',
        address: user.address || '',
        isActive: user.isActive,
        isClockedIn: user.isClockedIn || false,
        activeOrderId: user.activeOrderId || null,
        assignedTicketCategories: user.assignedTicketCategories || [],
        token: generateToken(user._id)
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

        res.status(201).json({
            _id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            isActive: user.isActive,
            token: generateToken(user._id)
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

        res.status(201).json({
            _id: user._id,
            name: user.name,
            email: user.email,
            phone: user.phone,
            role: user.role,
            isActive: user.isActive,
            token: generateToken(user._id)
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

    res.status(201).json({
        success: true,
        data: 'Password reset success',
        token: generateToken(user._id)
    });
});

// @desc    Get user profile
// @route   GET /api/auth/profile
// @access  Private
const getUserProfile = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        res.json({
            _id: user._id,
            name: user.name,
            email: user.email,
            phone: user.phone || '',
            role: user.role,
            profilePhoto: user.profilePhoto || null,
            companyLogo: user.companyLogo || null,
            companyName: user.companyName || '',
            businessType: user.businessType || '',
            gstin: user.gstin || '',
            panNumber: user.panNumber || '',
            address: user.address || '',
            isActive: user.isActive,
            isClockedIn: user.isClockedIn || false,
            activeOrderId: user.activeOrderId || null,
            skills: user.skills,
            yearsOfExperience: user.yearsOfExperience,
            resumeUrl: user.resumeUrl,
            panCard: user.panCard,
            bankDetails: user.bankDetails,
            pendingProfileUpdate: user.pendingProfileUpdate
        });
    } else {
        res.status(404);
        throw new Error('User not found');
    }
});

// @desc    Update user profile
// @route   PUT /api/auth/profile
// @access  Private
const updateUserProfile = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (!user) {
        res.status(404);
        throw new Error('User not found');
    }

    if (req.body.name !== undefined) user.name = req.body.name;
    if (req.body.phone !== undefined) user.phone = req.body.phone;
    if (req.body.companyName !== undefined) user.companyName = req.body.companyName;
    if (req.body.businessType !== undefined) user.businessType = req.body.businessType;
    if (req.body.gstin !== undefined) user.gstin = req.body.gstin;
    if (req.body.panNumber !== undefined) user.panNumber = req.body.panNumber;
    if (req.body.address !== undefined) user.address = req.body.address;
    if (req.body.profilePhoto !== undefined) user.profilePhoto = req.body.profilePhoto;
    if (req.body.companyLogo !== undefined) user.companyLogo = req.body.companyLogo;

    if (req.body.password) {
        user.password = req.body.password;
    }

    const updatedUser = await user.save();

    res.json({
        _id: updatedUser._id,
        name: updatedUser.name,
        email: updatedUser.email,
        phone: updatedUser.phone || '',
        role: updatedUser.role,
        profilePhoto: updatedUser.profilePhoto || null,
        companyLogo: updatedUser.companyLogo || null,
        companyName: updatedUser.companyName || '',
        businessType: updatedUser.businessType || '',
        gstin: updatedUser.gstin || '',
        panNumber: updatedUser.panNumber || '',
        address: updatedUser.address || '',
        isActive: updatedUser.isActive,
        token: generateToken(updatedUser._id)
    });
});

// @desc    Upload profile photo or company logo
// @route   POST /api/auth/upload-avatar or /api/auth/upload-logo
// @access  Private
const uploadProfileMedia = asyncHandler(async (req, res) => {
    if (!req.file) {
        res.status(400);
        throw new Error('No image file uploaded');
    }

    const mediaType = req.body.type || (req.path.includes('logo') ? 'companyLogo' : 'profilePhoto');
    const user = await User.findById(req.user._id);
    if (!user) {
        res.status(404);
        throw new Error('User not found');
    }

    let fileUrl = '';
    try {
        const cleanName = (req.file.originalname || 'upload.png').replace(/[^a-zA-Z0-9._-]/g, '');
        const fileName = `${mediaType}_${user._id}_${Date.now()}_${cleanName}`;
        const driveRes = await uploadBufferToDrive({
            fileBuffer: req.file.buffer,
            mimeType: req.file.mimetype,
            fileName
        });
        fileUrl = driveRes.webViewLink || driveRes.webContentLink;
    } catch (driveErr) {
        console.warn('[ProfileMediaUpload] Google Drive upload fallback to base64 data URL:', driveErr.message);
        const base64 = req.file.buffer.toString('base64');
        fileUrl = `data:${req.file.mimetype};base64,${base64}`;
    }

    if (mediaType === 'companyLogo') {
        user.companyLogo = fileUrl;
    } else {
        user.profilePhoto = fileUrl;
    }
    await user.save();

    res.json({
        success: true,
        mediaType,
        url: fileUrl,
        user: {
            _id: user._id,
            name: user.name,
            email: user.email,
            phone: user.phone || '',
            profilePhoto: user.profilePhoto || null,
            companyLogo: user.companyLogo || null,
            companyName: user.companyName || '',
            role: user.role
        }
    });
});

// @desc    Update FCM Token for user
// @route   PUT /api/auth/fcm-token
// @access  Private
const updateFcmToken = asyncHandler(async (req, res) => {
    const token = req.body.fcmToken || req.body.token;
    const user = await User.findById(req.user._id);

    if (user) {
        user.fcmToken = token || null;
        await user.save();
        res.json({ success: true, message: 'FCM token updated successfully', fcmToken: user.fcmToken });
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
    const { name, email, phone, role, isActive, commissionPercentage, panCard, canManageCompliance, assignedTicketCategories } = req.body;
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
    if (canManageCompliance !== undefined) user.canManageCompliance = Boolean(canManageCompliance);
    if (commissionPercentage !== undefined) user.commissionPercentage = Number(commissionPercentage);
    if (panCard !== undefined) user.panCard = panCard;
    if (assignedTicketCategories !== undefined) {
        user.assignedTicketCategories = Array.isArray(assignedTicketCategories) ? assignedTicketCategories : [];
    }

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
            canManageCompliance: user.canManageCompliance,
            commissionPercentage: user.commissionPercentage,
            panCard: user.panCard,
            assignedTicketCategories: user.assignedTicketCategories,
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

// @desc    Delete self account
// @route   DELETE /api/auth/delete-account
// @access  Private
const deleteSelfAccount = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (!user) {
        res.status(404);
        throw new Error('User not found');
    }

    if (user.role === 'admin') {
        res.status(400);
        throw new Error('Admins cannot delete their own account from the app');
    }

    await User.deleteOne({ _id: req.user._id });

    res.json({ success: true, message: 'Account deleted successfully' });
});

// @desc    Authenticate or register user with Google OAuth Token or Code
// @route   POST /api/auth/google
// @access  Public
const googleAuth = asyncHandler(async (req, res) => {
    const { idToken, credential, accessToken, code } = req.body;

    let payload;

    // Handle OAuth Authorization Code exchange if provided
    if (code) {
        try {
            const effectiveRedirectUri = (req.body.redirectUri || `${(process.env.FRONTEND_URL || 'https://vrhere.in').replace(/\/$/, '')}/auth/google/callback`).split('?')[0].split('#')[0];
            const clientId = process.env.GOOGLE_CLIENT_ID || '674627570227-vt8ub6924het3d49j57ep1fh6k42c9p0.apps.googleusercontent.com';
            const clientSecret = process.env.GOOGLE_CLIENT_SECRET || '';

            const postBody = new URLSearchParams({
                code: String(code).trim(),
                client_id: clientId,
                client_secret: clientSecret,
                redirect_uri: effectiveRedirectUri,
                grant_type: 'authorization_code'
            });

            console.log('[Google Auth] Exchanging code with redirect_uri:', effectiveRedirectUri);

            const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: postBody.toString()
            });

            const tokens = await tokenRes.json();

            if (tokens.error) {
                console.error('[Google Auth] Token exchange error from Google:', tokens.error, tokens.error_description);
            } else if (tokens.id_token) {
                try {
                    const ticket = await googleClient.verifyIdToken({
                        idToken: tokens.id_token,
                        audience: clientId ? [clientId] : undefined
                    });
                    payload = ticket.getPayload();
                } catch (verifyErr) {
                    payload = await httpGetJson(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(tokens.id_token)}`);
                }
            } else if (tokens.access_token) {
                payload = await httpGetJson('https://www.googleapis.com/oauth2/v3/userinfo', {
                    Authorization: `Bearer ${tokens.access_token}`
                });
            }
        } catch (codeErr) {
            console.error('OAuth code exchange error:', codeErr);
        }
    }

    if (!payload && accessToken) {
        try {
            payload = await httpGetJson('https://www.googleapis.com/oauth2/v3/userinfo', {
                Authorization: `Bearer ${accessToken}`
            });
            if (!payload) {
                payload = await httpGetJson(`https://oauth2.googleapis.com/tokeninfo?access_token=${encodeURIComponent(accessToken)}`);
            }
        } catch (e) {
            console.error('AccessToken verify error:', e);
        }
    }

    if (!payload) {
        const tokenToVerify = idToken || credential;
        if (!tokenToVerify) {
            res.status(400);
            throw new Error('Google token or authorization code is required');
        }

        try {
            const ticket = await googleClient.verifyIdToken({
                idToken: tokenToVerify,
                audience: process.env.GOOGLE_CLIENT_ID ? [process.env.GOOGLE_CLIENT_ID] : undefined
            });
            payload = ticket.getPayload();
        } catch (err) {
            try {
                payload = await httpGetJson(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(tokenToVerify)}`);
                if (!payload) {
                    throw new Error('Invalid token response from Google API');
                }
            } catch (fetchErr) {
                res.status(401);
                throw new Error('Invalid or expired Google token');
            }
        }
    }

    if (!payload || !payload.email) {
        res.status(401);
        throw new Error('Could not extract user details from Google token');
    }

    const { email, name, sub: googleId } = payload;

    let user = await User.findOne({ email });

    if (user) {
        if (!user.isActive) {
            res.status(403);
            const message = user.role === 'partner' 
                ? 'Your partner account is pending validation. Please wait for admin approval.' 
                : 'User account is inactive. Contact admin.';
            throw new Error(message);
        }

        if (!user.googleId) {
            user.googleId = googleId;
            user.authProvider = user.authProvider || 'google';
        }
        if (payload.picture && !user.profilePhoto) {
            user.profilePhoto = payload.picture;
        }
        await user.save();
    } else {
        user = await User.create({
            name: name || email.split('@')[0],
            email,
            googleId,
            profilePhoto: payload.picture || null,
            authProvider: 'google',
            role: 'client',
            isActive: true
        });

        try {
            await sendEmail({
                email: user.email,
                subject: 'Welcome to VR HERE Business Solutions',
                message: `<h1>Welcome ${user.name}!</h1><p>Thank you for signing up with Google at VR HERE.</p>`
            });
        } catch (emailError) {
            console.error('Failed to send welcome email:', emailError.message);
        }
    }

    res.json({
        _id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone || '',
        role: user.role,
        profilePhoto: user.profilePhoto || null,
        companyLogo: user.companyLogo || null,
        companyName: user.companyName || '',
        businessType: user.businessType || '',
        gstin: user.gstin || '',
        panNumber: user.panNumber || '',
        address: user.address || '',
        requiresPhone: !user.phone,
        isActive: user.isActive,
        isClockedIn: user.isClockedIn || false,
        activeOrderId: user.activeOrderId || null,
        token: generateToken(user._id)
    });
});

export {
    authUser,
    googleAuth,
    registerUser,
    registerPartner,
    forgotPassword,
    resetPassword,
    getUserProfile,
    updateUserProfile,
    uploadProfileMedia,
    getEmployees,
    getUsers,
    createUserByAdmin,
    updateUserByAdmin,
    toggleUserActiveByAdmin,
    sendPasswordLinkByAdmin,
    deleteUserByAdmin,
    deleteSelfAccount,
    updateFcmToken
};
