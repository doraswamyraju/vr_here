import express from 'express';
import { 
    getAuthorizeUrl, 
    handleOAuthCallback, 
    getOAuthStatus 
} from '../controllers/razorpayOAuthController.js';

const router = express.Router();

// Authorize URL generator or redirect
router.get('/authorize', getAuthorizeUrl);

// OAuth Callback from Razorpay (both GET query params and fallback)
router.get('/callback', handleOAuthCallback);

// Status check of connected accounts
router.get('/status', getOAuthStatus);

export default router;
