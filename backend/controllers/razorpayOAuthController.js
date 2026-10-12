import RazorpayOAuthAccount from '../models/RazorpayOAuthAccount.js';

// Get OAuth Authorize URL
export const getAuthorizeUrl = (req, res) => {
    const isProd = process.env.NODE_ENV === 'production';
    const clientId = process.env.RAZORPAY_OAUTH_CLIENT_ID || process.env.RAZORPAY_OAUTH_DEV_CLIENT_ID;
    const redirectUri = isProd 
        ? 'https://vrhere.in/api/razorpay/callback' 
        : 'http://localhost:5002/api/razorpay/callback';
    const state = `vrhere_${Date.now()}`;

    const authUrl = `https://auth.razorpay.com/authorize?client_id=${clientId}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&scope=read_write&state=${state}`;

    if (req.query.redirect === 'true') {
        return res.redirect(authUrl);
    }

    res.json({
        success: true,
        authorizeUrl: authUrl,
        clientId,
        redirectUri
    });
};

// Handle OAuth Callback from Razorpay
export const handleOAuthCallback = async (req, res) => {
    const { code, error, error_description } = req.query;

    if (error) {
        return res.status(400).send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Razorpay Connection Failed</title>
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #0f172a; color: #fff; }
                    .card { background: #1e293b; border: 1px solid #ef4444; border-radius: 16px; padding: 32px; max-width: 480px; text-align: center; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
                    .badge { background: #ef444422; color: #ef4444; padding: 6px 14px; border-radius: 999px; font-weight: 600; display: inline-block; margin-bottom: 16px; }
                    h2 { margin: 0 0 12px; }
                    p { color: #94a3b8; font-size: 14px; line-height: 1.6; }
                    a { display: inline-block; margin-top: 20px; color: #38bdf8; text-decoration: none; font-weight: 500; }
                </style>
            </head>
            <body>
                <div class="card">
                    <div class="badge">Connection Failed</div>
                    <h2>Authorization Error</h2>
                    <p>${error_description || error}</p>
                    <a href="https://vrhere.in">Return to VR Here</a>
                </div>
            </body>
            </html>
        `);
    }

    if (!code) {
        return res.status(400).send('Missing authorization code');
    }

    try {
        const isProd = process.env.NODE_ENV === 'production';
        const clientId = process.env.RAZORPAY_OAUTH_CLIENT_ID || process.env.RAZORPAY_OAUTH_DEV_CLIENT_ID;
        const clientSecret = process.env.RAZORPAY_OAUTH_CLIENT_SECRET || process.env.RAZORPAY_OAUTH_DEV_CLIENT_SECRET;
        const redirectUri = isProd 
            ? 'https://vrhere.in/api/razorpay/callback' 
            : 'http://localhost:5002/api/razorpay/callback';
        const mode = isProd ? 'live' : 'test';

        // Exchange authorization code for tokens
        const tokenResponse = await fetch('https://api.razorpay.com/v1/oauth/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                client_id: clientId,
                client_secret: clientSecret,
                grant_type: 'authorization_code',
                redirect_uri: redirectUri,
                code: code,
                mode: mode
            })
        });

        const tokenData = await tokenResponse.json();

        if (!tokenResponse.ok || !tokenData.razorpay_account_id) {
            console.error('Razorpay OAuth Token Exchange Error:', tokenData);
            return res.status(400).send(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <title>Razorpay Token Exchange Failed</title>
                    <style>
                        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #0f172a; color: #fff; }
                        .card { background: #1e293b; border: 1px solid #ef4444; border-radius: 16px; padding: 32px; max-width: 480px; text-align: center; }
                        h2 { margin: 0 0 12px; }
                        p { color: #94a3b8; font-size: 14px; word-break: break-all; }
                    </style>
                </head>
                <body>
                    <div class="card">
                        <h2>Token Exchange Failed</h2>
                        <p>${JSON.stringify(tokenData)}</p>
                    </div>
                </body>
                </html>
            `);
        }

        const expiresAt = tokenData.expires_in 
            ? new Date(Date.now() + tokenData.expires_in * 1000) 
            : null;

        // Upsert the connected account
        await RazorpayOAuthAccount.findOneAndUpdate(
            { accountId: tokenData.razorpay_account_id },
            {
                accountId: tokenData.razorpay_account_id,
                mode: mode,
                accessToken: tokenData.access_token,
                refreshToken: tokenData.refresh_token,
                publicToken: tokenData.public_token,
                tokenType: tokenData.token_type || 'Bearer',
                expiresIn: tokenData.expires_in,
                expiresAt: expiresAt,
                isActive: true,
                metadata: tokenData
            },
            { upsert: true, new: true }
        );

        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>VR Here - Razorpay OAuth Connected</title>
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #0b1329; color: #fff; }
                    .card { background: #16203c; border: 1px solid #22c55e; border-radius: 20px; padding: 40px; max-width: 500px; text-align: center; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.7); }
                    .icon { width: 64px; height: 64px; background: #22c55e20; color: #22c55e; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 32px; margin: 0 auto 20px; }
                    h2 { margin: 0 0 8px; font-size: 24px; color: #f8fafc; }
                    .partner-tag { font-size: 13px; color: #60a5fa; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 20px; }
                    .details { background: #0b1329; border-radius: 12px; padding: 16px; margin: 24px 0; text-align: left; font-size: 14px; }
                    .row { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #1e293b; }
                    .row:last-child { border-bottom: none; }
                    .label { color: #94a3b8; }
                    .value { font-weight: 600; color: #f1f5f9; }
                    .btn { display: inline-block; background: #2563eb; color: #fff; text-decoration: none; padding: 12px 28px; border-radius: 10px; font-weight: 600; transition: background 0.2s; }
                    .btn:hover { background: #1d4ed8; }
                </style>
            </head>
            <body>
                <div class="card">
                    <div class="icon">✓</div>
                    <h2>Connected Successfully!</h2>
                    <div class="partner-tag">Rajugari Ventures • Platform Partner</div>
                    <p style="color: #94a3b8; font-size: 15px; margin: 0;">VR Here is now successfully authorized under your Razorpay Platform Partner account.</p>
                    
                    <div class="details">
                        <div class="row">
                            <span class="label">Merchant Account ID:</span>
                            <span class="value">${tokenData.razorpay_account_id}</span>
                        </div>
                        <div class="row">
                            <span class="label">Platform Partner:</span>
                            <span class="value">Rajugari Ventures</span>
                        </div>
                        <div class="row">
                            <span class="label">Environment:</span>
                            <span class="value">${mode.toUpperCase()}</span>
                        </div>
                        <div class="row">
                            <span class="label">Token Status:</span>
                            <span class="value" style="color: #22c55e;">Active</span>
                        </div>
                    </div>

                    <a class="btn" href="https://vrhere.in">Return to VR Here</a>
                </div>
            </body>
            </html>
        `);
    } catch (err) {
        console.error('OAuth Callback Exception:', err);
        res.status(500).send(`Server error: ${err.message}`);
    }
};

// Check connected account status
export const getOAuthStatus = async (req, res) => {
    try {
        const accounts = await RazorpayOAuthAccount.find({ isActive: true })
            .select('-accessToken -refreshToken')
            .sort({ createdAt: -1 });

        res.json({
            success: true,
            count: accounts.length,
            accounts
        });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
};
