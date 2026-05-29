import asyncHandler from 'express-async-handler';
import ServicePageConfig from '../models/ServicePageConfig.js';

const getGscConfig = () => {
    return {
        clientId: process.env.GSC_CLIENT_ID || 'dummy-client-id',
        clientSecret: process.env.GSC_CLIENT_SECRET || 'dummy-client-secret',
        redirectUri: process.env.GSC_REDIRECT_URI || 'http://localhost:5002/api/service-pages/gsc/callback'
    };
};

// @desc    Get Google OAuth2 URL
// @route   GET /api/service-pages/:pageId/gsc/auth
// @access  Private (Admin/Staff)
const getGscAuthUrl = asyncHandler(async (req, res) => {
    const { pageId } = req.params;
    const { clientId, redirectUri } = getGscConfig();

    const scope = 'https://www.googleapis.com/auth/webmasters.readonly';
    // State is used to pass the pageId to the callback
    const state = pageId;

    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
        `client_id=${encodeURIComponent(clientId)}&` +
        `redirect_uri=${encodeURIComponent(redirectUri)}&` +
        `response_type=code&` +
        `scope=${encodeURIComponent(scope)}&` +
        `access_type=offline&` +
        `prompt=consent&` +
        `state=${encodeURIComponent(state)}`;

    res.json({ authUrl });
});

// @desc    Google OAuth2 Callback Handler
// @route   GET /api/service-pages/gsc/callback
// @access  Public
const gscCallback = asyncHandler(async (req, res) => {
    const { code, state: pageId, error } = req.query;

    if (error) {
        return res.redirect(`/pvt-ltd-registration?gsc_status=error&error_message=${encodeURIComponent(error)}`);
    }

    if (!code || !pageId) {
        return res.status(400).send('Authorization code or pageId state is missing.');
    }

    const { clientId, clientSecret, redirectUri } = getGscConfig();

    try {
        // Exchange code for tokens
        const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                code,
                client_id: clientId,
                client_secret: clientSecret,
                redirect_uri: redirectUri,
                grant_type: 'authorization_code'
            })
        });

        const tokenData = await tokenResponse.json();

        if (tokenData.error) {
            console.error('GSC Token Exchange Error:', tokenData);
            return res.redirect(`/${pageId}?gsc_status=error&error_message=${encodeURIComponent(tokenData.error_description || tokenData.error)}`);
        }

        // Save tokens in database under the specified pageId
        const page = await ServicePageConfig.findOne({ pageId });
        if (!page) {
            return res.status(404).send(`Service page config for ${pageId} not found.`);
        }

        page.gscTokens = {
            accessToken: tokenData.access_token,
            refreshToken: tokenData.refresh_token || page.gscTokens.refreshToken, // refresh_token might only be returned on the first auth
            expiryDate: new Date(Date.now() + tokenData.expires_in * 1000)
        };

        await page.save();

        // Redirect back to the frontend page with a success message
        // In this workspace, PrivateLimitedPage corresponds to '/pvt-ltd-registration' route or '/pvt-ltd-registration' frontend path
        const redirectPath = pageId === 'private-limited' ? '/pvt-ltd-registration' : `/${pageId}`;
        res.redirect(`${redirectPath}?gsc_status=success`);
    } catch (err) {
        console.error('GSC Callback Error:', err);
        res.status(500).send(`OAuth2 Callback Error: ${err.message}`);
    }
});

// Helper to refresh Google OAuth2 Access Token
const refreshAccessToken = async (page) => {
    const { clientId, clientSecret } = getGscConfig();

    if (!page.gscTokens || !page.gscTokens.refreshToken) {
        throw new Error('Google Search Console is not connected yet. Please authorize access first.');
    }

    const response = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            client_id: clientId,
            client_secret: clientSecret,
            refresh_token: page.gscTokens.refreshToken,
            grant_type: 'refresh_token'
        })
    });

    const data = await response.json();

    if (data.error) {
        throw new Error(`Failed to refresh GSC token: ${data.error_description || data.error}`);
    }

    page.gscTokens.accessToken = data.access_token;
    page.gscTokens.expiryDate = new Date(Date.now() + data.expires_in * 1000);
    await page.save();

    return data.access_token;
};

// @desc    Get live GSC performance metrics for the page
// @route   GET /api/service-pages/:pageId/gsc/performance
// @access  Private (Admin/Staff)
const getGscPerformance = asyncHandler(async (req, res) => {
    const { pageId } = req.params;
    const page = await ServicePageConfig.findOne({ pageId });

    if (!page) {
        res.status(404);
        throw new Error('Service page config not found');
    }

    if (!page.gscTokens || !page.gscTokens.refreshToken) {
        return res.status(400).json({
            connected: false,
            message: 'Google Search Console is not connected yet.'
        });
    }

    let accessToken = page.gscTokens.accessToken;

    // Check if token has expired, refresh if necessary
    if (!accessToken || !page.gscTokens.expiryDate || new Date(page.gscTokens.expiryDate) <= new Date()) {
        try {
            accessToken = await refreshAccessToken(page);
        } catch (err) {
            return res.status(400).json({
                connected: false,
                message: err.message
            });
        }
    }

    // Determine target URL for Google Search Console API.
    // Replace with correct live production website URL.
    const siteUrl = process.env.GSC_SITE_URL || 'sc-domain:vrhere.in'; 
    const pageUrlPath = pageId === 'private-limited' ? '/pvt-ltd-registration' : `/${pageId}`;
    const pageUrl = `https://vrhere.in${pageUrlPath}`;

    // Query Search Console API
    const today = new Date().toISOString().split('T')[0];
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

    try {
        const queryResponse = await fetch(
            `https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(siteUrl)}/searchAnalytics/query`,
            {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    startDate: thirtyDaysAgo,
                    endDate: today,
                    dimensions: ['date'],
                    dimensionFilterGroups: [{
                        filters: [{
                            dimension: 'page',
                            operator: 'equals',
                            expression: pageUrl
                        }]
                    }]
                })
            }
        );

        const queryData = await queryResponse.json();

        if (queryData.error) {
            console.error('GSC Query API Error:', queryData);
            return res.status(400).json({
                connected: true,
                message: `GSC API Error: ${queryData.error.message}`,
                error: queryData.error
            });
        }

        // Return formatted performance dataset
        const performance = queryData.rows || [];
        
        // Sum up total performance metrics
        let totalClicks = 0;
        let totalImpressions = 0;
        let sumCtr = 0;
        let sumPosition = 0;

        performance.forEach(row => {
            totalClicks += row.clicks || 0;
            totalImpressions += row.impressions || 0;
            sumCtr += row.ctr || 0;
            sumPosition += row.position || 0;
        });

        const avgCtr = performance.length > 0 ? (sumCtr / performance.length) : 0;
        const avgPosition = performance.length > 0 ? (sumPosition / performance.length) : 0;

        res.json({
            connected: true,
            summary: {
                totalClicks,
                totalImpressions,
                avgCtr,
                avgPosition
            },
            history: performance.map(row => ({
                date: row.keys[0],
                clicks: row.clicks,
                impressions: row.impressions,
                ctr: row.ctr,
                position: row.position
            }))
        });
    } catch (err) {
        console.error('GSC Fetching Error:', err);
        res.status(500);
        throw new Error(`Failed to query Google Search Console: ${err.message}`);
    }
});

export {
    getGscAuthUrl,
    gscCallback,
    getGscPerformance
};
