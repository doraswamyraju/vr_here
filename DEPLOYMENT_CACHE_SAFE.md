# Cache-Safe Deployment Guide

## Standard Deploy (VPS)
Run these commands on the server:

```bash
cd /var/www/vrhere

# 1. Discard any local modifications and untracked files on the server (avoids merge blocks)
git reset --hard HEAD
git checkout .
git clean -fd

# 2. Pull the latest code cleanly
git pull origin main

# 3. Update backend and restart the process
cd backend
npm install
pm2 restart vrhere-api --update-env
pm2 save
```

### Quick One-Liner (Copy-Paste Safe):
```bash
cd /var/www/vrhere && git reset --hard HEAD && git checkout . && git clean -fd && git pull origin main && cd backend && npm install && pm2 restart vrhere-api --update-env && pm2 save
```

> [!IMPORTANT]
> **Do NOT copy `dist/index.html` to the root `index.html`.** 
> Doing so overwrites the development entry point `<script type="module" src="/src/main.jsx"></script>` and causes future builds to fail by bundling old bundles instead of compiling fresh source code. The Node.js Express server on this VPS is configured to serve directly from the `/dist` directory.

## Browser-side verify
1. Open the site in Incognito.
2. Open DevTools -> Network -> enable `Disable cache`.
3. Hard reload once (`Ctrl + Shift + R`).

## Razorpay Webhook Configuration
To enable automatic payment status updates:
1. In the Razorpay Dashboard, configure a webhook pointing to:
   `https://vrhere.in/api/payments/razorpay/webhook`
2. Subscribe to the following active events:
   - `payment_link.paid`
   - `payment.captured`
3. Optional: Set `RAZORPAY_WEBHOOK_SECRET` in the backend `.env` file to match the secret generated in the dashboard. If signature validation is bypassed/unset, signature checks are automatically skipped.

