# Cache-Safe Deployment Guide

## Standard deploy (VPS)
Run these commands on the server:

```bash
cd /var/www/vrhere

# 1. Pull the latest code
git pull origin main

# 2. Restore index.html in case it was mutated by old deployment commands
git checkout index.html

# 3. Clean install and compile
npm install
npm run build

# 4. Update and restart the backend
cd backend
npm install
pm2 restart vrhere-api --update-env
pm2 save
```

> [!IMPORTANT]
> **Do NOT copy `dist/index.html` to the root `index.html`.** 
> Doing so overwrites the development entry point `<script type="module" src="/src/main.jsx"></script>` and causes future builds to fail by bundling old bundles instead of compiling fresh source code. The Node.js Express server on this VPS is configured to serve directly from the `/dist` directory.

## Browser-side verify
1. Open the site in Incognito.
2. Open DevTools -> Network -> enable `Disable cache`.
3. Hard reload once (`Ctrl + Shift + R`).

