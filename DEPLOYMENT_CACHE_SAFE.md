# Cache-Safe Deployment Guide

## Why old UI appears after deploy
This usually happens when:
- old hashed JS files still exist in `assets/`
- browser/CDN caches old `index.html`
- deploy copies `dist/` folder incorrectly instead of replacing root `index.html` + `assets`

## Standard deploy (VPS)
Run these commands on server:

```bash
cd /var/www/vrhere
git pull origin main
npm install
npm run build

# cache-safe publish
cp -f dist/index.html index.html
rm -rf assets
mkdir -p assets
cp -r dist/assets/* assets/

cd backend
npm install
pm2 restart vrhere-api --update-env
pm2 save
```

## Optional hard cleanup publish
Use if you still see stale files:

```bash
cd /var/www/vrhere
find assets -type f -name "index-*.js" -delete
find assets -type f -name "index-*.css" -delete
cp -f dist/index.html index.html
cp -r dist/assets/* assets/
```

## Verify latest code is live
```bash
cd /var/www/vrhere
grep -R "Import Tasks & Sub Tasks (Excel)" dist assets -n
```

## Browser-side verify
1. Open site in Incognito.
2. Open DevTools -> Network -> enable `Disable cache`.
3. Hard reload once (`Ctrl + Shift + R`).

## cPanel auto-deploy note
`.cpanel.yml` is set to:
- clear `public_html/assets/*`
- copy fresh `dist/index.html` to `public_html/index.html`
- copy fresh `dist/assets/*` to `public_html/assets/`

This prevents stale bundle references on auto-deploy.
