# VR Here Project Context & Architecture

## Backend API & Routing
*   **Production PM2 Process Name**: `vrhere-api` (IMPORTANT: Use this instead of `vr-here-backend`).
*   **Production Deployment Directory**: `/var/www/vrhere` on VPS.
*   **Backend Port**: `5002`.
*   **Database**: MongoDB. Connection string via `process.env.MONGO_URI`.
*   **Routes**: 
    *   `/api/orders` - Handles `Order` creation (POST) and retrieval (GET).
    *   `/api/users` - User authentication and details.

## Frontend
*   **Framework**: React (Vite).
*   **Proxy Setup**: Vite proxies `/api` to `http://localhost:5002`.
*   **Admin Panel**: Located in `frontend/admin.jsx`. Handles dashboard logic and fetches orders from backend. Logout functionality redirects to `/login`.

## Commands
*   **Start Backend via PM2**: `pm2 restart vrhere-api && pm2 save` (Requires `cwd` inside `backend`).
*   **Build Frontend**: `npm run build` in root directory.

## Known Gotchas
*   Always ensure you are operating inside the `/var/www/vrhere` path when deploying.
*   Backend dependencies are in `.cjs` or `package.json` with `"type": "module"`. Handle CommonJS interactions gracefully.
