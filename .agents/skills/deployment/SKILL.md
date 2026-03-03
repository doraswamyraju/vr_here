---
name: Deploy to VPS
description: Steps for testing and deploying changes to the live VPS environment.
---

# Deploy to VPS (vrhere.in)

The workflow for deploying live changes to this VPS is:

1.  **Commit locally and push to GitHub**.
2.  **On the VPS**, navigate to `/var/www/vrhere`.
3.  **Sync the code**:
    ```bash
    git pull origin main
    chmod -R +x node_modules/.bin
    npm run build
    pm2 restart ecosystem.config.cjs --env production
    ```

### Important Notes
- **Process Name**: Always use **`vrhere-api`** (configured in `ecosystem.config.cjs`).
- **Port**: The backend listens on port **5002**.
- **Build Step**: You **must** run `npm run build` on the server after pulling code to see UI changes.
