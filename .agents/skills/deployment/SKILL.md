---
name: Deploy to VPS
description: Steps for testing and deploying changes to the live VPS environment.
---

# Deploy to VPS

We do not run `npm run build` or `npm run dev` locally to test the production build or serve it directly to clients. The workflow for testing and deploying live changes is strictly:

1. **Commit your changes locally**
2. **Push the changes to Git**
3. **Pull the Git repository on the remote VPS**
4. **Test it on the live website**

By following this workflow, we ensure that the source of truth is always Git and that live testing perfectly matches the remote environment.
