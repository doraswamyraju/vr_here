import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            '@': path.resolve(__dirname, './frontend'),
        },
    },
    build: {
        outDir: 'dist',
        assetsDir: 'assets',
        // We want the build to be copy-pasteable so empty outDir is fine
        emptyOutDir: true,
    }
})
