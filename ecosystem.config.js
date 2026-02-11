export default {
    apps: [
        {
            name: 'vr-here-backend',
            script: './backend/server.js',
            env: {
                NODE_ENV: 'development',
                PORT: 5002,
            },
            env_production: {
                NODE_ENV: 'production',
                PORT: 5002,
            },
        },
    ],
};
