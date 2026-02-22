module.exports = {
    apps: [
        {
            name: 'vrhere-api',
            script: './server.js',
            cwd: './backend',
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
