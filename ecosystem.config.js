module.exports = {
    apps: [{
        name: "reverse-proxy-server",
        script: "./server.js",
        autorestart: true,
        restart_delay: 5000,
        env_production: {
            NODE_ENV: "production"
        },
        env_development: {
            NODE_ENV: "development"
        }
    }]
}
