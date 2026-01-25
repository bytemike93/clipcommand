const dotenv = require('dotenv');

dotenv.config();

module.exports = {
    apps: [
        {
            name: "clipserver",
            script: "server.js",
            env: {
                NODE_ENV: process.env.NODE_ENV || "production",
                PORT: process.env.PORT || 3001,
                TWITCH_CLIENT_ID: process.env.TWITCH_CLIENT_ID,
                TWITCH_CLIENT_SECRET: process.env.TWITCH_CLIENT_SECRET,
                TWITCH_REDIRECT_URI: process.env.TWITCH_REDIRECT_URI,
                TOKEN_ENCRYPTION_KEY: process.env.TOKEN_ENCRYPTION_KEY,
                HTTP_TIMEOUT_MS: process.env.HTTP_TIMEOUT_MS || 10000
            },
            merge_logs: true,
            out_file: "./logs/clipserver-out.log",
            error_file: "./logs/clipserver-err.log"
        }
    ]
};
