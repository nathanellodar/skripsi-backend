// ecosystem.config.js
// Taruh di root folder project: /home/thanel/skripsi/skripsi-backend/

module.exports = {
    apps: [{
        name: "skripsi-backend",

        // Jalankan Python dari dalam virtualenv langsung
        interpreter: "/home/thanel/skripsi/skripsi-backend/venv/bin/python3",
        script: "run.py",
        cwd: "/home/thanel/skripsi/skripsi-backend",

        // Mode fork — bukan cluster, karena Python tidak support cluster mode PM2
        exec_mode: "fork",
        instances: 1,

        // Env variables — PM2 akan load ini, .env tetap dipakai oleh dotenv
        env: {
            LOG_MODE: "deploy",
        },

        // Auto restart jika crash
        autorestart: true,
        restart_delay: 3000,   // tunggu 3 detik sebelum restart
        max_restarts: 10,       // max 10 restart dalam 1 jam sebelum stop

        // Log
        out_file: "/home/thanel/skripsi/skripsi-backend/logs/pm2-out.log",
        error_file: "/home/thanel/skripsi/skripsi-backend/logs/pm2-error.log",
        log_date_format: "YYYY-MM-DD HH:mm:ss",
        merge_logs: true,
    }]
}