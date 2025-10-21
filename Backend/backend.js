require('dotenv').config();

const jwt = require('jsonwebtoken');
const express = require("express");
const { Pool } = require('pg'); // USE POSTGRES
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const bcrypt = require("bcrypt");
const crypto = require('crypto');
const sgMail = require('@sendgrid/mail');
const twilio = require('twilio');

sgMail.setApiKey(process.env.SENDGRID_API_KEY);
console.log("📧 SendGrid mail client configured.");

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
console.log("📱 Twilio client initialized.");

const app = express();
const saltRounds = 10;

const corsOptions = {
    origin: 'https://civicsathi.netlify.app' // Allow requests ONLY from your Netlify site
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- CORRECTED STATIC FILE SERVING ---
const frontendPath = path.join(__dirname, '..', 'Frontend');
app.use(express.static(frontendPath));

const adminPath = path.join(__dirname, '..', 'Admin Dashboard');
app.use('/admin', express.static(adminPath));
// ------------------------------------

const uploadPath = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadPath)) fs.mkdirSync(uploadPath, { recursive: true });

const imageFileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Not an image! Please upload an image.', false));
    }
};

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadPath),
    filename: (req, file, cb) => cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`),
});

const upload = multer({
    storage: storage,
    fileFilter: imageFileFilter,
    limits: { fileSize: 5 * 1024 * 1024 }
});
app.use('/uploads', express.static(uploadPath));

// --- DATABASE CONNECTION FOR POSTGRES ---
const isProduction = process.env.NODE_ENV === 'production';
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: isProduction ? { rejectUnauthorized: false } : false
});
console.log("✅ Database connection pool for Postgres created successfully.");

// ==================================================================
// === AUTOMATIC DATABASE INITIALIZATION FUNCTION ===
// ==================================================================
async function initializeDatabase() {
    const client = await pool.connect();
    try {
        const setupScript = `
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(255) UNIQUE NOT NULL,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                phone VARCHAR(20) UNIQUE,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL DEFAULT 'user',
                is_email_verified BOOLEAN DEFAULT FALSE,
                email_verification_token TEXT,
                phone_otp VARCHAR(6),
                phone_otp_expires TIMESTAMP,
                is_phone_verified BOOLEAN DEFAULT FALSE,
                password_reset_token TEXT,
                password_reset_expires TIMESTAMP,
                points INTEGER DEFAULT 0 NOT NULL,
                profile_photo VARCHAR(255),
                address TEXT,
                pincode VARCHAR(10),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS reports (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(255) REFERENCES users(user_id),
                issue_type VARCHAR(100) NOT NULL,
                description TEXT,
                landmark VARCHAR(255),
                lat DECIMAL(10, 8),
                lon DECIMAL(11, 8),
                media TEXT,
                status VARCHAR(50) DEFAULT 'Pending',
                upvotes INTEGER DEFAULT 0,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS report_upvotes (
                report_id INTEGER REFERENCES reports(id) ON DELETE CASCADE,
                user_id VARCHAR(255) REFERENCES users(user_id) ON DELETE CASCADE,
                PRIMARY KEY (report_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS badges (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                description TEXT NOT NULL,
                icon_url VARCHAR(255)
            );

            CREATE TABLE IF NOT EXISTS user_badges (
                user_id VARCHAR(255) REFERENCES users(user_id) ON DELETE CASCADE,
                badge_id INTEGER REFERENCES badges(id) ON DELETE CASCADE,
                PRIMARY KEY (user_id, badge_id)
            );

            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM badges) THEN
                    INSERT INTO badges (id, name, description, icon_url) VALUES
                    (1, 'First Report', 'Submitted your very first report.', 'uploads/badge-first-report.png'),
                    (2, 'Community Scout', 'Submitted 5 reports.', 'uploads/badge-5-reports.png'),
                    (3, 'Civic Guardian', 'Submitted 25 reports.', 'uploads/badge-25-reports.png'),
                    (4, 'Resolution Achieved', 'Your report was marked as resolved.', 'uploads/badge-resolved.png'),
                    (5, 'Pothole Pro', 'Reported 5 potholes.', 'uploads/badge-pothole.png'),
                    (6, 'Waste Warrior', 'Reported 5 garbage dumps.', 'uploads/badge-garbage.png');
                END IF;
            END $$;
        `;
        await client.query(setupScript);
        console.log('✅ Database schema initialized successfully.');
    } finally {
        client.release();
    }
}
// ==================================================================
// === END OF FUNCTION ===
// ==================================================================


// --- GAMIFICATION HELPER FUNCTIONS ---
async function awardBadge(userId, badgeId) {
    try {
        await pool.query(
            "INSERT INTO user_badges (user_id, badge_id) VALUES ($1, $2) ON CONFLICT (user_id, badge_id) DO NOTHING",
            [userId, badgeId]
        );
    } catch (error) {
        console.error(`Failed to award badge ${badgeId} to user ${userId}:`, error);
    }
}

async function checkAndAwardBadges(userId) {
    try {
        const { rows: [userStats] } = await pool.query(
            `SELECT
                (SELECT COUNT(*) FROM reports WHERE user_id = $1) AS total_reports,
                (SELECT COUNT(*) FROM reports WHERE user_id = $1 AND issue_type = 'Pothole') AS pothole_reports,
                (SELECT COUNT(*) FROM reports WHERE user_id = $1 AND issue_type = 'Garbage Dump') AS garbage_reports,
                (SELECT COUNT(*) FROM reports WHERE user_id = $1 AND status = 'Resolved') AS resolved_reports
            `, [userId]
        );

        if (userStats.total_reports >= 1) await awardBadge(userId, 1);
        if (userStats.total_reports >= 5) await awardBadge(userId, 2);
        if (userStats.total_reports >= 25) await awardBadge(userId, 3);
        if (userStats.resolved_reports >= 1) await awardBadge(userId, 4);
        if (userStats.pothole_reports >= 5) await awardBadge(userId, 5);
        if (userStats.garbage_reports >= 5) await awardBadge(userId, 6);

    } catch (error) {
        console.error(`Failed to check badges for user ${userId}:`, error);
    }
}

async function addPoints(userId, pointsToAdd) {
    try {
        await pool.query(
            "UPDATE users SET points = points + $1 WHERE user_id = $2",
            [pointsToAdd, userId]
        );
        await checkAndAwardBadges(userId);
    } catch (error) {
        console.error(`Failed to add ${pointsToAdd} points to user ${userId}:`, error);
    }
}
// --- END GAMIFICATION HELPERS ---


const protect = (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = decoded;
            next();
        } catch (error) {
            return res.status(401).json({ error: 'Not authorized, token failed' });
        }
    } else {
        return res.status(401).json({ error: 'Not authorized, no token' });
    }
};

const isAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        return res.status(403).json({ error: 'Not authorized as an admin' });
    }
};

app.get('/verify-email', async (req, res) => {
    try {
        const { token } = req.query;
        if (!token) return res.status(400).send("<h1>Verification Failed</h1><p>No verification token provided.</p>");
        const { rows: results } = await pool.query("SELECT * FROM users WHERE email_verification_token = $1", [token]);
        if (results.length === 0) return res.status(400).send("<h1>Verification Failed</h1><p>Invalid or expired verification link.</p>");
        const user = results[0];
        await pool.query("UPDATE users SET is_email_verified = TRUE, email_verification_token = NULL WHERE user_id = $1", [user.user_id]);
        res.redirect(`/login.html?user_id=${user.user_id}&verified=true`);
    } catch (error) {
        console.error("Email Verification Error:", error);
        res.status(500).send("<h1>Error</h1><p>An error occurred during email verification.</p>");
    }
});

app.post("/register", async (req, res) => {
    try {
        let { name, email, phone, password } = req.body;
        if (!name || !email || !phone || !password) {
            return res.status(400).json({ error: "All fields are required." });
        }

        if (!phone.startsWith('+')) {
            phone = `+91${phone.replace(/[^0-9]/g, '')}`;
        }

        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const userId = `CS${Date.now()}`;
        const verificationToken = crypto.randomBytes(32).toString('hex');
        
        await pool.query(
            "INSERT INTO users (user_id, name, email, phone, password, role, email_verification_token) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            [userId, name, email, phone, hashedPassword, 'user', verificationToken]
        );

        const verificationLink = `${process.env.APP_URL}/verify-email?token=${verificationToken}`;
        const msg = {
            to: email,
            from: process.env.FROM_EMAIL,
            subject: 'Verify Your Email Address for Civic Sathi',
            html: `<p>Please click the link below to verify your email address:</p><a href="${verificationLink}">Verify My Email</a>`
        };
        await sgMail.send(msg);

        res.status(201).json({ message: "Registration successful! Please check your email to verify your account.", user_id: userId });
    } catch (error) {
        if (error.code === '23505') { // Postgres duplicate key error code
            return res.status(409).json({ error: "An account with this email or phone already exists." });
        }
        console.error("Register Error:", error);
        res.status(500).json({ error: "Registration failed. Please try again later." });
    }
});

app.post('/send-phone-otp', protect, async (req, res) => {
    const userId = req.user.userId;
    try {
        const { rows: results } = await pool.query("SELECT phone, is_phone_verified FROM users WHERE user_id = $1", [userId]);
        if (results.length === 0) return res.status(404).json({ error: 'User not found.' });
        
        const user = results[0];
        if (user.is_phone_verified) return res.status(400).json({ error: 'Phone number is already verified.' });

        const phoneOtp = crypto.randomInt(100000, 999999).toString();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

        await pool.query(
            "UPDATE users SET phone_otp = $1, phone_otp_expires = $2 WHERE user_id = $3",
            [phoneOtp, otpExpires, userId]
        );
        
        await twilioClient.messages.create({
            body: `Your Civic Sathi verification code is: ${phoneOtp}`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: user.phone
        });

        res.status(200).json({ message: 'Verification code sent to your phone number.' });
    } catch (error) {
        console.error("Send OTP Error:", error);
        res.status(500).json({ error: 'Failed to send verification code.' });
    }
});

app.post('/verify-phone', protect, async (req, res) => {
    const userId = req.user.userId;
    const { otp } = req.body;
    try {
        if (!otp) return res.status(400).json({ error: 'OTP is required.' });

        const { rows: results } = await pool.query("SELECT * FROM users WHERE user_id = $1", [userId]);
        if (results.length === 0) return res.status(404).json({ error: 'User not found.' });

        const user = results[0];
        const now = new Date();

        if (user.phone_otp !== otp || now > new Date(user.phone_otp_expires)) {
            return res.status(400).json({ error: 'Invalid or expired OTP. Please try again.' });
        }

        await pool.query(
            "UPDATE users SET is_phone_verified = TRUE, phone_otp = NULL, phone_otp_expires = NULL WHERE user_id = $1",
            [userId]
        );

        res.status(200).json({ message: 'Phone number verified successfully!' });

    } catch (error) {
        console.error("Phone Verification Error:", error);
        res.status(500).json({ error: "An internal server error occurred." });
    }
});

app.post("/login", async (req, res) => {
    try {
        const { user_id, password } = req.body;
        if (!user_id || !password) return res.status(400).json({ error: "User ID and password are required." });
        const { rows: results } = await pool.query("SELECT * FROM users WHERE user_id = $1", [user_id]);
        if (results.length === 0) return res.status(404).json({ error: "User not found." });
        const user = results[0];

        if (!user.is_email_verified) {
            return res.status(403).json({ error: "Please verify your email address before logging in." });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: "Invalid credentials." });

        const payload = { userId: user.user_id, role: user.role };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ message: "Login successful!", token: token });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ error: "An internal server error occurred." });
    }
});

app.get('/user/profile', protect, async (req, res) => {
    try {
        const { rows: results } = await pool.query(
            "SELECT user_id, name, email, phone, address, pincode, profile_photo, created_at, is_phone_verified, points FROM users WHERE user_id = $1",
            [req.user.userId]
        );
        if (results.length === 0) return res.status(404).json({ error: "User not found." });
        res.json(results[0]);
    } catch (error) {
        console.error("Get Profile Error:", error);
        res.status(500).json({ error: "Could not fetch profile. Please try again later." });
    }
});

app.get('/user/badges', protect, async (req, res) => {
    try {
        const { rows: results } = await pool.query(
            `SELECT b.name, b.description, b.icon_url 
             FROM user_badges ub
             JOIN badges b ON ub.badge_id = b.id
             WHERE ub.user_id = $1`,
            [req.user.userId]
        );
        res.json(results);
    } catch (error) {
        console.error("Get User Badges Error:", error);
        res.status(500).json({ error: "Could not fetch user badges." });
    }
});

app.post('/update-profile', protect, upload.single('profile_photo'), async (req, res) => {
    try {
        let { name, email, phone, pincode, address } = req.body;
        const userId = req.user.userId;

        if (phone && !phone.startsWith('+')) {
            phone = `+91${phone.replace(/[^0-9]/g, '')}`;
        }

        const params = [name, email, phone, pincode, address];
        let sql = "UPDATE users SET name = $1, email = $2, phone = $3, pincode = $4, address = $5";
        
        if (req.file) {
            sql += ", profile_photo = $6 WHERE user_id = $7";
            params.push(req.file.filename);
            params.push(userId);
        } else {
            sql += " WHERE user_id = $6";
            params.push(userId);
        }
        
        await pool.query(sql, params);
        res.json({ message: "Profile updated successfully!" });
    } catch (error) {
        console.error("Update Profile Error:", error);
        res.status(500).json({ error: "Could not update profile. Please try again later." });
    }
});

app.post('/report', protect, upload.array('media', 5), async (req, res) => {
    const { issue_type, description, landmark, lat, lon } = req.body;
    const userId = req.user.userId;
    const mediaFilenames = req.files.map(file => file.filename).join(',');

    try {
        await pool.query(
            "INSERT INTO reports (user_id, issue_type, description, landmark, lat, lon, media) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            [userId, issue_type, description, landmark, lat, lon, mediaFilenames]
        );
        await addPoints(userId, 10);
        res.status(201).json({ message: "Report submitted successfully!" });
    } catch (error) {
        console.error("Submit Report Error:", error);
        res.status(500).json({ error: "Could not submit report. Please try again later." });
    }
});

app.get('/reports/my-reports', protect, async (req, res) => {
    try {
        const { rows: results } = await pool.query(
            "SELECT id, issue_type, description, media, status, created_at FROM reports WHERE user_id = $1 ORDER BY created_at DESC",
            [req.user.userId]
        );
        res.json(results);
    } catch (error) {
        console.error("Get My Reports Error:", error);
        res.status(500).json({ error: "Could not fetch your reports." });
    }
});

app.delete('/report/:id', protect, async (req, res) => {
    try {
        const { rowCount } = await pool.query(
            "DELETE FROM reports WHERE id = $1 AND user_id = $2",
            [req.params.id, req.user.userId]
        );
        if (rowCount === 0) {
            return res.status(404).json({ error: "Report not found or you do not have permission to delete it." });
        }
        res.json({ message: "Report deleted successfully." });
    } catch (error) {
        console.error("Delete Report Error:", error);
        res.status(500).json({ error: "Could not delete report." });
    }
});

app.get('/reports', async (req, res) => {
    try {
        const { days } = req.query;
        let sql = "SELECT id, user_id, issue_type, description, landmark, lat, lon, media, status, upvotes, created_at FROM reports";
        const params = [];
        if (days && days !== 'all') {
            sql += ` WHERE created_at >= NOW() - INTERVAL '${parseInt(days, 10)} DAY'`;
        }
        sql += " ORDER BY created_at DESC";
        const { rows: results } = await pool.query(sql, params);
        res.json(results);
    } catch (error) {
        console.error("Get All Reports Error:", error);
        res.status(500).json({ error: "Database error fetching reports." });
    }
});

app.post('/reports/:id/upvote', protect, async (req, res) => {
    const reportId = req.params.id;
    const upvoterId = req.user.userId;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const { rows: [report] } = await client.query("SELECT user_id, status FROM reports WHERE id = $1 FOR UPDATE", [reportId]);
        if (!report) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: "Report not found." });
        }
        const reporterId = report.user_id;
        if (report.status !== 'Pending') {
            await client.query('ROLLBACK');
            return res.status(403).json({ message: `This issue is already '${report.status}' and can no longer be upvoted.` });
        }
        if (upvoterId === reporterId) {
            await client.query('ROLLBACK');
            return res.status(403).json({ message: "You cannot upvote your own issue." });
        }
        const { rows: existing } = await client.query("SELECT * FROM report_upvotes WHERE report_id = $1 AND user_id = $2", [reportId, upvoterId]);
        if (existing.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({ message: "You have already upvoted this issue." });
        }
        await client.query("INSERT INTO report_upvotes (report_id, user_id) VALUES ($1, $2)", [reportId, upvoterId]);
        await client.query("UPDATE reports SET upvotes = upvotes + 1 WHERE id = $1", [reportId]);
        await client.query("UPDATE users SET points = points + 5 WHERE user_id = $1", [reporterId]);
        await client.query('COMMIT');
        
        await checkAndAwardBadges(reporterId);
        res.status(200).json({ message: "Report upvoted successfully!" });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Upvote Report Error:", error);
        res.status(500).json({ error: "Database error during report upvote." });
    } finally {
        client.release();
    }
});

app.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ error: "Email is required."});
        }
        const { rows: [user] } = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

        if (!user) {
            return res.json({ message: "If an account with that email exists, a password reset link has been sent." });
        }
        
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetExpires = new Date(Date.now() + 15 * 60 * 1000);

        await pool.query(
            "UPDATE users SET password_reset_token = $1, password_reset_expires = $2 WHERE user_id = $3",
            [resetToken, resetExpires, user.user_id]
        );

        const resetLink = `${process.env.APP_URL}/reset-password.html?token=${resetToken}`;
        const msg = {
            to: user.email,
            from: process.env.FROM_EMAIL,
            subject: 'Password Reset Request for Civic Sathi',
            html: `<p>Please click the link to reset your password:</p><a href="${resetLink}">Reset Password</a>`
        };
        
        await sgMail.send(msg);

        res.json({ message: "If an account with that email exists, a password reset link has been sent." });
    } catch (error) {
        console.error("Forgot Password Error:", error);
        res.status(500).json({ error: "An error occurred." });
    }
});

app.post('/reset-password', async (req, res) => {
    try {
        const { token, new_password } = req.body;
        const { rows: [user] } = await pool.query(
            "SELECT * FROM users WHERE password_reset_token = $1 AND password_reset_expires > NOW()",
            [token]
        );
        if (!user) {
            return res.status(400).json({ error: 'Password reset token is invalid or has expired.' });
        }
        const hashedPassword = await bcrypt.hash(new_password, saltRounds);
        await pool.query(
            "UPDATE users SET password = $1, password_reset_token = NULL, password_reset_expires = NULL WHERE user_id = $2",
            [hashedPassword, user.user_id]
        );
        res.json({ message: "Password has been reset successfully." });
    } catch (error) {
        console.error("Reset Password Error:", error);
        res.status(500).json({ error: "Failed to reset password." });
    }
});

app.post("/admin/login", async (req, res) => {
    try {
        const { user_id, password } = req.body;
        const { rows: [user] } = await pool.query("SELECT * FROM users WHERE user_id = $1", [user_id]);
        if (!user) return res.status(404).json({ error: "User not found." });
        if (user.role !== 'admin') { return res.status(403).json({ error: "Access denied." }); }
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: "Invalid credentials." });
        const payload = { userId: user.user_id, role: user.role };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ message: "Admin login successful!", token: token });
    } catch (error) {
        console.error("Admin Login Error:", error);
        res.status(500).json({ error: "An internal server error occurred." });
    }
});

app.get('/admin/reports', protect, isAdmin, async (req, res) => {
    try {
        const { rows: results } = await pool.query("SELECT * FROM reports ORDER BY created_at DESC");
        res.json(results);
    } catch (error) {
        console.error("Admin Get Reports Error:", error);
        res.status(500).json({ error: "Could not fetch reports." });
    }
});

app.get('/admin/reports/:id', protect, isAdmin, async (req, res) => {
    try {
        const { rows: [report] } = await pool.query("SELECT * FROM reports WHERE id = $1", [req.params.id]);
        if (!report) {
            return res.status(404).json({ error: "Report not found." });
        }
        res.json(report);
    } catch (error) {
        console.error("Admin Get Report Details Error:", error);
        res.status(500).json({ error: "Could not fetch report details." });
    }
});

app.post('/admin/reports/:id/status', protect, isAdmin, async (req, res) => {
    try {
        const reportId = req.params.id;
        const { status } = req.body;
        if (status === 'Resolved') {
            const { rows: [report] } = await pool.query("SELECT user_id, status FROM reports WHERE id = $1", [reportId]);
            if (report && report.status !== 'Resolved') {
                await addPoints(report.user_id, 25);
            }
        }
        const { rowCount } = await pool.query("UPDATE reports SET status = $1 WHERE id = $2", [status, reportId]);
        if (rowCount === 0) { return res.status(404).json({ error: "Report not found." }); }
        res.json({ message: "Status updated successfully." });
    } catch (error) {
        console.error("Admin Update Status Error:", error);
        res.status(500).json({ error: "Could not update status." });
    }
});

app.post('/admin/reports/:id/reject', protect, isAdmin, async (req, res) => {
    const reportId = req.params.id;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const { rows: [report] } = await client.query("SELECT user_id FROM reports WHERE id = $1", [reportId]);
        if (!report) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: "Report not found." });
        }
        await client.query(
            "UPDATE users SET points = GREATEST(0, points - 20) WHERE user_id = $1",
            [report.user_id]
        );
        await client.query("DELETE FROM reports WHERE id = $1", [reportId]);
        await client.query('COMMIT');
        res.json({ message: `Report ${reportId} rejected.` });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Admin Reject Report Error:", error);
        res.status(500).json({ error: "Could not reject report." });
    } finally {
        client.release();
    }
});

app.get('/leaderboard', async (req, res) => {
    try {
        const { rows: results } = await pool.query(
            "SELECT user_id, points FROM users WHERE role = 'user' ORDER BY points DESC LIMIT 10"
        );
        res.json(results);
    } catch (error) {
        console.error("Get Leaderboard Error:", error);
        res.status(500).json({ error: "Could not fetch leaderboard data." });
    }
});

// ==================================================================
// === UPDATED SERVER STARTUP LOGIC ===
// ==================================================================
const startServer = async () => {
    try {
        await initializeDatabase();
        const PORT = process.env.PORT || 3000;
        app.listen(PORT, () => {
            console.log(`🚀 Server running on http://localhost:${PORT}`);
        });
    } catch (error) {
        console.error("❌ DATABASE SETUP FAILED:", error);
        process.exit(1); // Exit the process with an error code
    }
};

startServer();
// ==================================================================