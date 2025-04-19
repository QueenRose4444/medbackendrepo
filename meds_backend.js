// meds_backend.js - Using SQLite with Refresh Token Authentication
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto'); // Needed for generating refresh tokens

const app = express();
const PORT = process.env.PORT || 3001;

// --- Security Configuration ---
// Access Token: Short-lived, used for most API calls
const JWT_SECRET = process.env.JWT_SECRET || 't8r74T3y&a*PCpev$8QCz!sxd%$B$TMHZyTp79%eSKzqEt!mKBf!yA1X3kX3Qu0M';
const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '45m'; // e.g., 15 minutes

// Refresh Token: Long-lived, used ONLY to get a new access token
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'B8rkF3#wk@5xsXG7c*vzgmurpM9gs1#4*hUn5h4e^M6UNES1F2M8&*n!U5tVea6c';
const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '28d'; // e.g., 7 days

// --- Database Setup ---
const dbPath = path.resolve('/data', 'meds.db');
console.log(`INFO: Database path: ${dbPath}`);

const dataDir = path.dirname(dbPath);
if (!fs.existsSync(dataDir)) {
    console.log(`INFO: Creating data directory: ${dataDir}`);
    try {
        fs.mkdirSync(dataDir, { recursive: true });
    } catch (mkdirErr) {
        console.error(`FATAL: Could not create data directory ${dataDir}`, mkdirErr);
        process.exit(1);
    }
}

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("FATAL: Could not connect to database", err.message);
        process.exit(1);
    } else {
        console.log("INFO: Connected to SQLite database.");
        db.run("PRAGMA foreign_keys = ON;", (pragmaErr) => {
            if (pragmaErr) console.error("Error enabling foreign keys:", pragmaErr.message);
            else console.log("INFO: Foreign key support enabled.");
            createTables();
        });
    }
});

// Updated createTables function to include refresh_token column
function createTables() {
    db.serialize(() => {
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                refresh_token TEXT, -- Store the current valid refresh token (nullable)
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `, (err) => {
            if (err) console.error("Error creating/altering users table:", err.message);
            else {
                console.log("INFO: 'users' table checked/created.");
                // Add refresh_token column if it doesn't exist (for upgrades)
                db.run("ALTER TABLE users ADD COLUMN refresh_token TEXT", (alterErr) => {
                    if (alterErr && !alterErr.message.includes('duplicate column name')) {
                         console.error("Error adding refresh_token column:", alterErr.message);
                    } else if (!alterErr) {
                         console.log("INFO: Added 'refresh_token' column to 'users' table.");
                    }
                });
            }
        });

        db.run(`
            CREATE TABLE IF NOT EXISTS med_data (
                data_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                shot_history TEXT,
                settings TEXT,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        `, (err) => {
            if (err) console.error("Error creating med_data table:", err.message);
            else console.log("INFO: 'med_data' table checked/created.");
        });
    });
}

// --- Middleware ---
const corsOptions = {
    origin: 'https://rosiesite.rosestuffs.org', // Allow only your frontend domain
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS",
    allowedHeaders: "Content-Type, Authorization",
    credentials: true, // Allow cookies if you switch to HttpOnly later
    optionsSuccessStatus: 204
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Handle preflight requests
app.use(bodyParser.json());

// --- Authentication Middleware (authenticateToken) ---
// Verifies the ACCESS token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) {
        console.log("Auth middleware: No token provided");
        return res.status(401).json({ error: 'No token provided' }); // Unauthorized
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log("Auth middleware: JWT verification failed:", err.message);
            if (err.name === 'TokenExpiredError') {
                // Send specific error for expired token
                return res.status(401).json({ error: 'Token expired' });
            }
            if (err.name === 'JsonWebTokenError') {
                 return res.status(403).json({ error: 'Invalid token' }); // Forbidden
            }
             return res.status(403).json({ error: 'Token verification failed' }); // Forbidden for other errors
        }
        // Add user payload to request
        if (!user || !user.userId || !user.username) {
            console.error("Auth middleware: Invalid token payload structure:", user);
            return res.status(403).json({ error: 'Invalid token payload' }); // Forbidden
        }
        req.user = user; // Contains { userId, username }
        console.log(`Auth middleware: Access Token verified for user ${user.username} (ID: ${user.userId})`);
        next();
    });
};

// --- API Routes ---

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    console.log(`Registration attempt for username: ${username}`);
    if (!username || !password || typeof username !== 'string' || typeof password !== 'string' || password.length < 4) {
        return res.status(400).json({ error: 'Username and a password (min 4 chars) are required' });
    }

    db.get("SELECT user_id FROM users WHERE username = ?", [username], async (err, row) => {
        if (err) { console.error("DB error checking username:", err.message); return res.status(500).json({ error: 'Database error during registration check' }); }
        if (row) { console.log(`Registration failed: Username ${username} already exists`); return res.status(400).json({ error: 'Username already exists' }); }

        try {
            const saltRounds = 10;
            const passwordHash = await bcrypt.hash(password, saltRounds);
            db.run("INSERT INTO users (username, password_hash) VALUES (?, ?)", [username, passwordHash], function (err) {
                if (err) { console.error("DB error inserting user:", err.message); return res.status(500).json({ error: 'Failed to register user due to database error' }); }
                const newUserId = this.lastID;
                console.log(`User registered successfully: ${username} (ID: ${newUserId})`);
                // Initialize med_data
                db.run("INSERT INTO med_data (user_id, shot_history, settings) VALUES (?, ?, ?)",
                    [newUserId, JSON.stringify([]), JSON.stringify({})],
                    (initErr) => {
                        if (initErr) console.error(`DB error initializing med_data for user ID ${newUserId}:`, initErr.message);
                        else console.log(`Initialized med_data for user ID ${newUserId}`);
                        res.status(201).json({ message: 'User registered successfully' });
                    }
                );
            });
        } catch (error) { console.error("Registration bcrypt/db error:", error); res.status(500).json({ error: 'Failed to register user' }); }
    });
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    console.log(`Login attempt for username: ${username}`);
    if (!username || !password) { return res.status(400).json({ error: 'Username and password are required' }); }

    db.get("SELECT user_id, username, password_hash FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) { console.error("DB error finding user:", err.message); return res.status(500).json({ error: 'Login failed due to database error' }); }
        if (!user) { console.log(`Login failed: User ${username} not found`); return res.status(401).json({ error: 'Invalid credentials' }); }

        try {
            const match = await bcrypt.compare(password, user.password_hash);
            if (match) {
                // --- Generate Tokens ---
                const userPayload = { userId: user.user_id, username: user.username };

                // Access Token (short-lived)
                const accessToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });

                // Refresh Token (long-lived) - Contains minimal info needed for refresh
                // Using a simple random string for the token itself for now, could also be a JWT
                // const refreshToken = crypto.randomBytes(40).toString('hex');
                // Let's use a JWT for the refresh token too, makes verification easier
                 const refreshTokenPayload = { userId: user.user_id }; // Only need userId
                 const refreshToken = jwt.sign(refreshTokenPayload, REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });


                // --- Store Refresh Token in DB ---
                db.run("UPDATE users SET refresh_token = ? WHERE user_id = ?", [refreshToken, user.user_id], (updateErr) => {
                    if (updateErr) {
                        console.error(`DB error storing refresh token for user ${user.username}:`, updateErr.message);
                        // Decide if login should fail here - maybe proceed but warn? For now, fail.
                        return res.status(500).json({ error: 'Login failed during token storage.' });
                    }
                    console.log(`User logged in successfully: ${username} (ID: ${user.user_id}). Refresh token stored.`);
                    // --- Send Both Tokens to Frontend ---
                    res.json({
                        accessToken: accessToken,
                        refreshToken: refreshToken // Send refresh token in response body
                    });
                });
            } else {
                console.log(`Login failed: Invalid password for user ${username}`);
                res.status(401).json({ error: 'Invalid credentials' });
            }
        } catch (error) {
            console.error("Login bcrypt/jwt/db error:", error);
            res.status(500).json({ error: 'Login failed due to server error' });
        }
    });
});

// POST /api/auth/refresh (NEW)
// Takes a refresh token, verifies it, and returns a new access token
app.post('/api/auth/refresh', (req, res) => {
    const { refreshToken } = req.body;
    console.log("Refresh token attempt received.");

    if (!refreshToken) {
        console.log("Refresh failed: No refresh token provided.");
        return res.status(401).json({ error: 'Refresh token required' });
    }

    // Verify the refresh token using its specific secret
    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            console.log("Refresh failed: Refresh token verification failed:", err.message);
             // If expired or invalid, prompt user to log in again
            return res.status(403).json({ error: 'Invalid or expired refresh token. Please log in again.' }); // Forbidden
        }

        // Token is structurally valid and not expired, check if it matches the one in DB
        const userId = decoded.userId;
        if (!userId) {
             console.log("Refresh failed: Invalid payload in refresh token.");
             return res.status(403).json({ error: 'Invalid refresh token payload.' });
        }

        db.get("SELECT user_id, username, refresh_token FROM users WHERE user_id = ?", [userId], (dbErr, user) => {
            if (dbErr) { console.error(`DB error finding user ${userId} for refresh:`, dbErr.message); return res.status(500).json({ error: 'Server error during token refresh.' }); }
            if (!user) { console.log(`Refresh failed: User ${userId} not found.`); return res.status(403).json({ error: 'User not found.' }); }
            if (user.refresh_token !== refreshToken) {
                 console.log(`Refresh failed: Provided token does not match stored token for user ${userId}. Possible old/revoked token.`);
                 return res.status(403).json({ error: 'Refresh token has been invalidated. Please log in again.' });
            }

            // --- Refresh Token is Valid and Matches Stored Token ---
            // Generate a new access token
            const userPayload = { userId: user.user_id, username: user.username };
            const newAccessToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });

            console.log(`Token refreshed successfully for user ${user.username} (ID: ${userId})`);
            res.json({ accessToken: newAccessToken });
        });
    });
});

// POST /api/auth/logout (NEW) - Protected by Access Token
// Clears the refresh token from the database
app.post('/api/auth/logout', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const username = req.user.username;
    console.log(`Logout request for user: ${username} (ID: ${userId})`);

    // Clear the refresh token in the database
    db.run("UPDATE users SET refresh_token = NULL WHERE user_id = ?", [userId], function(err) {
        if (err) {
            console.error(`DB error clearing refresh token for user ${userId}:`, err.message);
            // Still proceed with logout on client-side, but report server error
            return res.status(500).json({ error: 'Server error during logout process.' });
        }
        console.log(`Refresh token cleared for user ${username} (ID: ${userId}). Rows affected: ${this.changes}`);
        res.status(200).json({ message: 'Logged out successfully.' });
    });
});


// POST /api/auth/change-password - Updated to clear refresh token
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
    const username = req.user.username;
    const userId = req.user.userId;
    const { currentPassword, newPassword } = req.body;
    console.log(`Password change attempt for user: ${username} (ID: ${userId})`);

    if (!currentPassword || !newPassword || typeof newPassword !== 'string' || newPassword.length < 4) {
        return res.status(400).json({ error: 'Current password and new password (min 4 chars) are required.' });
    }

    db.get("SELECT password_hash FROM users WHERE user_id = ?", [userId], async (err, user) => {
        if (err) { console.error("DB error finding user for pwd change:", err.message); return res.status(500).json({ error: 'Failed to process request.' }); }
        if (!user) { return res.status(404).json({ error: 'User not found.' }); }

        try {
            const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
            if (!isMatch) { return res.status(401).json({ error: 'Incorrect current password.' }); }

            const saltRounds = 10;
            const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

            // Update password AND clear refresh token in one transaction (using serialize)
            db.serialize(() => {
                db.run("BEGIN TRANSACTION;"); // Start transaction

                let success = true;
                db.run("UPDATE users SET password_hash = ? WHERE user_id = ?", [newPasswordHash, userId], function (updateErr) {
                    if (updateErr) {
                        console.error(`DB error updating password for ${username}:`, updateErr.message);
                        success = false;
                    } else if (this.changes === 0) {
                         console.error(`Pwd change failed: No rows updated for user ID ${userId}.`);
                         success = false;
                    }
                });

                db.run("UPDATE users SET refresh_token = NULL WHERE user_id = ?", [userId], function (clearErr) {
                     if (clearErr) {
                        console.error(`DB error clearing refresh token after pwd change for ${username}:`, clearErr.message);
                        // Don't necessarily fail the whole operation if token clear fails, but log it.
                    } else {
                         console.log(`Refresh token cleared after password change for ${username}.`);
                    }
                });

                db.run(success ? "COMMIT;" : "ROLLBACK;", (commitErr) => {
                    if (commitErr) {
                         console.error(`DB transaction error during pwd change for ${username}:`, commitErr.message);
                         return res.status(500).json({ error: 'Failed to update password due to transaction error.' });
                    }
                    if (success) {
                        console.log(`Password changed successfully for user: ${username}`);
                        res.status(200).json({ message: 'Password changed successfully. Please log in again if needed.' });
                    } else {
                         res.status(500).json({ error: 'Failed to update password.' });
                    }
                });
            }); // End serialize

        } catch (error) {
            console.error(`Password change bcrypt/db error for ${username}:`, error);
            db.run("ROLLBACK;"); // Ensure rollback on catch
            res.status(500).json({ error: 'Failed to process password change.' });
        }
    });
});


// GET /api/meddata - Protected Route (No changes needed here)
app.get('/api/meddata', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    console.log(`Fetching data for user ID: ${userId}`);
    db.get("SELECT shot_history, settings FROM med_data WHERE user_id = ?", [userId], (err, row) => {
        if (err) { console.error(`DB error fetching data for user ID ${userId}:`, err.message); return res.status(500).json({ error: "Failed to fetch data" }); }
        if (row) {
            try {
                const medData = {
                    shotHistory: JSON.parse(row.shot_history || '[]'),
                    settings: JSON.parse(row.settings || '{}')
                };
                console.log(`Data fetched successfully for user ID ${userId}`);
                res.json(medData);
            } catch (parseError) {
                console.error(`DB error parsing data for user ID ${userId}:`, parseError.message);
                res.json({ shotHistory: [], settings: {} });
            }
        } else {
            console.log(`No med_data found for user ID ${userId}, returning empty.`);
            res.json({ shotHistory: [], settings: {} });
        }
    });
});

// POST /api/meddata - Protected Route (No changes needed here)
app.post('/api/meddata', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const newMedData = req.body;
    console.log(`Received data update request for user ID: ${userId}`);
    if (!newMedData || typeof newMedData !== 'object' || !Array.isArray(newMedData.shotHistory) || typeof newMedData.settings !== 'object') {
        return res.status(400).json({ error: 'Invalid data format provided' });
    }
    if (newMedData.shotHistory.some(shot => !shot || !shot.dateTime || isNaN(new Date(shot.dateTime).getTime()))) {
        return res.status(400).json({ error: 'Invalid date found in shot history.' });
    }
    const shotHistoryJson = JSON.stringify(newMedData.shotHistory);
    const settingsJson = JSON.stringify(newMedData.settings);
    const currentTime = new Date().toISOString();
    const sql = `
        INSERT INTO med_data (user_id, shot_history, settings, last_updated)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            shot_history = excluded.shot_history,
            settings = excluded.settings,
            last_updated = excluded.last_updated;
    `;
    db.run(sql, [userId, shotHistoryJson, settingsJson, currentTime], function (err) {
        if (err) { console.error(`DB error saving data for user ID ${userId}:`, err.message); return res.status(500).json({ error: 'Failed to save data.' }); }
        console.log(`Data saved successfully for user ID: ${userId}. Rows affected: ${this.changes}`);
        res.status(200).json({ message: 'Data saved successfully' });
    });
});


// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Meds backend server running on port ${PORT}`);
    console.log(`Allowing requests from origin: ${corsOptions.origin}`);
    // Security warnings for secrets
    if (!process.env.JWT_SECRET || JWT_SECRET === 'FALLBACK_ACCESS_SECRET_CHANGE_ME') { console.error("SECURITY WARNING: Default/Fallback JWT_SECRET is used! Set JWT_SECRET environment variable."); }
    if (!process.env.REFRESH_TOKEN_SECRET || REFRESH_TOKEN_SECRET === 'FALLBACK_REFRESH_SECRET_CHANGE_ME_TOO') { console.error("SECURITY WARNING: Default/Fallback REFRESH_TOKEN_SECRET is used! Set REFRESH_TOKEN_SECRET environment variable."); }
    console.log(`INFO: Access token expiry: ${ACCESS_TOKEN_EXPIRY}, Refresh token expiry: ${REFRESH_TOKEN_EXPIRY}`);
    console.log(`INFO: Database file located at ${dbPath}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log("INFO: Received SIGINT. Closing database connection...");
    db.close((err) => {
        if (err) { console.error("Error closing database:", err.message); }
        else { console.log("INFO: Database connection closed successfully."); }
        process.exit(err ? 1 : 0);
    });
});
