// meds_backend.js - Using SQLite for persistent storage
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose(); // Use verbose for more detailed logs
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001; // Use a different port than the mixer backend
// IMPORTANT: Get secret from environment variable set in docker-compose.yml
// Provide a fallback ONLY for local testing IF NOT running in Docker with env var set.
const JWT_SECRET = process.env.JWT_SECRET || 'FALLBACK_SECRET_CHANGE_ME_IF_NOT_USING_DOCKER_ENV';

// --- Database Setup ---
const dbPath = path.resolve('/data', 'meds.db'); // Store DB in /data directory (mounted volume)
console.log(`INFO: Database path: ${dbPath}`);

// Ensure /data directory exists (Docker volume mount should handle this, but good practice)
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

// Connect to SQLite database
// Using Database#verbose() for better stack traces on errors
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("FATAL: Could not connect to database", err.message);
        process.exit(1); // Exit if DB connection fails
    } else {
        console.log("INFO: Connected to SQLite database.");
        // Use PRAGMA for foreign key support (recommended for SQLite)
        db.run("PRAGMA foreign_keys = ON;", (pragmaErr) => {
            if (pragmaErr) {
                 console.error("Error enabling foreign keys:", pragmaErr.message);
            } else {
                 console.log("INFO: Foreign key support enabled.");
            }
            // Create tables if they don't exist upon startup
            createTables();
        });
    }
});

function createTables() {
     db.serialize(() => {
        // Users table: Stores login credentials
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE, -- Ensure username is unique, case-insensitive
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `, (err) => {
            if (err) console.error("Error creating users table:", err.message);
            else console.log("INFO: 'users' table checked/created.");
        });

        // Medication Data table: Stores data per user
        db.run(`
            CREATE TABLE IF NOT EXISTS med_data (
                data_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE, -- Each user has one row of data
                shot_history TEXT, -- Store as JSON string
                settings TEXT,     -- Store as JSON string
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE -- Delete data if user deleted
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
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS", // Allow methods including OPTIONS
  allowedHeaders: "Content-Type, Authorization", // Allow necessary headers
  optionsSuccessStatus: 204 // Return 204 for preflight OPTIONS requests
};
app.use(cors(corsOptions)); // Use configured CORS for all routes
// Explicitly handle OPTIONS preflight requests for all routes
app.options('*', cors(corsOptions));
app.use(bodyParser.json()); // Parse JSON request bodies


// --- Authentication Middleware ---
// Checks for a valid JWT in the Authorization header
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) {
        console.log("Auth middleware: No token provided");
        return res.sendStatus(401); // if no token, unauthorized
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log("Auth middleware: JWT verification failed:", err.message);
            // Handle specific errors like expired token if needed
            if (err.name === 'TokenExpiredError') {
                 return res.status(401).json({ error: 'Token expired' }); // Use 401 for expired token
            }
            return res.sendStatus(403); // if token is invalid, forbidden
        }
        // Add user payload (e.g., { username: 'rose', userId: 1 }) to the request object
        // Ensure the payload contains what you need (set during login)
        if (!user || !user.userId || !user.username) {
             console.error("Auth middleware: Invalid token payload structure:", user);
             return res.sendStatus(403); // Invalid payload
        }
        req.user = user;
        console.log(`Auth middleware: Token verified for user ${user.username} (ID: ${user.userId})`);
        next(); // Proceed to the next middleware or route handler
    });
};


// --- API Routes ---

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    console.log(`Registration attempt for username: ${username}`);
    // Basic validation
    if (!username || !password || typeof username !== 'string' || typeof password !== 'string' || password.length < 4) {
        return res.status(400).json({ error: 'Username and a password (min 4 chars) are required' });
    }

    // Check if user exists (case-insensitive due to COLLATE NOCASE)
    db.get("SELECT user_id FROM users WHERE username = ?", [username], async (err, row) => {
        if (err) { console.error("DB error checking username:", err.message); return res.status(500).json({ error: 'Database error during registration check' }); }
        if (row) { console.log(`Registration failed: Username ${username} already exists`); return res.status(400).json({ error: 'Username already exists' }); }

        // Hash password and insert user
        try {
            const saltRounds = 10;
            const passwordHash = await bcrypt.hash(password, saltRounds);
            db.run("INSERT INTO users (username, password_hash) VALUES (?, ?)", [username, passwordHash], function(err) {
                if (err) { console.error("DB error inserting user:", err.message); return res.status(500).json({ error: 'Failed to register user due to database error' }); }
                const newUserId = this.lastID;
                console.log(`User registered successfully: ${username} (ID: ${newUserId})`);
                // Initialize med_data row for the new user
                const initialShotHistory = JSON.stringify([]);
                const initialSettings = JSON.stringify({});
                db.run("INSERT INTO med_data (user_id, shot_history, settings) VALUES (?, ?, ?)",
                    [newUserId, initialShotHistory, initialSettings],
                    (initErr) => {
                         if (initErr) { console.error(`DB error initializing med_data for user ID ${newUserId}:`, initErr.message); /* Continue registration anyway */ }
                         else { console.log(`Initialized med_data for user ID ${newUserId}`); }
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

    // Find user (case-insensitive)
    db.get("SELECT user_id, username, password_hash FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) { console.error("DB error finding user:", err.message); return res.status(500).json({ error: 'Login failed due to database error' }); }
        if (!user) { console.log(`Login failed: User ${username} not found`); return res.status(401).json({ error: 'Invalid credentials' }); }

        try {
            // Compare provided password with stored hash
            const match = await bcrypt.compare(password, user.password_hash);
            if (match) {
                // Passwords match - Generate JWT including user_id
                const userPayload = { userId: user.user_id, username: user.username };
                const accessToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '1h' }); // Expires in 1 hour
                console.log(`User logged in successfully: ${username} (ID: ${user.user_id})`);
                res.json({ accessToken: accessToken });
            } else {
                console.log(`Login failed: Invalid password for user ${username}`);
                res.status(401).json({ error: 'Invalid credentials' });
            }
        } catch (error) {
            console.error("Login bcrypt error:", error);
            res.status(500).json({ error: 'Login failed due to server error' });
        }
    });
});

// POST /api/auth/change-password - Protected Route
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
    const username = req.user.username; // Get username from verified token
    const userId = req.user.userId;     // Get userId from verified token
    const { currentPassword, newPassword } = req.body;

    console.log(`Password change attempt for user: ${username} (ID: ${userId})`);

    // Validation
    if (!currentPassword || !newPassword || typeof newPassword !== 'string' || newPassword.length < 4) {
        console.log(`Password change failed for ${username}: Invalid input`);
        return res.status(400).json({ error: 'Current password and new password (min 4 chars) are required.' });
    }

    // Get current hash from DB
    db.get("SELECT password_hash FROM users WHERE user_id = ?", [userId], async (err, user) => {
         if (err) { console.error("DB error finding user for pwd change:", err.message); return res.status(500).json({ error: 'Failed to process request.' }); }
         // Check if user exists (shouldn't happen if token is valid, but check anyway)
         if (!user) { console.error(`Pwd change failed: User ID ${userId} from token not found.`); return res.status(404).json({ error: 'User not found.' }); }

        try {
            // Verify current password
            const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
            if (!isMatch) {
                console.log(`Password change failed for ${username}: Current password incorrect.`);
                return res.status(401).json({ error: 'Incorrect current password.' });
            }

            // Hash the new password
            const saltRounds = 10;
            const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

            // Update the hash in the database
            db.run("UPDATE users SET password_hash = ? WHERE user_id = ?", [newPasswordHash, userId], function(err) {
                if (err) { console.error(`DB error updating password for ${username}:`, err.message); return res.status(500).json({ error: 'Failed to update password.' }); }
                if (this.changes === 0) { console.error(`Pwd change failed: No rows updated for user ID ${userId}.`); return res.status(404).json({ error: 'User not found during update.' }); } // Safety check

                console.log(`Password changed successfully for user: ${username}`);
                res.status(200).json({ message: 'Password changed successfully.' });
            });
        } catch (error) {
            console.error(`Password change bcrypt/db error for ${username}:`, error);
            res.status(500).json({ error: 'Failed to process password change.' });
        }
    });
});


// GET /api/meddata - Protected Route
app.get('/api/meddata', authenticateToken, (req, res) => {
    const userId = req.user.userId; // Get userId from token
    console.log(`Fetching data for user ID: ${userId}`);

    db.get("SELECT shot_history, settings FROM med_data WHERE user_id = ?", [userId], (err, row) => {
        if (err) { console.error(`DB error fetching data for user ID ${userId}:`, err.message); return res.status(500).json({ error: "Failed to fetch data" }); }

        if (row) {
            try {
                // Parse the JSON strings back into objects/arrays
                const medData = {
                    shotHistory: JSON.parse(row.shot_history || '[]'),
                    settings: JSON.parse(row.settings || '{}')
                };
                console.log(`Data fetched successfully for user ID ${userId}`);
                res.json(medData);
            } catch (parseError) {
                 console.error(`DB error parsing data for user ID ${userId}:`, parseError.message);
                 // Return empty data if parsing fails to prevent frontend errors
                 res.json({ shotHistory: [], settings: {} });
            }
        } else {
            // No data found for this user yet, return empty structure
            console.log(`No med_data found for user ID ${userId}, returning empty.`);
            res.json({ shotHistory: [], settings: {} });
        }
    });
});

// POST /api/meddata - Protected Route
app.post('/api/meddata', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const newMedData = req.body;
    console.log(`Received data update request for user ID: ${userId}`);

    // Validation
    if (!newMedData || typeof newMedData !== 'object' || !Array.isArray(newMedData.shotHistory) || typeof newMedData.settings !== 'object') {
        console.log(`Save failed for user ID ${userId}: Invalid data format.`);
        return res.status(400).json({ error: 'Invalid data format provided' });
    }
    // Basic validation of dates within shotHistory before saving
    if (newMedData.shotHistory.some(shot => !shot || !shot.dateTime || isNaN(new Date(shot.dateTime).getTime()))) {
         console.log(`Save failed for user ID ${userId}: Invalid date found in shot history.`);
         return res.status(400).json({ error: 'Invalid date found in shot history.' });
    }

    // Stringify data for storage
    const shotHistoryJson = JSON.stringify(newMedData.shotHistory);
    const settingsJson = JSON.stringify(newMedData.settings);
    const currentTime = new Date().toISOString();

    // Use UPSERT logic: Insert or Replace based on user_id constraint
    // (ON CONFLICT requires SQLite 3.24.0+)
    // Alternatively, use INSERT OR IGNORE for user_id, then UPDATE.
    // Simpler UPSERT:
    const sql = `
        INSERT INTO med_data (user_id, shot_history, settings, last_updated)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            shot_history = excluded.shot_history,
            settings = excluded.settings,
            last_updated = excluded.last_updated;
    `;

    db.run(sql, [userId, shotHistoryJson, settingsJson, currentTime], function(err) {
        if (err) {
            console.error(`DB error saving data for user ID ${userId}:`, err.message);
            return res.status(500).json({ error: 'Failed to save data.' });
        }
        console.log(`Data saved successfully for user ID: ${userId}. Rows affected: ${this.changes}`);
        res.status(200).json({ message: 'Data saved successfully' });
    });
});


// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Meds backend server running on port ${PORT}`);
    console.log(`Allowing requests from origin: ${corsOptions.origin}`);
    if (!process.env.JWT_SECRET && JWT_SECRET === 'FALLBACK_SECRET_CHANGE_ME_IF_NOT_USING_DOCKER_ENV') { console.error("SECURITY WARNING: Default fallback JWT_SECRET is used!"); }
    else if (!process.env.JWT_SECRET && JWT_SECRET.startsWith('YOUR_REALLY_SECRET_KEY')) { console.error("SECURITY WARNING: Placeholder JWT_SECRET is used! Set via environment variable."); }
    else if (!process.env.JWT_SECRET){ console.warn("WARNING: JWT_SECRET is not set via environment variable. Using fallback from code."); }
    // Removed in-memory warning, added DB path info
    console.log(`INFO: Database file located at ${dbPath}`);
});

// Graceful shutdown - close the database connection
process.on('SIGINT', () => {
    console.log("INFO: Received SIGINT. Closing database connection...");
    db.close((err) => {
        if (err) { console.error("Error closing database:", err.message); }
        else { console.log("INFO: Database connection closed successfully."); }
        process.exit(err ? 1 : 0);
    });
});
