// meds_backend.js - Using SQLite with Multi-Session Refresh Token Authentication
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
// const crypto = require('crypto'); // No longer needed for refresh tokens as JWTs are used

const app = express();
const PORT = process.env.PORT || 3001;

// --- Security Configuration ---
// Access Token: Short-lived, used for most API calls
const DEFAULT_JWT_SECRET = 'FALLBACK_ACCESS_SECRET_CHANGE_ME';
const JWT_SECRET = process.env.JWT_SECRET || DEFAULT_JWT_SECRET;
const DEFAULT_ACCESS_TOKEN_EXPIRY = '45m'; // Increased for better UX during testing, consider 15m-30m for prod
const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || DEFAULT_ACCESS_TOKEN_EXPIRY;

// Refresh Token: Long-lived, used ONLY to get a new access token
const DEFAULT_REFRESH_TOKEN_SECRET = 'FALLBACK_REFRESH_SECRET_CHANGE_ME_TOO';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || DEFAULT_REFRESH_TOKEN_SECRET;
const DEFAULT_REFRESH_TOKEN_EXPIRY = '28d'; // e.g., 28 days
const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || DEFAULT_REFRESH_TOKEN_EXPIRY;

// --- Logging Security Configuration ---
console.log("--- Security Configuration ---");
console.log(`INFO: JWT_SECRET: ${process.env.JWT_SECRET ? 'Loaded from environment variable.' : `Using default fallback (SECURITY RISK!).`}`);
console.log(`INFO: ACCESS_TOKEN_EXPIRY: ${ACCESS_TOKEN_EXPIRY} (${process.env.ACCESS_TOKEN_EXPIRY ? 'from environment variable' : 'using default fallback'})`);
console.log(`INFO: REFRESH_TOKEN_SECRET: ${process.env.REFRESH_TOKEN_SECRET ? 'Loaded from environment variable.' : `Using default fallback (SECURITY RISK!).`}`);
console.log(`INFO: REFRESH_TOKEN_EXPIRY: ${REFRESH_TOKEN_EXPIRY} (${process.env.REFRESH_TOKEN_EXPIRY ? 'from environment variable' : 'using default fallback'})`);
console.log("-----------------------------");

// --- Database Setup ---
const dbPath = path.resolve('/data', 'meds.db'); // Ensure this path is persistent
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
        // Enable foreign key constraints
        db.run("PRAGMA foreign_keys = ON;", (pragmaErr) => {
            if (pragmaErr) console.error("Error enabling foreign keys:", pragmaErr.message);
            else console.log("INFO: Foreign key support enabled.");
            createTables(); // Create tables after enabling FKs
        });
    }
});

// --- Create Database Tables ---
// Updated createTables function for multi-session support
function createTables() {
    db.serialize(() => {
        // Users table (no refresh token column needed here anymore)
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `, (err) => {
            if (err) console.error("Error creating users table:", err.message);
            else console.log("INFO: 'users' table checked/created.");
            // Attempt to drop the old refresh_token column if migrating (optional, can be noisy)
            // db.run("ALTER TABLE users DROP COLUMN refresh_token", (dropErr) => {
            //     if (dropErr && !dropErr.message.includes('no such column')) {
            //         console.warn("Could not drop old refresh_token column (might not exist):", dropErr.message);
            //     } else if (!dropErr) {
            //         console.log("INFO: Removed old 'refresh_token' column from 'users' table.");
            //     }
            // });
        });

        // NEW: Table to store multiple refresh tokens per user
        db.run(`
            CREATE TABLE IF NOT EXISTS user_refresh_tokens (
                token_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE, -- The actual refresh token JWT
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                -- Optional: Add device info (e.g., user agent) here if needed
                -- device_info TEXT,
                FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE -- Delete tokens if user is deleted
            )
        `, (err) => {
            if (err) console.error("Error creating user_refresh_tokens table:", err.message);
            else console.log("INFO: 'user_refresh_tokens' table checked/created.");
        });

        // Index for faster token lookup by user_id
        db.run(`CREATE INDEX IF NOT EXISTS idx_user_refresh_tokens_user_id ON user_refresh_tokens(user_id);`, (err) => {
             if (err) console.error("Error creating index on user_refresh_tokens:", err.message);
             else console.log("INFO: Index on 'user_refresh_tokens (user_id)' checked/created.");
        });

        // Med Data table (unchanged)
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
    allowedHeaders: "Content-Type, Authorization", // Ensure Authorization is allowed
    credentials: true,
    optionsSuccessStatus: 204
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Handle preflight requests for all routes
app.use(bodyParser.json());

// --- Authentication Middleware (authenticateToken) ---
// Verifies the ACCESS token (remains the same)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) {
        // console.log("Auth middleware: No token provided"); // Reduce noise
        return res.status(401).json({ error: 'No token provided' }); // Unauthorized
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            // console.log("Auth middleware: JWT verification failed:", err.message); // Reduce noise
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ error: 'Token expired' }); // Specific error for expired token
            }
            if (err.name === 'JsonWebTokenError') {
                 return res.status(403).json({ error: 'Invalid token' }); // Forbidden - Malformed token
            }
             // Other verification errors (e.g., signature mismatch)
             return res.status(403).json({ error: 'Token verification failed' }); // Forbidden
        }
        // Add user payload to request
        if (!user || !user.userId || !user.username) {
            console.error("Auth middleware: Invalid token payload structure:", user);
            return res.status(403).json({ error: 'Invalid token payload' }); // Forbidden
        }
        req.user = user; // Contains { userId, username }
        // console.log(`Auth middleware: Access Token verified for user ${user.username} (ID: ${user.userId})`); // Reduce noise
        next();
    });
};

// --- API Routes ---

// POST /api/auth/register (Mostly unchanged, ensures med_data initialization)
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    console.log(`Registration attempt for username: ${username}`);
    if (!username || !password || typeof username !== 'string' || typeof password !== 'string' || password.length < 4) {
        return res.status(400).json({ error: 'Username and a password (min 4 chars) are required' });
    }

    // Check if username already exists
    db.get("SELECT user_id FROM users WHERE username = ?", [username], async (err, row) => {
        if (err) {
            console.error("DB error checking username:", err.message);
            return res.status(500).json({ error: 'Database error during registration check' });
        }
        if (row) {
            console.log(`Registration failed: Username ${username} already exists`);
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash password and insert user
        try {
            const saltRounds = 10;
            const passwordHash = await bcrypt.hash(password, saltRounds);

            db.run("INSERT INTO users (username, password_hash) VALUES (?, ?)", [username, passwordHash], function (insertUserErr) {
                if (insertUserErr) {
                    console.error("DB error inserting user:", insertUserErr.message);
                    return res.status(500).json({ error: 'Failed to register user due to database error' });
                }
                const newUserId = this.lastID;
                console.log(`User registered successfully: ${username} (ID: ${newUserId})`);

                // Initialize med_data for the new user
                db.run("INSERT INTO med_data (user_id, shot_history, settings) VALUES (?, ?, ?)",
                    [newUserId, JSON.stringify([]), JSON.stringify({})], // Start with empty data
                    (initMedDataErr) => {
                        if (initMedDataErr) {
                            // Log error but don't necessarily fail registration if this part fails
                            console.error(`DB error initializing med_data for user ID ${newUserId}:`, initMedDataErr.message);
                        } else {
                            console.log(`Initialized med_data for user ID ${newUserId}`);
                        }
                        // Send success response regardless of med_data initialization outcome (user exists)
                        res.status(201).json({ message: 'User registered successfully' });
                    }
                );
            });
        } catch (hashError) {
            console.error("Registration bcrypt error:", hashError);
            res.status(500).json({ error: 'Failed to register user due to server error' });
        }
    });
});

// POST /api/auth/login (UPDATED for multi-session)
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    console.log(`Login attempt for username: ${username}`);
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    // Find user by username
    db.get("SELECT user_id, username, password_hash FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) {
            console.error("DB error finding user:", err.message);
            return res.status(500).json({ error: 'Login failed due to database error' });
        }
        if (!user) {
            console.log(`Login failed: User ${username} not found`);
            return res.status(401).json({ error: 'Invalid credentials' }); // Use 401 Unauthorized
        }

        // Compare provided password with stored hash
        try {
            const match = await bcrypt.compare(password, user.password_hash);
            if (match) {
                // --- Generate Tokens ---
                const userPayload = { userId: user.user_id, username: user.username };
                const accessToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });

                // Refresh token payload only needs userId (keeps it smaller)
                const refreshTokenPayload = { userId: user.user_id };
                const refreshToken = jwt.sign(refreshTokenPayload, REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });

                // --- Store NEW Refresh Token in the dedicated table ---
                db.run("INSERT INTO user_refresh_tokens (user_id, token) VALUES (?, ?)",
                    [user.user_id, refreshToken],
                    (insertTokenErr) => {
                        if (insertTokenErr) {
                            console.error(`DB error storing refresh token for user ${user.username}:`, insertTokenErr.message);
                            // If token insertion fails, don't let the user log in with potentially unusable tokens
                            return res.status(500).json({ error: 'Login failed during session setup.' });
                        }
                        console.log(`User logged in successfully: ${username} (ID: ${user.user_id}). New refresh token stored.`);

                        // --- Send Both Tokens to Frontend ---
                        res.json({
                            accessToken: accessToken,
                            refreshToken: refreshToken // Send the newly generated refresh token
                        });
                    }
                );
            } else {
                console.log(`Login failed: Invalid password for user ${username}`);
                res.status(401).json({ error: 'Invalid credentials' }); // Use 401 Unauthorized
            }
        } catch (error) {
            console.error("Login bcrypt/jwt/db error:", error);
            res.status(500).json({ error: 'Login failed due to server error' });
        }
    });
});

// POST /api/auth/refresh (UPDATED for multi-session)
app.post('/api/auth/refresh', (req, res) => {
    const { refreshToken } = req.body;
    // console.log("Refresh token attempt received."); // Reduce noise

    if (!refreshToken) {
        // console.log("Refresh failed: No refresh token provided."); // Reduce noise
        return res.status(401).json({ error: 'Refresh token required' });
    }

    // 1. Verify the JWT signature and expiry of the refresh token
    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            // This catches expired tokens, invalid signatures, etc.
            console.log("Refresh failed: Refresh token verification failed:", err.message);
            // 403 Forbidden is appropriate as the token is invalid/expired
            return res.status(403).json({ error: 'Invalid or expired refresh token. Please log in again.' });
        }

        const userId = decoded.userId;
        if (!userId) {
             console.log("Refresh failed: Invalid payload in refresh token (missing userId).");
             return res.status(403).json({ error: 'Invalid refresh token payload.' });
        }

        // 2. Check if the token exists in our database (it hasn't been revoked/logged out)
        db.get("SELECT token_id FROM user_refresh_tokens WHERE token = ? AND user_id = ?",
            [refreshToken, userId],
            (dbErr, tokenRow) => {
                if (dbErr) {
                    console.error(`DB error checking refresh token validity for user ${userId}:`, dbErr.message);
                    return res.status(500).json({ error: 'Server error during token refresh.' });
                }
                if (!tokenRow) {
                    // Token is valid JWT, but not in our DB (likely logged out or invalidated)
                    console.log(`Refresh failed: Refresh token for user ${userId} not found in database (revoked?).`);
                    // Send 403 Forbidden as the token is no longer authorized
                    return res.status(403).json({ error: 'Refresh token has been invalidated. Please log in again.' });
                }

                // 3. Refresh token is valid and exists in DB. Get user info to create new access token.
                db.get("SELECT user_id, username FROM users WHERE user_id = ?", [userId], (userErr, user) => {
                    if (userErr) {
                        console.error(`DB error finding user ${userId} for refresh payload:`, userErr.message);
                        return res.status(500).json({ error: 'Server error retrieving user details.' });
                    }
                    if (!user) {
                        // Should not happen if FK constraints are working, but good to check
                        console.log(`Refresh failed: User ${userId} associated with valid token not found.`);
                        // Invalidate the token as the user doesn't exist anymore
                        db.run("DELETE FROM user_refresh_tokens WHERE token = ?", [refreshToken], (delErr) => {
                             if(delErr) console.error("Error deleting orphaned refresh token:", delErr.message);
                        });
                        return res.status(403).json({ error: 'User associated with token not found.' });
                    }

                    // --- Issue a new Access Token ---
                    const userPayload = { userId: user.user_id, username: user.username };
                    const newAccessToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });

                    console.log(`Token refreshed successfully for user ${user.username} (ID: ${userId})`);
                    res.json({ accessToken: newAccessToken });
                }); // End get user for payload
            } // End check token exists in DB
        ); // End db.get check token
    }); // End jwt.verify
});

// POST /api/auth/logout (UPDATED for multi-session)
// Requires the specific refresh token to be logged out
// Still protected by the Access Token to ensure the user is authenticated
app.post('/api/auth/logout', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const username = req.user.username;
    const { refreshToken } = req.body; // ** Frontend MUST send the refresh token to be invalidated **

    console.log(`Logout request for user: ${username} (ID: ${userId})`);

    if (!refreshToken) {
        console.log(`Logout failed for user ${userId}: No refresh token provided in request body.`);
        // Cannot logout a specific session without its token
        return res.status(400).json({ error: 'Refresh token is required to log out this session.' });
    }

    // Delete the specific refresh token from the database
    db.run("DELETE FROM user_refresh_tokens WHERE token = ? AND user_id = ?",
        [refreshToken, userId],
        function(err) { // Use function() to access this.changes
            if (err) {
                console.error(`DB error deleting refresh token for user ${userId}:`, err.message);
                return res.status(500).json({ error: 'Server error during logout process.' });
            }

            if (this.changes === 0) {
                // Token wasn't found for this user (maybe already logged out or invalid token sent)
                console.log(`Logout warning for user ${userId}: Refresh token provided was not found or did not belong to the user.`);
                // Still return success as the goal is to be logged out, and this session effectively is.
                res.status(200).json({ message: 'Session not found or already logged out.' });
            } else {
                console.log(`Refresh token invalidated successfully for user ${username} (ID: ${userId}).`);
                res.status(200).json({ message: 'Logged out successfully.' });
            }
        }
    );
});

// POST /api/auth/change-password (UPDATED for multi-session)
// Invalidates ALL refresh tokens for the user upon successful password change
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
    const username = req.user.username;
    const userId = req.user.userId;
    const { currentPassword, newPassword } = req.body;
    console.log(`Password change attempt for user: ${username} (ID: ${userId})`);

    if (!currentPassword || !newPassword || typeof newPassword !== 'string' || newPassword.length < 4) {
        return res.status(400).json({ error: 'Current password and new password (min 4 chars) are required.' });
    }

    // 1. Get current password hash
    db.get("SELECT password_hash FROM users WHERE user_id = ?", [userId], async (err, user) => {
        if (err) {
            console.error("DB error finding user for pwd change:", err.message);
            return res.status(500).json({ error: 'Failed to process request due to database error.' });
        }
        if (!user) {
            // Should not happen if authenticateToken worked, but check anyway
            return res.status(404).json({ error: 'User not found.' });
        }

        try {
            // 2. Verify current password
            const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
            if (!isMatch) {
                console.log(`Password change failed for ${username}: Incorrect current password.`);
                return res.status(401).json({ error: 'Incorrect current password.' }); // 401 Unauthorized
            }

            // 3. Hash the new password
            const saltRounds = 10;
            const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

            // 4. Use a transaction to update password AND delete all refresh tokens
            db.serialize(() => {
                db.run("BEGIN TRANSACTION;", (beginErr) => {
                     if (beginErr) { console.error(`Begin transaction failed for pwd change ${username}:`, beginErr.message); return res.status(500).json({ error: 'Failed to start password update process.' }); }

                     let transactionSuccess = true; // Flag to track transaction steps

                     // Step A: Update the password hash
                     db.run("UPDATE users SET password_hash = ? WHERE user_id = ?", [newPasswordHash, userId], function (updateErr) {
                         if (updateErr) {
                             console.error(`DB error updating password for ${username}:`, updateErr.message);
                             transactionSuccess = false;
                         } else if (this.changes === 0) {
                             // Should not happen if user was found earlier
                             console.error(`Pwd change failed: No rows updated for user ID ${userId}.`);
                             transactionSuccess = false;
                         } else {
                              console.log(`Password hash updated for user ${username}.`);
                         }
                     });

                     // Step B: Delete ALL refresh tokens for this user
                     db.run("DELETE FROM user_refresh_tokens WHERE user_id = ?", [userId], function (deleteErr) {
                          if (deleteErr) {
                              console.error(`DB error deleting refresh tokens after pwd change for ${username}:`, deleteErr.message);
                              transactionSuccess = false; // Mark transaction as failed
                          } else {
                               console.log(`Deleted ${this.changes} refresh tokens for user ${username} after password change.`);
                          }
                     });

                     // Step C: Commit or Rollback
                     const finalAction = transactionSuccess ? "COMMIT;" : "ROLLBACK;";
                     db.run(finalAction, (commitRollbackErr) => {
                         if (commitRollbackErr) {
                             console.error(`DB ${finalAction} error during pwd change for ${username}:`, commitRollbackErr.message);
                             // If commit/rollback fails, the state is uncertain, return server error
                             return res.status(500).json({ error: 'Failed to finalize password update due to transaction error.' });
                         }

                         if (transactionSuccess) {
                             console.log(`Password changed successfully for user: ${username}. All sessions invalidated.`);
                             res.status(200).json({ message: 'Password changed successfully. All active sessions have been logged out.' });
                         } else {
                             console.log(`Password change transaction rolled back for user: ${username}.`);
                             res.status(500).json({ error: 'Failed to update password or clear sessions.' });
                         }
                     }); // End Commit/Rollback run
                }); // End Begin Transaction
            }); // End serialize

        } catch (error) {
            console.error(`Password change bcrypt/db error for ${username}:`, error);
            // Attempt rollback if an error occurred outside the transaction block structure (e.g., bcrypt)
            db.run("ROLLBACK;", (rollbackErr) => {
                 if(rollbackErr) console.error("Error attempting rollback after external error:", rollbackErr.message);
            });
            res.status(500).json({ error: 'Failed to process password change due to server error.' });
        }
    }); // End get user
});


// GET /api/meddata - Protected Route (Unchanged)
app.get('/api/meddata', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    // console.log(`Fetching data for user ID: ${userId}`); // Reduce noise
    db.get("SELECT shot_history, settings FROM med_data WHERE user_id = ?", [userId], (err, row) => {
        if (err) {
            console.error(`DB error fetching data for user ID ${userId}:`, err.message);
            return res.status(500).json({ error: "Failed to fetch data" });
        }
        if (row) {
            try {
                // Safely parse JSON, providing defaults if parsing fails or data is null/malformed
                const shotHistory = JSON.parse(row.shot_history || '[]');
                const settings = JSON.parse(row.settings || '{}');

                // Basic validation (optional but good practice)
                if (!Array.isArray(shotHistory)) {
                    console.warn(`Invalid shot_history format for user ${userId}. Resetting to empty array.`);
                    shotHistory = [];
                }
                 if (typeof settings !== 'object' || settings === null) {
                    console.warn(`Invalid settings format for user ${userId}. Resetting to empty object.`);
                    settings = {};
                }

                const medData = {
                    shotHistory: shotHistory,
                    settings: settings
                };
                // console.log(`Data fetched successfully for user ID ${userId}`); // Reduce noise
                res.json(medData);
            } catch (parseError) {
                console.error(`DB error parsing JSON data for user ID ${userId}:`, parseError.message);
                // Return default empty structure if parsing fails
                res.status(500).json({ error: "Failed to parse stored data.", shotHistory: [], settings: {} });
            }
        } else {
            // No data found for user, return empty structure (first time user or data deleted?)
            // console.log(`No med_data found for user ID ${userId}, returning empty.`); // Reduce noise
            res.json({ shotHistory: [], settings: {} });
        }
    });
});

// POST /api/meddata - Protected Route (Unchanged)
app.post('/api/meddata', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const newMedData = req.body;
    // console.log(`Received data update request for user ID: ${userId}`); // Reduce noise

    // Basic validation of incoming data structure
    if (!newMedData || typeof newMedData !== 'object' || !Array.isArray(newMedData.shotHistory) || typeof newMedData.settings !== 'object' || newMedData.settings === null) {
        console.warn(`Invalid data format received for user ${userId}:`, newMedData);
        return res.status(400).json({ error: 'Invalid data format provided' });
    }

    // Optional: Deeper validation of shot history dates
    if (newMedData.shotHistory.some(shot => !shot || !shot.dateTime || isNaN(new Date(shot.dateTime).getTime()))) {
         console.warn(`Invalid date found in shot history for user ${userId}.`);
         return res.status(400).json({ error: 'Invalid date found in shot history.' });
    }

    // Prepare data for DB insertion/update
    const shotHistoryJson = JSON.stringify(newMedData.shotHistory);
    const settingsJson = JSON.stringify(newMedData.settings);
    const currentTime = new Date().toISOString(); // Use ISO format for consistency

    // Use INSERT OR REPLACE (or ON CONFLICT DO UPDATE) to handle existing data
    const sql = `
        INSERT INTO med_data (user_id, shot_history, settings, last_updated)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            shot_history = excluded.shot_history,
            settings = excluded.settings,
            last_updated = excluded.last_updated;
    `;

    db.run(sql, [userId, shotHistoryJson, settingsJson, currentTime], function (err) {
        if (err) {
            console.error(`DB error saving data for user ID ${userId}:`, err.message);
            return res.status(500).json({ error: 'Failed to save data.' });
        }
        // console.log(`Data saved successfully for user ID: ${userId}. Rows affected: ${this.changes}`); // Reduce noise
        res.status(200).json({ message: 'Data saved successfully' });
    });
});


// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Meds backend server running on port ${PORT}`);
    console.log(`Allowing requests from origin: ${corsOptions.origin}`);
    // Security warnings are logged near the top where vars are defined
    console.log(`INFO: Database file located at ${dbPath}`);
});

// --- Graceful Shutdown ---
process.on('SIGINT', () => {
    console.log("\nINFO: Received SIGINT (Ctrl+C). Closing database connection...");
    db.close((err) => {
        if (err) {
            console.error("Error closing database:", err.message);
            process.exit(1); // Exit with error code if DB close fails
        } else {
            console.log("INFO: Database connection closed successfully.");
            process.exit(0); // Exit cleanly
        }
    });
});

// Optional: Handle SIGTERM for graceful shutdown in containers/orchestrators
process.on('SIGTERM', () => {
    console.log("INFO: Received SIGTERM. Closing database connection...");
    db.close((err) => {
        if (err) {
            console.error("Error closing database on SIGTERM:", err.message);
            process.exit(1);
        } else {
            console.log("INFO: Database connection closed successfully on SIGTERM.");
            process.exit(0);
        }
    });
});
