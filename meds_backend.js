// meds_backend.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'FALLBACK_SECRET_CHANGE_ME_IF_NOT_USING_DOCKER_ENV';

// --- Middleware ---
const corsOptions = {
  origin: 'https://rosiesite.rosestuffs.org',
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS",
  allowedHeaders: "Content-Type, Authorization",
  optionsSuccessStatus: 204
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(bodyParser.json());

// --- In-Memory Data Store (TEMPORARY) ---
const users = {};
console.log("INFO: Using temporary in-memory storage.");

// --- Authentication Middleware ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) { console.log("JWT verification failed:", err.message); return res.sendStatus(403); }
        req.user = user; // Attach user payload ({ username: '...' })
        console.log(`Auth middleware: Token verified for user ${user.username}`);
        next();
    });
};

// --- API Routes ---

// Register
app.post('/api/auth/register', async (req, res) => { /* ... same as before ... */
    const { username, password } = req.body; console.log(`Registration attempt for username: ${username}`); if (!username || !password || typeof username !== 'string' || typeof password !== 'string' || password.length < 4) { console.log("Registration failed: Invalid input"); return res.status(400).json({ error: 'Username and a password (min 4 chars) are required' }); } if (users[username]) { console.log(`Registration failed: Username ${username} already exists`); return res.status(400).json({ error: 'Username already exists' }); } try { const saltRounds = 10; const passwordHash = await bcrypt.hash(password, saltRounds); users[username] = { passwordHash: passwordHash, medData: { shotHistory: [], settings: {} } }; console.log(`User registered successfully: ${username}`); res.status(201).json({ message: 'User registered successfully' }); } catch (error) { console.error("Registration error:", error); res.status(500).json({ error: 'Failed to register user' }); }
});

// Login
app.post('/api/auth/login', async (req, res) => { /* ... same as before ... */
    const { username, password } = req.body; console.log(`Login attempt for username: ${username}`); if (!username || !password) { console.log("Login failed: Missing username or password"); return res.status(400).json({ error: 'Username and password are required' }); } const user = users[username]; if (!user) { console.log(`Login failed: User ${username} not found`); return res.status(401).json({ error: 'Invalid credentials' }); } try { const match = await bcrypt.compare(password, user.passwordHash); if (match) { const userPayload = { username: username }; const accessToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '1h' }); console.log(`User logged in successfully: ${username}`); res.json({ accessToken: accessToken }); } else { console.log(`Login failed: Invalid password for user ${username}`); res.status(401).json({ error: 'Invalid credentials' }); } } catch (error) { console.error("Login error:", error); res.status(500).json({ error: 'Login failed' }); }
});

// **NEW:** Change Password Route (Protected)
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
    const username = req.user.username; // Get username from verified token
    const { currentPassword, newPassword } = req.body;

    console.log(`Password change attempt for user: ${username}`);

    // Validation
    if (!currentPassword || !newPassword || typeof newPassword !== 'string' || newPassword.length < 4) {
        console.log(`Password change failed for ${username}: Invalid input`);
        return res.status(400).json({ error: 'Current password and new password (min 4 chars) are required.' });
    }

    const user = users[username];
    if (!user) {
        // Should not happen if token is valid, but safety check
        console.error(`Password change failed: User ${username} from valid token not found in store.`);
        return res.status(404).json({ error: 'User not found.' });
    }

    try {
        // Verify current password
        const isMatch = await bcrypt.compare(currentPassword, user.passwordHash);
        if (!isMatch) {
            console.log(`Password change failed for ${username}: Current password incorrect.`);
            return res.status(401).json({ error: 'Incorrect current password.' });
        }

        // Hash the new password
        const saltRounds = 10;
        const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

        // Update the stored hash (TEMPORARY in-memory store)
        users[username].passwordHash = newPasswordHash;

        console.log(`Password changed successfully for user: ${username}`);
        res.status(200).json({ message: 'Password changed successfully.' });

    } catch (error) {
        console.error(`Password change error for ${username}:`, error);
        res.status(500).json({ error: 'Failed to change password.' });
    }
});


// GET /api/meddata (Protected)
app.get('/api/meddata', authenticateToken, (req, res) => { /* ... same as before ... */
    const username = req.user.username; const userData = users[username]; if (!userData) { console.error(`Data integrity issue: User ${username} found in token but not in memory store.`); return res.status(404).json({ error: 'User data not found' }); } console.log(`Fetching data for user: ${username}`); res.json(userData.medData || { shotHistory: [], settings: {} });
});

// POST /api/meddata (Protected)
app.post('/api/meddata', authenticateToken, (req, res) => { /* ... same as before ... */
    const username = req.user.username; const newMedData = req.body; console.log(`Received data update request for user: ${username}`); if (!users[username]) { console.error(`Data integrity issue: User ${username} found in token but not in memory store during save.`); return res.status(404).json({ error: 'User not found' }); } if (!newMedData || typeof newMedData !== 'object' || !Array.isArray(newMedData.shotHistory) || typeof newMedData.settings !== 'object') { console.log(`Save failed for ${username}: Invalid data format received.`); return res.status(400).json({ error: 'Invalid data format provided' }); } if (newMedData.shotHistory.some(shot => !shot || !shot.dateTime || isNaN(new Date(shot.dateTime).getTime()))) { console.log(`Save failed for ${username}: Invalid date found in shot history.`); return res.status(400).json({ error: 'Invalid date found in shot history.' }); } users[username].medData = newMedData; console.log(`Updated data successfully for user: ${username}`); res.status(200).json({ message: 'Data saved successfully' });
});

// --- Start Server ---
app.listen(PORT, () => { /* ... same as before ... */
    console.log(`Meds backend server running on port ${PORT}`); console.log(`Allowing requests from origin: ${corsOptions.origin}`); if (!process.env.JWT_SECRET && JWT_SECRET === 'FALLBACK_SECRET_CHANGE_ME_IF_NOT_USING_DOCKER_ENV') { console.error("SECURITY WARNING: Default fallback JWT_SECRET is used! Set via environment variable!"); } else if (!process.env.JWT_SECRET && JWT_SECRET.startsWith('YOUR_REALLY_SECRET_KEY')) { console.error("SECURITY WARNING: Placeholder JWT_SECRET is used! Set via environment variable."); } else if (!process.env.JWT_SECRET){ console.warn("WARNING: JWT_SECRET is not set via environment variable. Using fallback from code."); } console.log("WARNING: Using temporary in-memory storage.");
});
