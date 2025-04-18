// meds_backend.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser'); // Or use express.json() / express.urlencoded()

const app = express();
const PORT = process.env.PORT || 3001; // Use a different port than the mixer backend
const JWT_SECRET = 'YOUR_REALLY_SECRET_KEY_CHANGE_ME!'; // CHANGE THIS to a strong, random secret key!

// --- Middleware ---
app.use(cors()); // Allow requests from your frontend domain
app.use(bodyParser.json()); // Parse JSON request bodies

// --- In-Memory Data Store (TEMPORARY - Replace with Database!) ---
// Structure: { username: { passwordHash: '...', medData: { shotHistory: [], settings: {} } } }
const users = {};

// --- Authentication Middleware ---
// Checks for a valid JWT in the Authorization header
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.sendStatus(401); // if no token, unauthorized

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log("JWT verification failed:", err.message);
            return res.sendStatus(403); // if token is invalid/expired, forbidden
        }
        // Add user payload (e.g., { username: 'rose' }) to the request object
        req.user = user;
        next(); // Proceed to the next middleware or route handler
    });
};


// --- API Routes ---

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    if (users[username]) {
        return res.status(400).json({ error: 'Username already exists' });
    }

    try {
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Store user (TEMPORARY in-memory store)
        users[username] = {
            passwordHash: passwordHash,
            medData: { shotHistory: [], settings: {} } // Initialize empty data
        };

        console.log(`User registered: ${username}`);
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = users[username];
    if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' }); // User not found
    }

    try {
        const match = await bcrypt.compare(password, user.passwordHash);
        if (match) {
            // Passwords match - Generate JWT
            const userPayload = { username: username }; // Include username in token payload
            const accessToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '1h' }); // Token expires in 1 hour

            console.log(`User logged in: ${username}`);
            res.json({ accessToken: accessToken });
        } else {
            // Passwords don't match
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// GET /api/meddata - Protected Route
app.get('/api/meddata', authenticateToken, (req, res) => {
    const username = req.user.username; // Get username from verified token payload
    const userData = users[username];

    if (!userData) {
         // Should not happen if token is valid, but safety check
        return res.status(404).json({ error: 'User data not found' });
    }

    console.log(`Fetching data for user: ${username}`);
    // Return only the medData part
    res.json(userData.medData || { shotHistory: [], settings: {} });
});

// POST /api/meddata - Protected Route
app.post('/api/meddata', authenticateToken, (req, res) => {
    const username = req.user.username;
    const newMedData = req.body; // Expecting { shotHistory: [...], settings: {...} }

    if (!users[username]) {
        return res.status(404).json({ error: 'User not found' });
    }
    if (!newMedData || typeof newMedData !== 'object') {
         return res.status(400).json({ error: 'Invalid data format provided' });
    }

    // Validate structure minimally (you might want more validation)
    if (!Array.isArray(newMedData.shotHistory) || typeof newMedData.settings !== 'object') {
         return res.status(400).json({ error: 'Invalid data structure (missing shotHistory array or settings object)' });
    }


    // Update user's data (TEMPORARY in-memory store)
    users[username].medData = newMedData;

    console.log(`Updated data for user: ${username}`);
    res.status(200).json({ message: 'Data saved successfully' });
});


// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Meds backend server running on port ${PORT}`);
    console.log("WARNING: Using temporary in-memory storage. Data will be lost on restart!");
});
