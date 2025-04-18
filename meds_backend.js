    // meds_backend.js
    const express = require('express');
    const bcrypt = require('bcrypt');
    const jwt = require('jsonwebtoken');
    const cors = require('cors'); // Require the cors package
    const bodyParser = require('body-parser');

    const app = express();
    const PORT = process.env.PORT || 3001;
    const JWT_SECRET = process.env.JWT_SECRET || 'YOUR_REALLY_SECRET_KEY_CHANGE_ME!'; // Get secret from env or fallback (CHANGE FALLBACK)

    // --- Middleware ---

    // **Explicit CORS Configuration**
    const corsOptions = {
      origin: 'https://rosiesite.rosestuffs.org', // Allow only your frontend domain
      methods: "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS", // Add OPTIONS
      allowedHeaders: "Content-Type, Authorization", // Allow necessary headers
      optionsSuccessStatus: 204 // Return 204 for preflight OPTIONS requests
    };
    // Use configured CORS for all routes
    app.use(cors(corsOptions));
    // Explicitly handle OPTIONS preflight requests for all routes
    app.options('*', cors(corsOptions)); // Enable pre-flight across-the-board

    app.use(bodyParser.json()); // Parse JSON request bodies

    // --- In-Memory Data Store (TEMPORARY - Replace with Database!) ---
    const users = {};

    // --- Authentication Middleware ---
    const authenticateToken = (req, res, next) => {
        // Handle preflight requests BEFORE authentication check
        // The cors middleware with app.options should handle this, but keeping explicit check just in case
        // if (req.method === 'OPTIONS') {
        //     return next();
        // }

        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        if (token == null) return res.sendStatus(401); // No token

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) { console.log("JWT verification failed:", err.message); return res.sendStatus(403); } // Invalid/expired token
            req.user = user;
            next();
        });
    };

    // --- API Routes ---

    // POST /api/auth/register
    app.post('/api/auth/register', async (req, res) => { /* ... same as before ... */
        const { username, password } = req.body; if (!username || !password || typeof username !== 'string' || typeof password !== 'string' || password.length < 4) { return res.status(400).json({ error: 'Username and a password (min 4 chars) are required' }); } if (users[username]) { return res.status(400).json({ error: 'Username already exists' }); } try { const saltRounds = 10; const passwordHash = await bcrypt.hash(password, saltRounds); users[username] = { passwordHash: passwordHash, medData: { shotHistory: [], settings: {} } }; console.log(`User registered: ${username}`); res.status(201).json({ message: 'User registered successfully' }); } catch (error) { console.error("Registration error:", error); res.status(500).json({ error: 'Failed to register user' }); }
    });

    // POST /api/auth/login
    app.post('/api/auth/login', async (req, res) => { /* ... same as before ... */
        const { username, password } = req.body; if (!username || !password) { return res.status(400).json({ error: 'Username and password are required' }); } const user = users[username]; if (!user) { return res.status(401).json({ error: 'Invalid credentials' }); } try { const match = await bcrypt.compare(password, user.passwordHash); if (match) { const userPayload = { username: username }; const accessToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '1h' }); console.log(`User logged in: ${username}`); res.json({ accessToken: accessToken }); } else { res.status(401).json({ error: 'Invalid credentials' }); } } catch (error) { console.error("Login error:", error); res.status(500).json({ error: 'Login failed' }); }
    });

    // GET /api/meddata - Protected Route
    // Note: authenticateToken middleware runs first
    app.get('/api/meddata', authenticateToken, (req, res) => { /* ... same as before ... */
        const username = req.user.username; const userData = users[username]; if (!userData) { return res.status(404).json({ error: 'User data not found' }); } console.log(`Fetching data for user: ${username}`); res.json(userData.medData || { shotHistory: [], settings: {} });
    });

    // POST /api/meddata - Protected Route
    // Note: authenticateToken middleware runs first
    app.post('/api/meddata', authenticateToken, (req, res) => { /* ... same as before ... */
        const username = req.user.username; const newMedData = req.body; if (!users[username]) { return res.status(404).json({ error: 'User not found' }); } if (!newMedData || typeof newMedData !== 'object' || !Array.isArray(newMedData.shotHistory) || typeof newMedData.settings !== 'object') { return res.status(400).json({ error: 'Invalid data format provided' }); } if (newMedData.shotHistory.some(shot => !shot.dateTime || isNaN(new Date(shot.dateTime).getTime()))) { return res.status(400).json({ error: 'Invalid date found in shot history.' }); } users[username].medData = newMedData; console.log(`Updated data for user: ${username}`); res.status(200).json({ message: 'Data saved successfully' });
    });

    // --- Start Server ---
    app.listen(PORT, () => {
        console.log(`Meds backend server running on port ${PORT}`);
        console.log(`Allowing requests from origin: ${corsOptions.origin}`); // Log allowed origin
        if (!process.env.JWT_SECRET && JWT_SECRET === 'YOUR_REALLY_SECRET_KEY_CHANGE_ME!') { console.error("SECURITY WARNING: Default JWT_SECRET is used!"); }
        console.log("WARNING: Using temporary in-memory storage.");
    });
    
