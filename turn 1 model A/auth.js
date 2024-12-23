const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(express.json());

// In-memory user storage for demonstration; in real applications use a database
const users = [];

// Route to register a new user
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });

    res.send('User registered');
});

// Route to login and return a JWT token
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (user && await bcrypt.compare(password, user.password)) {
        // Generate a token
        const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).send('Invalid credentials');
    }
});

// Middleware to verify the token
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// An example of a secured route
app.get('/secure-data', authenticateToken, (req, res) => {
    res.json({ message: 'This is secure data', user: req.user });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Authentication service running on port ${PORT}`);
});
