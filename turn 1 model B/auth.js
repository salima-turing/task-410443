// Assuming you have express & jsonwebtoken modules installed
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

const secretKey = 'your-super-secret-key';

app.post('/login', (req, res) => {
    // Assuming your login API handles credentials validation
    // For demonstration, we'll use a static username and password
    console.log(req.body);
    const { username, password } = req.body;
    if (username === 'test' && password === 'test') {
        // Generate a token if credentials are valid
        const payload = {
            username: 'test',
            id: 'user123',
            roles: ['admin']
        };

        const token = jwt.sign(payload, secretKey, { expiresIn: '1h' });

        res.json({ token });
    } else {
        res.status(401).json({ message: 'Invalid credentials' });
    }
});

app.get('/protected-route', (req, res) => {
    // Verify the token in the request header
    const token = req.header('Authorization').replace('Bearer ', '');

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token is invalid' });
        }

        res.json({ message: 'Welcome to the protected route', user: decoded });
    });
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
