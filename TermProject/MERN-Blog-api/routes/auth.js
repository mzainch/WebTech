const router = require('express').Router();
const User = require('../models/User');
const bcrypt = require('bcrypt');

// REGISTER
router.post('/register', async (req, res) => {
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);
        const { username, email } = req.body;

        const newUser = new User({
            username,
            password: hashedPassword,
            email,
        });

        const user = await newUser.save();
        res.status(200).json(user);
    } catch (err) {
        // Ensure that only one response is sent
        if (res.headersSent) {
            console.error('Headers already sent, cannot send error response.');
        } else {
            if (err.code === 11000) {
                // MongoDB duplicate key error
                res.status(400).json({ error: 'Username or email already exists.' });
            } else {
                res.status(500).json({ error: 'Internal server error.' });
            }
        }
    }
});

// LOGIN
router.post("/login", async (req, res) => {
    console.log("request came")
    try {
        const user = await User.findOne({ username: req.body.username });

        if (!user) {
            return res.status(400).json({ error: 'Wrong credentials!' });
        }

        const validated = await bcrypt.compare(req.body.password, user.password);
        if (!validated) {
            return res.status(400).json({ error: 'Wrong credentials!' });
        }

        const { password, ...others } = user._doc;
        res.status(200).json(others);
    } catch (err) {
        // Ensure that only one response is sent
        if (!res.headersSent) {
            res.status(500).json({ error: 'Internal server error.' });
        } else {
            console.error('Headers already sent, cannot send error response.');
        }
    }
});

module.exports = router;
