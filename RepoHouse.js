// server.js

const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/messaging_app', { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;
db.once('open', () => {
    console.log('Connected to MongoDB');
});
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

// User model
const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String
});
const User = mongoose.model('User', userSchema);

// Message model
const messageSchema = new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    content: String,
    media: String, // For storing file paths
    createdAt: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

// Authentication endpoints
app.post('/api/register', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = new User({
            username: req.body.username,
            email: req.body.email,
            password: hashedPassword
        });
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

app.post('/api/login', async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
        return res.status(401).json({ error: 'User not found' });
    }
    try {
        if (await bcrypt.compare(req.body.password, user.password)) {
            const accessToken = jwt.sign({ userId: user._id }, 'secret');
            res.status(200).json({ accessToken });
        } else {
            res.status(401).json({ error: 'Invalid password' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    jwt.verify(token, 'secret', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        req.user = user;
        next();
    });
}

// File uploading
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function(req, file, cb) {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
    res.json({ file: req.file });
});

// Real-time messaging with Socket.io
const http = require('http').createServer(app);
const io = require('socket.io')(http);

io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (token) {
        jwt.verify(token, 'secret', (err, decoded) => {
            if (err) return next(new Error('Authentication error'));
            socket.userId = decoded.userId;
            next();
        });
    } else {
        return next(new Error('Authentication error'));
    }
}).on('connection', async (socket) => {
    console.log('User connected: ' + socket.userId);

    // Join a room based on user ID
    socket.join(socket.userId);

    // Listen for new messages
    socket.on('new message', async (data) => {
        try {
            const message = new Message({
                sender: socket.userId,
                content: data.content,
                media: data.media // Store file path or URL
            });
            await message.save();
            // Broadcast the new message to all users in the room
            io.to(socket.userId).emit('new message', message);
        } catch (error) {
            console.error(error);
        }
    });

    // Handle disconnect
    socket.on('disconnect', () => {
        console.log('User disconnected: ' + socket.userId);
        socket.leave(socket.userId);
    });
});

// Get all messages
app.get('/api/messages', authenticateToken, async (req, res) => {
    try {
        const messages = await Message.find().populate('sender', 'username');
        res.json({ messages });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

http.listen(3000, () => {
    console.log('Server is running on port 3000');
});