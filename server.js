const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const { findUserByEmail, pool } = require('./db'); // Import findUserByEmail and pool from your db module
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());
const PORT = 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'your_secret_key';

app.use(bodyParser.json());

app.post('/register', async (req, res) => {
    const { username, password, email, firstName, lastName, phone } = req.body;
    if (!username || !password || !email || !firstName || !lastName || !phone) {
        return res.status(400).json({ message: 'Username, password, email, firstname, lastname, phone are required ' });
    }

    try {
        const userCheckQuery = 'SELECT * FROM users WHERE username = ? OR email = ?';
        const [userResults] = await pool.query(userCheckQuery, [username, email]);

        if (userResults.length > 0) {
            return res.status(409).json({ message: 'Username or email is already taken' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const insertQuery = 'INSERT INTO users (username, password, email, firstName, lastName, phone) VALUES (?, ?, ?, ?, ?, ?)';
        await pool.query(insertQuery, [username, hashedPassword, email, firstName, lastName, phone]);
        
        console.log('User registered successfully');
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        console.error('Server error:', err);
        res.status(500).json({ message: 'Error processing your request', error: err.message });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try {
        const query = 'SELECT * FROM users WHERE username = ?';
        const [results] = await pool.query(query, [username]);

        if (results.length === 0) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        const user = results[0];
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        const token = jwt.sign({ userId: user.id }, process.env.SECRET_KEY, { expiresIn: '1h' });

        // ส่งกลับข้อมูลผู้ใช้รวมถึง token
        res.json({
            message: 'Login successful',
            token,
            firstName: user.firstName,
            lastName: user.lastName,
            phoneNumber: user.phone
        });
    } catch (err) {
        console.error('Server error:', err);
        res.status(500).json({ message: 'Error processing your request', error: err.message });
    }
});


app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await findUserByEmail(email);
        if (!user) {
            return res.status(404).json({ message: 'No account with that email address exists.' });
        }

        const token = jwt.sign(
            { userId: user.id, email: user.email },
            SECRET_KEY,
            { expiresIn: '1h' }
        );

        const resetLink = `https://adminsure.online/reset-password?token=${token}`;

        let transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_PASS
            }
        });

        let mailOptions = {
            from: `"asminsure.online" <${process.env.GMAIL_USER}>`,
            to: email,
            subject: 'Reset your password',
            html: `<p>กรุณาคลิก <a href="${resetLink}">ที่นี่</a> เพื่อตั้งรหัสผ่านใหม่ ลิงก์นี้จะหมดอายุภายใน 1 ชั่วโมง</p>`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error);
                return res.status(500).json({ message: 'Failed to send email.' });
            }
            console.log('Email sent: %s', info.messageId);
            res.status(200).json({ message: 'Please check your email for the password reset link.' });
        });
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ message: 'Error processing your request.' });
    }
});


app.post('/update-password', async (req, res) => {
    const { token, newPassword } = req.body;

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const userId = decoded.userId;

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const updateQuery = 'UPDATE users SET password = ? WHERE id = ?'; // Ensure your user table has an 'id' column
        await pool.query(updateQuery, [hashedPassword, userId]);

        res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Error updating password:', error);
        res.status(500).json({ message: 'Error updating password' });
    }
});


// Middleware สำหรับการตรวจสอบ JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN_HERE"

    if (token == null) return res.sendStatus(401); // ถ้าไม่มี token ส่ง 401 Unauthorized

    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403); // ส่ง 403 Forbidden ถ้า token ไม่ถูกต้อง
        req.user = user; // เก็บข้อมูล user ที่ได้จาก token ไว้ใน req.user
        next(); // ดำเนินการต่อ
    });
};


app.get('/api/user', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId; // ดึง userId จากข้อมูลที่อยู่ใน token
        const query = 'SELECT firstname, lastname, phone FROM users WHERE id = ?';
        const [results] = await pool.query(query, [userId]);

        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = results[0];
        res.status(200).json(user);
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ message: 'Error fetching user' });
    }
});


app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
