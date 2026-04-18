require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const http = require('http');  // ← ADD THIS
const socketIo = require('socket.io');  // ← ADD THIS
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { sendOTPEmail } = require('./services/emailService');

const app = express();
app.use(cors());
app.use(helmet());
app.use(express.json());

const server = http.createServer(app);  // ← ADD THIS
const io = socketIo(server, {          // ← ADD THIS
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// DB Configuration
const DB_CONFIG = {
    host: 'host id',
    user: 'username',
    password: 'password',
    database: 'database name'
};

// OTP Store & Failed Attempts
const otpStore = new Map();
const failedAttempts = new Map();

// Helper: DB Connection
async function getDB() {
    return await mysql.createConnection(DB_CONFIG);
}

// SNS Alert
async function sendSNSAlert(email, ip, attempts) {
    const AWS = require('aws-sdk');
    AWS.config.update({ region: 'eu-north-1', accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY });
    const sns = new AWS.SNS();
    try {
        await sns.publish({ Message: `🚨 ${email} failed ${attempts} attempts from ${ip}`, Subject: 'Shorto Alert', TopicArn: process.env.AWS_SNS_TOPIC_ARN }).promise();
        console.log('✅ SNS Alert sent');
    } catch(e) { console.log('SNS Error:', e.message); }
}

// Auth Middleware
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'No token provided' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
        req.user = decoded;
        next();
    } catch(e) {
        return res.status(401).json({ success: false, message: 'Invalid token' });
    }
};

// ========== 1. SEND OTP ==========
app.post('/api/auth/send-otp', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: 'Email required' });
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore.set(email, { otp, verified: false, expiresAt: Date.now() + 600000 });
    try {
        await sendOTPEmail(email, otp);
        console.log(`✅ OTP sent to ${email}: ${otp}`);
        const conn = await getDB();
        await conn.execute('INSERT INTO otp_logs (email, otp_code, purpose) VALUES (?, ?, ?)', [email, otp, 'register']);
        await conn.end();
        res.json({ success: true, message: 'OTP sent to your email!' });
    } catch(e) { res.status(500).json({ success: false, message: 'Email failed' }); }
});

// ========== 2. VERIFY OTP ==========
app.post('/api/auth/verify-otp', (req, res) => {
    const { email, otp } = req.body;
    const s = otpStore.get(email);
    if (!s) return res.status(400).json({ success: false, message: 'OTP expired' });
    if (s.otp !== otp) return res.status(400).json({ success: false, message: 'Invalid OTP' });
    s.verified = true;
    otpStore.set(email, s);
    res.json({ success: true, message: 'OTP verified!' });
});

// ========== 3. COMPLETE REGISTRATION ==========
app.post('/api/auth/complete-registration', async (req, res) => {
    const { email, password, fullname } = req.body;
    const s = otpStore.get(email);
    if (!s || !s.verified) return res.status(400).json({ success: false, message: 'Verify OTP first' });
    try {
        const conn = await getDB();
        const [existing] = await conn.execute('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length > 0) { await conn.end(); return res.status(400).json({ success: false, message: 'Email already registered' }); }
        const hash = await bcrypt.hash(password, 10);
        await conn.execute('INSERT INTO users (email, fullname, password_hash) VALUES (?, ?, ?)', [email, fullname || email.split('@')[0], hash]);
        await conn.end();
        const token = jwt.sign({ email }, process.env.JWT_SECRET || 'secret', { expiresIn: '7d' });
        otpStore.delete(email);
        res.json({ success: true, message: 'Registration complete!', token, user: { email, fullname } });
    } catch(e) { res.status(500).json({ success: false, message: 'Registration failed' }); }
});

// ========== LOGIN (with MFA) ==========
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const ip = req.ip;
    
    const lock = failedAttempts.get(email);
    if (lock && lock.lockUntil > Date.now()) {
        return res.status(423).json({ success: false, message: `Locked for ${Math.ceil((lock.lockUntil - Date.now())/3600000)} hours` });
    }
    
    const conn = await getDB();
    const [users] = await conn.execute('SELECT * FROM users WHERE email = ?', [email]);
    
    if (users.length === 0) { 
        await conn.end(); 
        return res.status(401).json({ success: false, message: 'Invalid credentials' }); 
    }
    
    const valid = await bcrypt.compare(password, users[0].password_hash);
    
    if (!valid) {
        try { 
            await conn.execute('INSERT INTO failed_logins (email, ip_address) VALUES (?, ?)', [email, ip || 'unknown']); 
        } catch(e) {}
        
        const curr = failedAttempts.get(email) || { count: 0 };
        curr.count++;
        if (curr.count >= 3) { 
            curr.lockUntil = Date.now() + 86400000; 
            await sendSNSAlert(email, ip, curr.count); 
        }
        failedAttempts.set(email, curr);
        await conn.end();
        return res.status(401).json({ success: false, message: `Wrong password. ${3-curr.count} attempts left` });
    }
    if (users[0].is_blocked == 1) {
        await conn.end();
        return res.status(403).json({ 
            success: false, 
            message: '❌ Your account has been blocked. Contact support.' 
        });
    } 
    // ✅ Login successful — Generate MFA OTP
    failedAttempts.delete(email);
    
    // Generate 6-digit MFA OTP
    const mfaOTP = Math.floor(100000 + Math.random() * 900000).toString();
    const mfaExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes
    
    // Store MFA OTP (alag se store karo, existing otpStore se interfere nahi hoga)
    const mfaStoreKey = `mfa_${email}`;
    otpStore.set(mfaStoreKey, { 
        otp: mfaOTP, 
        verified: false, 
        expiresAt: mfaExpiry,
        userId: users[0].id,
        fullname: users[0].fullname,
        purpose: 'mfa'
    });
    
    // Send MFA OTP via email
    try {
        await sendOTPEmail(email, mfaOTP);
        console.log(`🔐 MFA OTP sent to ${email}: ${mfaOTP}`);
    } catch(e) {
        console.log('Email send failed:', e.message);
    }
    
    await conn.end();
    
    // Return MFA required response (NO token yet)
    res.json({ 
        success: true, 
        requiresMFA: true,
        email: email,
        message: 'OTP sent to your email for verification'
    });
});

// ========== 5. HEALTH ==========
app.get('/api/health', (req, res) => res.json({ status: 'OK' }));

// ========== GET PROFILE ==========
app.get('/api/auth/profile', authMiddleware, async (req, res) => {
    try {
        const conn = await getDB();
        const [users] = await conn.execute(
            'SELECT id, email, fullname, created_at FROM users WHERE email = ?',
            [req.user.email]
        );
        await conn.end();
        
        if (users.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        res.json({ success: true, user: users[0] });
    } catch(e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ========== GET STATS ==========
app.get('/api/auth/stats', authMiddleware, async (req, res) => {
    try {
        const conn = await getDB();
        
        // Messages sent
        const [sent] = await conn.execute(
            'SELECT COUNT(*) as count FROM flying_messages WHERE sender_email = ?',
            [req.user.email]
        );
        
        // Messages caught
        const [caught] = await conn.execute(
            'SELECT COUNT(*) as count FROM caught_messages WHERE caught_by_email = ?',
            [req.user.email]
        );
        
        // Pending requests
        const [requests] = await conn.execute(
            'SELECT COUNT(*) as count FROM requests WHERE to_email = ? AND status = "pending"',
            [req.user.email]
        );
        
        await conn.end();
        
        res.json({
            success: true,
            stats: {
                sent: sent[0].count,
                caught: caught[0].count,
                requests: requests[0].count,
                flying: 0
            }
        });
    } catch(e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ========== CHANGE PASSWORD ==========
app.put('/api/auth/change-password', authMiddleware, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ success: false, message: 'All fields required' });
    }
    
    if (newPassword.length < 6) {
        return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
    }
    
    try {
        const conn = await getDB();
        const [users] = await conn.execute(
            'SELECT password_hash FROM users WHERE email = ?',
            [req.user.email]
        );
        
        if (users.length === 0) {
            await conn.end();
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        const isValid = await bcrypt.compare(currentPassword, users[0].password_hash);
        if (!isValid) {
            await conn.end();
            return res.status(401).json({ success: false, message: 'Current password is incorrect' });
        }
        
        const newHash = await bcrypt.hash(newPassword, 10);
        await conn.execute(
            'UPDATE users SET password_hash = ? WHERE email = ?',
            [newHash, req.user.email]
        );
        await conn.end();
        
        res.json({ success: true, message: 'Password changed successfully!' });
    } catch(e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ========== 6. SEND FLYING MESSAGE ==========
app.post('/api/messages/send', authMiddleware, async (req, res) => {
    const { text } = req.body;
    if (!text || text.trim().length === 0) return res.status(400).json({ success: false, message: 'Message text required' });
    const messageId = 'msg_' + Date.now() + '_' + Math.random().toString(36).substr(2, 8);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    const conn = await getDB();
    await conn.execute(`INSERT INTO flying_messages (message_id, text, sender_email, sender_name, expires_at, status) VALUES (?, ?, ?, ?, ?, 'flying')`, [messageId, text, req.user.email, 'Anonymous', expiresAt]);
    await conn.end();
    res.json({ success: true, message: '✨ Message released into the sky!', messageId });
});

// ========== 7. GET FLYING MESSAGES (Not own) ==========
app.get('/api/messages/flying', authMiddleware, async (req, res) => {
    const conn = await getDB();
    const [messages] = await conn.execute(`
    SELECT fm.message_id, fm.text, fm.sender_email, fm.created_at, fm.expires_at 
    FROM flying_messages fm
    LEFT JOIN caught_messages cm ON fm.message_id = cm.message_id AND cm.caught_by_email = ?
    WHERE fm.status = 'flying' 
      AND fm.expires_at > NOW() 
      AND fm.sender_email != ?
      AND (cm.message_id IS NULL OR cm.action_taken != 'passed')
    ORDER BY RAND() 
    LIMIT 10
`, [req.user.email, req.user.email]);
    await conn.end();
    res.json({ success: true, count: messages.length, messages });
});

// ========== 8. CATCH MESSAGE ==========
app.post('/api/messages/catch/:messageId', authMiddleware, async (req, res) => {
    const { messageId } = req.params;
    const conn = await getDB();
    const [messages] = await conn.execute('SELECT * FROM flying_messages WHERE message_id = ? AND status = "flying" AND expires_at > NOW() AND sender_email != ?', [messageId, req.user.email]);
    if (messages.length === 0) { await conn.end(); return res.status(404).json({ success: false, message: 'Message not found' }); }
    const message = messages[0];
    await conn.execute('UPDATE flying_messages SET status = "caught" WHERE message_id = ?', [messageId]);
    await conn.execute('INSERT INTO caught_messages (message_id, caught_by_email, caught_by_name, action_taken) VALUES (?, ?, ?, "pending")', [messageId, req.user.email, req.user.email.split('@')[0]]);
    await conn.end();
    res.json({ success: true, message: '🎯 Message caught!', caughtMessage: { text: message.text, message_id: messageId, sender_email: message.sender_email } });
});

// ========== 9. PASS MESSAGE ==========
app.post('/api/messages/pass/:messageId', authMiddleware, async (req, res) => {
    const { messageId } = req.params;
    const conn = await getDB();
    await conn.execute('UPDATE flying_messages SET status = "flying", expires_at = DATE_ADD(NOW(), INTERVAL 24 HOUR) WHERE message_id = ?', [messageId]);
    await conn.execute('UPDATE caught_messages SET action_taken = "passed" WHERE message_id = ? AND caught_by_email = ?', [messageId, req.user.email]);
    await conn.end();
    res.json({ success: true, message: '🕊️ Message passed to another user!' });
});

// ========== 10. SEND REQUEST ==========
app.post('/api/requests/send', authMiddleware, async (req, res) => {
    const { toEmail, messageId, messageText } = req.body;
    const requestId = 'req_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
    const conn = await getDB();
    await conn.execute('INSERT INTO requests (request_id, from_email, to_email, message_id, message_text, status) VALUES (?, ?, ?, ?, ?, "pending")', [requestId, req.user.email, toEmail, messageId, messageText || 'Wants to connect about your flying message']);
    await conn.end();
    res.json({ success: true, message: '🤝 Connection request sent!', requestId });
});

// ========== 11. GET INCOMING REQUESTS ==========
app.get('/api/requests/incoming', authMiddleware, async (req, res) => {
    const conn = await getDB();
    const [requests] = await conn.execute(`SELECT r.request_id, r.from_email, r.message_text, r.status, r.created_at, u.fullname as from_name FROM requests r JOIN users u ON r.from_email = u.email WHERE r.to_email = ? AND r.status = 'pending' ORDER BY r.created_at DESC`, [req.user.email]);
    await conn.end();
    res.json({ success: true, requests });
});

// ========== 12. ACCEPT REQUEST ==========
app.post('/api/requests/accept/:requestId', authMiddleware, async (req, res) => {
    const { requestId } = req.params;
    const conn = await getDB();
    await conn.execute('UPDATE requests SET status = "accepted" WHERE request_id = ? AND to_email = ?', [requestId, req.user.email]);
    const [requests] = await conn.execute('SELECT * FROM requests WHERE request_id = ?', [requestId]);
    if (requests.length > 0) {
        const reqData = requests[0];
        const chatId = [reqData.from_email, reqData.to_email].sort().join('#');
        await conn.execute('INSERT INTO chats (chat_id, participant1, participant2, last_updated) VALUES (?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE last_updated = NOW()', [chatId, reqData.from_email, reqData.to_email]);
    }
    await conn.end();
    res.json({ success: true, message: '✅ Request accepted! You can now chat.' });
});

// ========== 13. GET CHATS ==========
app.get('/api/chats', authMiddleware, async (req, res) => {
    const conn = await getDB();
    const [chats] = await conn.execute(`SELECT c.chat_id, c.last_message, c.last_updated, CASE WHEN c.participant1 = ? THEN c.participant2 ELSE c.participant1 END as other_user FROM chats c WHERE c.participant1 = ? OR c.participant2 = ? ORDER BY c.last_updated DESC`, [req.user.email, req.user.email, req.user.email]);
    await conn.end();
    res.json({ success: true, chats });
});

// ========== 14. SEND CHAT MESSAGE ==========
app.post('/api/chat/send', authMiddleware, async (req, res) => {
    const { chatId, message } = req.body;
    if (!message || message.trim().length === 0) return res.status(400).json({ success: false, message: 'Message required' });
    const conn = await getDB();
    await conn.execute('INSERT INTO chat_messages (chat_id, from_email, message) VALUES (?, ?, ?)', [chatId, req.user.email, message]);
    await conn.execute('UPDATE chats SET last_message = ?, last_updated = NOW() WHERE chat_id = ?', [message, chatId]);
    await conn.end();
    res.json({ success: true, message: '💬 Message sent!' });
});

// ========== 15. GET CHAT MESSAGES ==========
app.get('/api/chat/:chatId/messages', authMiddleware, async (req, res) => {
    let chatId = req.params.chatId;
    // Decode URL encoded chat_id (because # character in email)
    chatId = decodeURIComponent(chatId);
    
    const conn = await getDB();
    const [messages] = await conn.execute(
        `SELECT cm.id, cm.from_email, cm.message, cm.created_at, u.fullname as from_name 
         FROM chat_messages cm 
         JOIN users u ON cm.from_email = u.email 
         WHERE cm.chat_id = ? 
         ORDER BY cm.created_at ASC`,
        [chatId]
    );
    await conn.end();
    res.json({ success: true, messages });
});

// Socket.io events (YAHAN LAGAO - server.listen se PEHLE)
io.on('connection', (socket) => {
    console.log('🔌 New client connected:', socket.id);
    
    socket.on('join', (userId) => {
        socket.join(userId);
        console.log(`📢 User ${userId} joined room`);
    });
    
    socket.on('send_message', (data) => {
    console.log('💬 Notification via socket (no DB save):', data);
    const { chatId, message, fromEmail, toEmail } = data;
    
    // ONLY send notification - NO DB SAVE (HTTP API already saved)
    io.to(toEmail).emit('new_message', { chatId, message, fromEmail, created_at: new Date() });
    io.to(fromEmail).emit('new_message', { chatId, message, fromEmail, created_at: new Date() });
    });
    
    socket.on('disconnect', () => {
        console.log('🔌 Client disconnected:', socket.id);
    });
});
// ========== GET OUTGOING REQUESTS ==========
app.get('/api/requests/outgoing', authMiddleware, async (req, res) => {
    const conn = await getDB();
    const [requests] = await conn.execute(
        `SELECT r.request_id, r.to_email, r.message_text, r.status, r.created_at, u.fullname as to_name 
         FROM requests r 
         JOIN users u ON r.to_email = u.email 
         WHERE r.from_email = ? 
         ORDER BY r.created_at DESC`,
        [req.user.email]
    );
    await conn.end();
    res.json({ success: true, requests });
});

// ========== UPDATE PROFILE ==========
app.put('/api/auth/profile', authMiddleware, async (req, res) => {
    const { fullname } = req.body;
    
    if (!fullname) {
        return res.status(400).json({ success: false, message: 'Full name required' });
    }
    
    try {
        const conn = await getDB();
        await conn.execute(
            'UPDATE users SET fullname = ? WHERE email = ?',
            [fullname, req.user.email]
        );
        await conn.end();
        
        res.json({ success: true, message: 'Profile updated successfully!' });
    } catch(e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ========== FORGOT PASSWORD - SEND OTP ==========
app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: 'Email required' });
    
    try {
        const conn = await getDB();
        const [users] = await conn.execute('SELECT id FROM users WHERE email = ?', [email]);
        await conn.end();
        
        if (users.length === 0) {
            return res.status(404).json({ success: false, message: 'Email not found' });
        }
        
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = Date.now() + 10 * 60 * 1000;
        otpStore.set(email, { otp, verified: false, expiresAt, purpose: 'reset' });
        
        await sendOTPEmail(email, otp);
        console.log(`📧 Reset OTP sent to ${email}: ${otp}`);
        
        res.json({ success: true, message: 'OTP sent to your email!' });
    } catch(e) {
        console.error('Forgot password error:', e);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ========== FORGOT PASSWORD - RESET PASSWORD ==========
app.post('/api/auth/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;
    
    if (!email || !otp || !newPassword) {
        return res.status(400).json({ success: false, message: 'All fields required' });
    }
    if (newPassword.length < 6) {
        return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
    }
    
    const s = otpStore.get(email);
    if (!s || s.purpose !== 'reset') {
        return res.status(400).json({ success: false, message: 'OTP expired or not found. Request new OTP.' });
    }
    if (s.otp !== otp) {
        return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }
    if (Date.now() > s.expiresAt) {
        otpStore.delete(email);
        return res.status(400).json({ success: false, message: 'OTP expired. Request new OTP.' });
    }
    
    try {
        const conn = await getDB();
        const newHash = await bcrypt.hash(newPassword, 10);
        await conn.execute('UPDATE users SET password_hash = ? WHERE email = ?', [newHash, email]);
        await conn.end();
        
        otpStore.delete(email);
        res.json({ success: true, message: 'Password reset successfully! You can now login.' });
    } catch(e) {
        console.error('Reset password error:', e);
        res.status(500).json({ success: false, message: 'Failed to reset password' });
    }
});

// ========== DECLINE REQUEST ==========
app.post('/api/requests/decline/:requestId', authMiddleware, async (req, res) => {
    const { requestId } = req.params;
    const conn = await getDB();
    
    // Update status to declined
    await conn.execute(
        'UPDATE requests SET status = "declined" WHERE request_id = ? AND to_email = ?',
        [requestId, req.user.email]
    );
    
    await conn.end();
    res.json({ success: true, message: '❌ Request declined!' });
});

// ========== VERIFY MFA OTP AND COMPLETE LOGIN ==========
app.post('/api/auth/verify-mfa', async (req, res) => {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
        return res.status(400).json({ success: false, message: 'Email and OTP required' });
    }
    
    const mfaStoreKey = `mfa_${email}`;
    const mfaData = otpStore.get(mfaStoreKey);
    
    if (!mfaData || mfaData.purpose !== 'mfa') {
        return res.status(400).json({ success: false, message: 'No MFA request found. Please login again.' });
    }
    
    if (Date.now() > mfaData.expiresAt) {
        otpStore.delete(mfaStoreKey);
        return res.status(400).json({ success: false, message: 'OTP expired. Please login again.' });
    }
    
    if (mfaData.otp !== otp) {
        return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }
    
    // OTP verified — generate final token
    const token = jwt.sign(
        { id: mfaData.userId, email: email }, 
        process.env.JWT_SECRET || 'secret', 
        { expiresIn: '7d' }
    );
    
    // Clean up MFA data
    otpStore.delete(mfaStoreKey);
    
    res.json({ 
        success: true, 
        token: token,
        user: { email: email, fullname: mfaData.fullname },
        message: 'Login successful!'
    });
});


const PORT = 5000;
server.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server on port ${PORT}`));
