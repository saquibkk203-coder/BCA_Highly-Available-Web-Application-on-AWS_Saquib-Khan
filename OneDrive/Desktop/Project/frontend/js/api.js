// ========== API CONFIGURATION ==========
// Web Server's Public IP (EC2)
const API_BASE_URL = 'http://"Web Server Public IP"/api';

// ========== HELPER FUNCTIONS ==========
// Get Auth Token
function getToken() {
    return localStorage.getItem('token');
}

// Save Auth Token
function setToken(token) {
    localStorage.setItem('token', token);
}

// Remove Auth Token (Logout)
function removeToken() {
    localStorage.removeItem('token');
    localStorage.removeItem('currentUser');
}

// ========== API CALLS ==========
// Generic API caller
async function apiCall(endpoint, method = 'GET', data = null, requiresAuth = true) {
    const headers = {
        'Content-Type': 'application/json'
    };
    
    if (requiresAuth) {
        const token = getToken();
        if (!token) {
            throw new Error('No authentication token found');
        }
        headers['Authorization'] = `Bearer ${token}`;
    }
    
    const options = {
        method: method,
        headers: headers
    };
    
    if (data) {
        options.body = JSON.stringify(data);
    }
    
    const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
    return await response.json();
}

// ========== AUTH APIS ==========
async function login(email, password) {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
    });
    const data = await response.json();
    if (data.success && data.token) {
        setToken(data.token);
        localStorage.setItem('currentUser', JSON.stringify(data.user));
    }
    return data;
}

async function register(email, fullname, password) {
    const response = await fetch(`${API_BASE_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, fullname, password })
    });
    return await response.json();
}

async function sendOTP(email) {
    const response = await fetch(`${API_BASE_URL}/auth/send-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
    });
    return await response.json();
}

async function getUserStats() {
    return await apiCall('/auth/stats', 'GET', null, true);
}

// ========== MESSAGE APIS ==========
async function sendMessage(text) {
    return await apiCall('/messages/send', 'POST', { text }, true);
}

async function getFlyingMessages() {
    return await apiCall('/messages/flying', 'GET', null, true);
}

async function catchMessage(messageId) {
    return await apiCall(`/messages/catch/${messageId}`, 'POST', null, true);
}

async function passMessage(messageId) {
    return await apiCall(`/messages/pass/${messageId}`, 'POST', null, true);
}

// ========== REQUEST APIS ==========
async function sendRequest(toEmail, messageId, messageText) {
    return await apiCall('/requests/send', 'POST', { toEmail, messageId, messageText }, true);
}

async function getIncomingRequests() {
    return await apiCall('/requests/incoming', 'GET', null, true);
}

async function acceptRequest(requestId) {
    return await apiCall(`/requests/accept/${requestId}`, 'PUT', null, true);
}

// ========== CHAT APIS ==========
async function getChats() {
    return await apiCall('/chat/chats', 'GET', null, true);
}

async function sendChatMessage(chatId, message) {
    return await apiCall('/chat/send', 'POST', { chatId, message }, true);
}

// ========== LOGOUT ==========
function logout() {
    removeToken();
    window.location.href = 'index.html';
}

// ========== CHECK AUTH ==========
function isAuthenticated() {
    return !!getToken();
}

function redirectIfNotLoggedIn() {
    if (!isAuthenticated()) {
        window.location.href = 'login.html';
    }
}

function redirectIfLoggedIn() {
    if (isAuthenticated()) {
        window.location.href = 'dashboard.html';
    }
}
