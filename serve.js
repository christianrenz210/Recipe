const express = require('express');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

app.use(session({
    secret: 'recipeshare-secret-key-2026',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

const users = [
    { id: 1, name: 'Admin User', email: 'admin@email.com', password: 'admin123', role: 'admin' },
    { id: 2, name: 'Maria Santos', email: 'user@email.com', password: 'user123', role: 'user' }
];
let nextId = 3;

const requireAuth = (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    next();
};

const requireAdmin = (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    next();
};

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    const user = users.find(u => u.email === email && u.password === password);
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
    res.json({ id: user.id, name: user.name, email: user.email, role: user.role });
});

app.post('/api/register', (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required' });

    if (users.find(u => u.email === email)) return res.status(409).json({ error: 'Email already registered' });

    const newUser = { id: nextId++, name, email, password, role: 'user' };
    users.push(newUser);
    req.session.user = { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role };
    res.status(201).json({ id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role });
});

app.get('/api/me', requireAuth, (req, res) => {
    res.json(req.session.user);
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/users', requireAdmin, (req, res) => {
    res.json(users.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role })));
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
    console.log(`RecipeShare server running at http://localhost:${PORT}`);
});
