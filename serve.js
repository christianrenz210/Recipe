require('express-async-errors');
const express = require('express');
const session = require('express-session');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const multer = require('multer');
const fs = require('fs');
const { getDb, initDb } = require('./database');
const config = require('./config.json');

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

const app = express();
const PORT = process.env.PORT || 3000;

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

initDb().catch(console.error);

passport.use(new GoogleStrategy({
    clientID: config.google.clientID,
    clientSecret: config.google.clientSecret
}, async function (accessToken, refreshToken, profile, done) {
    try {
        const db = getDb();
        let user = await db.prepare('SELECT * FROM users WHERE google_id = ?').get(profile.id);
        if (!user) {
            user = await db.prepare('SELECT * FROM users WHERE email = ?').get(profile.emails?.[0]?.value);
        }
        if (!user) {
            const email = profile.emails?.[0]?.value || profile.id + '@google.oauth';
            const name = profile.displayName || 'Google User';
            const result = await db.prepare('INSERT INTO users (name, email, password, role, google_id) VALUES (?, ?, ?, ?, ?)')
                .run(name, email, 'oauth_' + profile.id, 'user', profile.id);
            user = await db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
        } else if (!user.google_id) {
            await db.prepare('UPDATE users SET google_id = ? WHERE id = ?').run(profile.id, user.id);
        }
        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

passport.serializeUser(function (user, done) { done(null, user.id); });
passport.deserializeUser(async function (id, done) {
    try {
        const db = getDb();
        const user = await db.prepare('SELECT * FROM users WHERE id = ?').get(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin) res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.header('Access-Control-Allow-Credentials', 'true');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

app.use(session({
    secret: 'recipeshare-secret-key-2026',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 24 * 60 * 60 * 1000, sameSite: false }
}));

app.use(passport.initialize());
app.use(passport.session());

app.get('/auth/google', function (req, res, next) {
    var base = req.headers['x-forwarded-proto'] && req.headers['x-forwarded-host']
        ? req.headers['x-forwarded-proto'] + '://' + req.headers['x-forwarded-host']
        : (req.protocol + '://' + req.get('host'));
    var cb = base + '/auth/google/callback';
    console.log('Google auth callback URL:', cb);
    passport.authenticate('google', {
        scope: ['profile', 'email'],
        callbackURL: cb
    })(req, res, next);
});

app.get('/auth/google/callback', function (req, res, next) {
    var base = req.headers['x-forwarded-proto'] && req.headers['x-forwarded-host']
        ? req.headers['x-forwarded-proto'] + '://' + req.headers['x-forwarded-host']
        : (req.protocol + '://' + req.get('host'));
    passport.authenticate('google', {
        failureRedirect: '/pages/login.html?error=google',
        callbackURL: base + '/auth/google/callback'
    }, function (err, user) {
        if (err) { console.error('Google auth error:', err); return res.redirect('/pages/login.html?error=' + encodeURIComponent(err.message)); }
        if (!user) return res.redirect('/pages/login.html?error=google');
        req.logIn(user, function (err) {
            if (err) { console.error('Login error:', err); return res.redirect('/pages/login.html?error=login'); }
            req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
            console.log('Google login success:', user.name, user.email);
            if (user.role === 'admin') res.redirect('/admin/dashboard.html');
            else res.redirect('/user/dashboard.html');
        });
    })(req, res, next);
});

const requireAuth = (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    next();
};

const requireAdmin = (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    next();
};

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    const db = getDb();
    const user = await db.prepare('SELECT * FROM users WHERE email = ? AND password = ?').get(email, password);
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
    res.json({ id: user.id, name: user.name, email: user.email, role: user.role });
});

app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required' });

    const db = getDb();
    const existing = await db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const result = await db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)')
        .run(name, email, password, 'user');
    const newUser = { id: result.lastInsertRowid, name, email, role: 'user' };

    req.session.user = { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role };
    res.status(201).json(newUser);
});

app.get('/api/me', requireAuth, (req, res) => {
    res.json(req.session.user);
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/users', requireAdmin, async (req, res) => {
    const db = getDb();
    const users = await db.prepare('SELECT id, name, email, role FROM users').all();
    res.json(users);
});

app.get('/api/users/me/profile', requireAuth, async (req, res) => {
    const db = getDb();
    const user = await db.prepare('SELECT id, name, email, role FROM users WHERE id = ?').get(req.session.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const followerCount = (await db.prepare('SELECT COUNT(*) as c FROM follows WHERE following_id = ?').get(req.session.user.id)).c;
    const followingCount = (await db.prepare('SELECT COUNT(*) as c FROM follows WHERE follower_id = ?').get(req.session.user.id)).c;
    const recipeCount = (await db.prepare('SELECT COUNT(*) as c FROM recipes WHERE author_id = ?').get(req.session.user.id)).c;
    res.json({ ...user, followerCount, followingCount, recipeCount });
});

app.get('/api/users/me/following/ids', requireAuth, async (req, res) => {
    const db = getDb();
    const rows = await db.prepare('SELECT following_id FROM follows WHERE follower_id = ?').all(req.session.user.id);
    res.json(rows.map(r => r.following_id));
});

app.get('/api/users/:id/profile', async (req, res) => {
    const db = getDb();
    const user = await db.prepare('SELECT id, name, email, role FROM users WHERE id = ?').get(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const followerCount = (await db.prepare('SELECT COUNT(*) as c FROM follows WHERE following_id = ?').get(req.params.id)).c;
    const followingCount = (await db.prepare('SELECT COUNT(*) as c FROM follows WHERE follower_id = ?').get(req.params.id)).c;
    const recipeCount = (await db.prepare('SELECT COUNT(*) as c FROM recipes WHERE author_id = ?').get(req.params.id)).c;
    let isFollowing = false;
    if (req.session.user) {
        const f = await db.prepare('SELECT id FROM follows WHERE follower_id = ? AND following_id = ?').get(req.session.user.id, req.params.id);
        if (f) isFollowing = true;
    }
    res.json({ ...user, followerCount, followingCount, recipeCount, isFollowing });
});

app.get('/api/users/:id/recipes', async (req, res) => {
    const db = getDb();
    const recipes = await db.prepare(`
        SELECT r.*, c.name as category_name,
            (SELECT COUNT(*) FROM likes WHERE recipe_id = r.id) as like_count,
            (SELECT COUNT(*) FROM reviews WHERE recipe_id = r.id) as review_count
        FROM recipes r
        LEFT JOIN categories c ON r.category_id = c.id
        WHERE r.author_id = ?
        ORDER BY r.created_at DESC
    `).all(req.params.id);
    res.json(recipes);
});

app.get('/api/users/suggested', requireAuth, async (req, res) => {
    const db = getDb();
    const users = await db.prepare(`
        SELECT u.id, u.name, u.email,
            (SELECT COUNT(*) FROM follows WHERE following_id = u.id) as followerCount
        FROM users u
        WHERE u.id != ? AND u.id NOT IN (
            SELECT following_id FROM follows WHERE follower_id = ?
        )
        ORDER BY followerCount DESC
        LIMIT 5
    `).all(req.session.user.id, req.session.user.id);
    res.json(users);
});

app.post('/api/users/:id/follow', requireAuth, async (req, res) => {
    const db = getDb();
    const targetId = parseInt(req.params.id);
    if (targetId === req.session.user.id) return res.status(400).json({ error: 'Cannot follow yourself' });
    const target = await db.prepare('SELECT id FROM users WHERE id = ?').get(targetId);
    if (!target) return res.status(404).json({ error: 'User not found' });
    try {
        await db.prepare('INSERT OR IGNORE INTO follows (follower_id, following_id) VALUES (?, ?)').run(req.session.user.id, targetId);
        await db.prepare('INSERT INTO notifications (user_id, type, actor_id, link) VALUES (?, ?, ?, ?)').run(targetId, 'follow', req.session.user.id, 'viewUserProfile(' + req.session.user.id + ')');
        const following = (await db.prepare('SELECT COUNT(*) as c FROM follows WHERE follower_id = ?').get(req.session.user.id)).c;
        res.json({ ok: true, following });
    } catch (e) {
        res.status(500).json({ error: 'Failed to follow' });
    }
});

app.post('/api/users/:id/unfollow', requireAuth, async (req, res) => {
    const db = getDb();
    await db.prepare('DELETE FROM follows WHERE follower_id = ? AND following_id = ?').run(req.session.user.id, req.params.id);
    const following = (await db.prepare('SELECT COUNT(*) as c FROM follows WHERE follower_id = ?').get(req.session.user.id)).c;
    res.json({ ok: true, following });
});

app.post('/api/users/:id/remove-follower', requireAuth, async (req, res) => {
    const db = getDb();
    await db.prepare('DELETE FROM follows WHERE follower_id = ? AND following_id = ?').run(req.params.id, req.session.user.id);
    const followers = (await db.prepare('SELECT COUNT(*) as c FROM follows WHERE following_id = ?').get(req.session.user.id)).c;
    res.json({ ok: true, followers });
});

app.get('/api/users/:id/followers', async (req, res) => {
    const db = getDb();
    const followers = await db.prepare(`
        SELECT u.id, u.name, u.email, f.created_at as followed_at
        FROM follows f
        JOIN users u ON f.follower_id = u.id
        WHERE f.following_id = ?
    `).all(req.params.id);
    if (req.session.user) {
        const followingIds = (await db.prepare('SELECT following_id FROM follows WHERE follower_id = ?').all(req.session.user.id)).map(r => r.following_id);
        followers.forEach(f => f.is_following_back = followingIds.includes(f.id));
    }
    res.json(followers);
});

app.get('/api/users/:id/following', async (req, res) => {
    const db = getDb();
    const following = await db.prepare(`
        SELECT u.id, u.name, u.email, f.created_at as followed_at
        FROM follows f
        JOIN users u ON f.following_id = u.id
        WHERE f.follower_id = ?
    `).all(req.params.id);
    res.json(following);
});

app.get('/api/recipes/feed/following', requireAuth, async (req, res) => {
    const db = getDb();
    const recipes = await db.prepare(`
        SELECT r.*, c.name as category_name, u.name as author_name,
            (SELECT COUNT(*) FROM likes WHERE recipe_id = r.id) as like_count,
            (SELECT COUNT(*) FROM reviews WHERE recipe_id = r.id) as review_count
        FROM recipes r
        LEFT JOIN categories c ON r.category_id = c.id
        JOIN users u ON r.author_id = u.id
        WHERE r.author_id IN (SELECT following_id FROM follows WHERE follower_id = ?)
        ORDER BY r.created_at DESC
    `).all(req.session.user.id);
    res.json(recipes);
});

app.get('/api/stats', async (req, res) => {
    const db = getDb();
    const recipes = (await db.prepare('SELECT COUNT(*) as c FROM recipes').get()).c;
    const users = (await db.prepare('SELECT COUNT(*) as c FROM users').get()).c;
    const chefs = (await db.prepare('SELECT COUNT(*) as c FROM users WHERE role = ?').get('admin')).c;
    res.json({ recipes, users, chefs });
});

app.get('/api/categories', async (req, res) => {
    const db = getDb();
    const categories = await db.prepare('SELECT * FROM categories').all();
    res.json(categories);
});

app.get('/api/recipes', async (req, res) => {
    const db = getDb();
    const { category } = req.query;
    let sql = `
        SELECT r.*, c.name as category_name, u.name as author_name,
            (SELECT COUNT(*) FROM likes WHERE recipe_id = r.id) as like_count,
            (SELECT COUNT(*) FROM reviews WHERE recipe_id = r.id) as review_count
        FROM recipes r
        LEFT JOIN categories c ON r.category_id = c.id
        LEFT JOIN users u ON r.author_id = u.id
    `;
    if (category && category !== 'all') {
        sql += ' WHERE c.slug = ?';
        const recipes = await db.prepare(sql).all(category);
        return res.json(recipes);
    }
    const recipes = await db.prepare(sql).all();
    res.json(recipes);
});

app.get('/api/recipes/user/me', requireAuth, async (req, res) => {
    const db = getDb();
    const recipes = await db.prepare(`
        SELECT r.*, c.name as category_name,
            (SELECT COUNT(*) FROM likes WHERE recipe_id = r.id) as like_count,
            (SELECT COUNT(*) FROM reviews WHERE recipe_id = r.id) as review_count
        FROM recipes r
        LEFT JOIN categories c ON r.category_id = c.id
        WHERE r.author_id = ?
        ORDER BY r.created_at DESC
    `).all(req.session.user.id);
    res.json(recipes);
});

app.get('/api/recipes/:id', async (req, res) => {
    const db = getDb();
    const recipe = await db.prepare(`
        SELECT r.*, c.name as category_name, u.name as author_name,
            (SELECT COUNT(*) FROM likes WHERE recipe_id = r.id) as like_count,
            (SELECT COUNT(*) FROM reviews WHERE recipe_id = r.id) as review_count
        FROM recipes r
        LEFT JOIN categories c ON r.category_id = c.id
        LEFT JOIN users u ON r.author_id = u.id
        WHERE r.id = ?
    `).get(req.params.id);
    if (!recipe) return res.status(404).json({ error: 'Recipe not found' });
    let user_liked = false;
    if (req.session.user) {
        const like = await db.prepare('SELECT id FROM likes WHERE recipe_id = ? AND user_id = ?').get(req.params.id, req.session.user.id);
        if (like) user_liked = true;
    }
    recipe.user_liked = user_liked;
    res.json(recipe);
});

app.get('/api/recipes/liked/ids', requireAuth, async (req, res) => {
    const db = getDb();
    const rows = await db.prepare('SELECT recipe_id FROM likes WHERE user_id = ?').all(req.session.user.id);
    res.json(rows.map(r => r.recipe_id));
});

app.post('/api/recipes/:id/like', requireAuth, async (req, res) => {
    const db = getDb();
    const recipe = await db.prepare('SELECT id, author_id FROM recipes WHERE id = ?').get(req.params.id);
    if (!recipe) return res.status(404).json({ error: 'Recipe not found' });
    const existing = await db.prepare('SELECT id FROM likes WHERE recipe_id = ? AND user_id = ?').get(req.params.id, req.session.user.id);
    if (existing) {
        await db.prepare('DELETE FROM likes WHERE id = ?').run(existing.id);
        const count = (await db.prepare('SELECT COUNT(*) as c FROM likes WHERE recipe_id = ?').get(req.params.id)).c;
        return res.json({ liked: false, like_count: count });
    }
    await db.prepare('INSERT INTO likes (recipe_id, user_id) VALUES (?, ?)').run(req.params.id, req.session.user.id);
    if (recipe.author_id !== req.session.user.id) {
        await db.prepare('INSERT INTO notifications (user_id, type, actor_id, recipe_id, link) VALUES (?, ?, ?, ?, ?)').run(recipe.author_id, 'like', req.session.user.id, req.params.id, 'viewRecipeDetail(' + req.params.id + ')');
    }
    const count = (await db.prepare('SELECT COUNT(*) as c FROM likes WHERE recipe_id = ?').get(req.params.id)).c;
    res.json({ liked: true, like_count: count });
});

app.post('/api/recipes', requireAuth, upload.single('image'), async (req, res) => {
    const { title, description, ingredients, instructions, category_id } = req.body;
    if (!title) return res.status(400).json({ error: 'Title is required' });

    const image = req.file ? '/uploads/' + req.file.filename : (req.body.image || null);
    const db = getDb();
    const result = await db.prepare(
        'INSERT INTO recipes (title, description, ingredients, instructions, image, category_id, author_id) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(title, description, ingredients, instructions, image, category_id || null, req.session.user.id);
    const recipeId = result.lastInsertRowid;
    const followers = await db.prepare('SELECT follower_id FROM follows WHERE following_id = ?').all(req.session.user.id);
    const insertNotif = db.prepare('INSERT INTO notifications (user_id, type, actor_id, recipe_id, link) VALUES (?, ?, ?, ?, ?)');
    for (const f of followers) {
        await insertNotif.run(f.follower_id, 'new_recipe', req.session.user.id, recipeId, 'viewRecipeDetail(' + recipeId + ')');
    }
    res.status(201).json({ id: recipeId, title });
});

app.put('/api/recipes/:id', requireAuth, upload.single('image'), async (req, res) => {
    const db = getDb();
    const recipe = await db.prepare('SELECT * FROM recipes WHERE id = ?').get(req.params.id);
    if (!recipe) return res.status(404).json({ error: 'Recipe not found' });
    if (recipe.author_id !== req.session.user.id && req.session.user.role !== 'admin')
        return res.status(403).json({ error: 'Forbidden' });

    const { title, description, ingredients, instructions, category_id } = req.body;
    if (!title) return res.status(400).json({ error: 'Title is required' });

    const image = req.file ? '/uploads/' + req.file.filename : (req.body.image || recipe.image);
    await db.prepare(
        'UPDATE recipes SET title=?, description=?, ingredients=?, instructions=?, image=?, category_id=? WHERE id=?'
    ).run(title, description, ingredients, instructions, image, category_id || null, req.params.id);
    res.json({ id: recipe.id, title });
});

app.delete('/api/recipes/:id', requireAuth, async (req, res) => {
    const db = getDb();
    const recipe = await db.prepare('SELECT * FROM recipes WHERE id = ?').get(req.params.id);
    if (!recipe) return res.status(404).json({ error: 'Recipe not found' });
    if (recipe.author_id !== req.session.user.id && req.session.user.role !== 'admin')
        return res.status(403).json({ error: 'Forbidden' });

    await db.prepare('DELETE FROM recipes WHERE id = ?').run(req.params.id);
    res.json({ ok: true });
});

app.get('/api/recipes/:id/reviews', async (req, res) => {
    const db = getDb();
    const reviews = await db.prepare(`
        SELECT rev.*, u.name as user_name
        FROM reviews rev
        LEFT JOIN users u ON rev.user_id = u.id
        WHERE rev.recipe_id = ?
        ORDER BY rev.created_at DESC
    `).all(req.params.id);
    res.json(reviews);
});

app.delete('/api/reviews/:id', requireAuth, async (req, res) => {
    const db = getDb();
    const review = await db.prepare('SELECT * FROM reviews WHERE id = ?').get(req.params.id);
    if (!review) return res.status(404).json({ error: 'Review not found' });
    const recipe = await db.prepare('SELECT author_id FROM recipes WHERE id = ?').get(review.recipe_id);
    const isReviewAuthor = review.user_id === req.session.user.id;
    const isRecipeAuthor = recipe && recipe.author_id === req.session.user.id;
    const isAdmin = req.session.user.role === 'admin';
    if (!isReviewAuthor && !isRecipeAuthor && !isAdmin)
        return res.status(403).json({ error: 'Forbidden' });
    await db.prepare('DELETE FROM reviews WHERE id = ?').run(req.params.id);
    res.json({ ok: true });
});

app.post('/api/recipes/:id/reviews', requireAuth, async (req, res) => {
    const { rating, comment } = req.body;
    if (!rating) return res.status(400).json({ error: 'Rating is required' });

    const db = getDb();
    const recipe = await db.prepare('SELECT author_id FROM recipes WHERE id = ?').get(req.params.id);
    const result = await db.prepare(
        'INSERT INTO reviews (recipe_id, user_id, rating, comment) VALUES (?, ?, ?, ?)'
    ).run(req.params.id, req.session.user.id, rating, comment || null);
    if (recipe && recipe.author_id !== req.session.user.id) {
        await db.prepare('INSERT INTO notifications (user_id, type, actor_id, recipe_id, link) VALUES (?, ?, ?, ?, ?)').run(recipe.author_id, 'comment', req.session.user.id, req.params.id, 'viewRecipeDetail(' + req.params.id + ')');
    }
    res.status(201).json({ id: result.lastInsertRowid, rating, comment });
});

app.get('/api/notifications', requireAuth, async (req, res) => {
    const db = getDb();
    const notifications = await db.prepare(`
        SELECT n.*, u.name as actor_name
        FROM notifications n
        JOIN users u ON n.actor_id = u.id
        WHERE n.user_id = ?
        ORDER BY n.created_at DESC
        LIMIT 20
    `).all(req.session.user.id);
    res.json(notifications);
});

app.get('/api/notifications/unread/count', requireAuth, async (req, res) => {
    const db = getDb();
    const count = (await db.prepare('SELECT COUNT(*) as c FROM notifications WHERE user_id = ? AND is_read = 0').get(req.session.user.id)).c;
    res.json({ count });
});

app.post('/api/notifications/read', requireAuth, async (req, res) => {
    const db = getDb();
    await db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(req.session.user.id);
    res.json({ ok: true });
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
    console.log(`RecipeShare server running at http://localhost:${PORT}`);
});
