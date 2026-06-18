const path = require('path');
const Database = require('better-sqlite3');
const { Pool } = require('pg');

const DB_PATH = path.join(__dirname, 'recipeshare.db');
const DATABASE_URL = process.env.DATABASE_URL;

let db;

function isPostgres() {
    return !!DATABASE_URL;
}

class SqliteDb {
    constructor() {
        this.db = new Database(DB_PATH);
        this.db.pragma('journal_mode = WAL');
        this.db.pragma('foreign_keys = ON');
        this.type = 'sqlite';
    }

    prepare(sql) {
        const stmt = this.db.prepare(sql);
        const self = this;
        return {
            get(...params) { return Promise.resolve(stmt.get(...params)); },
            all(...params) { return Promise.resolve(stmt.all(...params)); },
            run(...params) {
                const info = stmt.run(...params);
                return Promise.resolve({ lastInsertRowid: info.lastInsertRowid, changes: info.changes });
            }
        };
    }

    exec(sql) { this.db.exec(sql); }
    close() { this.db.close(); }
}

class PgDb {
    constructor() {
        this.pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
        this.type = 'pg';
    }

    prepare(sql) {
        let i = 0;
        let pgSql = sql.replace(/\?/g, () => `$${++i}`);

        const isInsertOrIgnore = /INSERT\s+OR\s+IGNORE\s+INTO/i.test(pgSql);
        if (isInsertOrIgnore) {
            pgSql = pgSql.replace(/INSERT\s+OR\s+IGNORE\s+INTO/i, 'INSERT INTO');
            pgSql += ' ON CONFLICT DO NOTHING';
        }

        const isInsert = /^\s*INSERT\s+INTO/i.test(pgSql) && !/RETURNING/i.test(pgSql);
        if (isInsert) {
            pgSql += ' RETURNING id';
        }

        const pool = this.pool;
        return {
            async get(...params) {
                const r = await pool.query(pgSql, params);
                return r.rows[0] || null;
            },
            async all(...params) {
                const r = await pool.query(pgSql, params);
                return r.rows;
            },
            async run(...params) {
                const r = await pool.query(pgSql, params);
                return { lastInsertRowid: r.rows[0]?.id || null, changes: r.rowCount };
            }
        };
    }

    async exec(sql) {
        await this.pool.query(sql);
    }

    async close() {
        await this.pool.end();
    }
}

function getDb() {
    if (!db) {
        db = isPostgres() ? new PgDb() : new SqliteDb();
    }
    return db;
}

async function initDb() {
    const db = getDb();
    const pg = db.type === 'pg';

    if (pg) {
        await db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
                google_id TEXT UNIQUE,
                created_at TIMESTAMP NOT NULL DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS categories (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                slug TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS recipes (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                ingredients TEXT,
                instructions TEXT,
                image TEXT,
                category_id INTEGER REFERENCES categories(id),
                author_id INTEGER NOT NULL REFERENCES users(id),
                created_at TIMESTAMP NOT NULL DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS reviews (
                id SERIAL PRIMARY KEY,
                recipe_id INTEGER NOT NULL REFERENCES recipes(id),
                user_id INTEGER NOT NULL REFERENCES users(id),
                rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
                comment TEXT,
                created_at TIMESTAMP NOT NULL DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS follows (
                id SERIAL PRIMARY KEY,
                follower_id INTEGER NOT NULL REFERENCES users(id),
                following_id INTEGER NOT NULL REFERENCES users(id),
                created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                UNIQUE(follower_id, following_id)
            );
            CREATE TABLE IF NOT EXISTS likes (
                id SERIAL PRIMARY KEY,
                recipe_id INTEGER NOT NULL REFERENCES recipes(id),
                user_id INTEGER NOT NULL REFERENCES users(id),
                created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                UNIQUE(recipe_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS notifications (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                type TEXT NOT NULL CHECK(type IN ('follow', 'like', 'comment', 'new_recipe')),
                actor_id INTEGER NOT NULL REFERENCES users(id),
                recipe_id INTEGER REFERENCES recipes(id),
                link TEXT,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP NOT NULL DEFAULT NOW()
            );
        `);
    } else {
        db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
                google_id TEXT UNIQUE,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                slug TEXT NOT NULL UNIQUE
            );
        `);
    }

    if (!pg) {
        const tableInfo = await db.prepare("PRAGMA table_info('users')").all();
        if (!tableInfo.find(col => col.name === 'google_id')) {
            db.exec("ALTER TABLE users ADD COLUMN google_id TEXT");
            console.log('Migrated: added google_id column to users table');
        }

        const notifTableInfo = await db.prepare("PRAGMA table_info('notifications')").all();
        if (!notifTableInfo.find(col => col.name === 'link')) {
            db.exec("ALTER TABLE notifications ADD COLUMN link TEXT");
            console.log('Migrated: added link column to notifications table');
        }

        try {
            await db.prepare("INSERT INTO notifications (user_id, type, actor_id) VALUES (1, 'new_recipe', 1)").run();
            await db.exec("DELETE FROM notifications WHERE type = 'new_recipe'");
        } catch (e) {
            console.log('Migrating notifications table to fix CHECK constraint...');
            db.exec(`
                CREATE TABLE notifications_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    type TEXT NOT NULL CHECK(type IN ('follow', 'like', 'comment', 'new_recipe')),
                    actor_id INTEGER NOT NULL,
                    recipe_id INTEGER,
                    link TEXT,
                    is_read INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (actor_id) REFERENCES users(id),
                    FOREIGN KEY (recipe_id) REFERENCES recipes(id)
                );
                INSERT INTO notifications_new (id, user_id, type, actor_id, recipe_id, link, is_read, created_at)
                    SELECT id, user_id, type, actor_id, recipe_id, link, is_read, created_at FROM notifications;
                DROP TABLE notifications;
                ALTER TABLE notifications_new RENAME TO notifications;
            `);
            console.log('Migrated: fixed notifications CHECK constraint');
        }

        db.exec(`
            CREATE TABLE IF NOT EXISTS recipes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                ingredients TEXT,
                instructions TEXT,
                image TEXT,
                category_id INTEGER,
                author_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (category_id) REFERENCES categories(id),
                FOREIGN KEY (author_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipe_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
                comment TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (recipe_id) REFERENCES recipes(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS follows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                follower_id INTEGER NOT NULL,
                following_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(follower_id, following_id),
                FOREIGN KEY (follower_id) REFERENCES users(id),
                FOREIGN KEY (following_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS likes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipe_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(recipe_id, user_id),
                FOREIGN KEY (recipe_id) REFERENCES recipes(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL CHECK(type IN ('follow', 'like', 'comment', 'new_recipe')),
                actor_id INTEGER NOT NULL,
                recipe_id INTEGER,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (actor_id) REFERENCES users(id),
                FOREIGN KEY (recipe_id) REFERENCES recipes(id)
            );
        `);
    }

    const userCount = (await db.prepare('SELECT COUNT(*) as count FROM users').get()).count;
    if (userCount === 0) {
        const insertUser = db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)');
        await insertUser.run('Admin User', 'admin@email.com', 'admin123', 'admin');
        await insertUser.run('Maria Santos', 'user@email.com', 'user123', 'user');
    }

    const catCount = (await db.prepare('SELECT COUNT(*) as count FROM categories').get()).count;
    if (catCount === 0) {
        const insertCat = db.prepare('INSERT INTO categories (name, slug) VALUES (?, ?)');
        await insertCat.run('Breakfast', 'breakfast');
        await insertCat.run('Lunch', 'lunch');
        await insertCat.run('Dinner', 'dinner');
        await insertCat.run('Dessert', 'dessert');
        await insertCat.run('Appetizer', 'appetizer');
        await insertCat.run('Snack', 'snack');
    }

    const recipeCount = (await db.prepare('SELECT COUNT(*) as count FROM recipes').get()).count;
    const seedAuthor = await db.prepare("SELECT id FROM users WHERE email = 'admin@email.com'").get();
    if (recipeCount === 0 && seedAuthor) {
        const insertRecipe = db.prepare(
            `INSERT INTO recipes (title, description, ingredients, instructions, image, category_id, author_id)
             VALUES (?, ?, ?, ?, ?, ?, ?)`
        );
        await insertRecipe.run(
            'Chicken Adobo',
            'Tender chicken simmered in soy sauce, vinegar, garlic, bay leaves, and peppercorns.',
            '1 kg chicken thighs\n1/2 cup soy sauce\n1/2 cup vinegar\n6 cloves garlic\n1 tsp peppercorns\n3 bay leaves\n1 cup water\n2 tbsp oil',
            '1. Marinate chicken in soy sauce, garlic, peppercorns for 30 min\n2. Heat oil, sear chicken until golden\n3. Pour marinade, vinegar, bay leaves, water. Boil without stirring.\n4. Simmer 30-40 min until tender\n5. Serve hot with rice',
            'https://upload.wikimedia.org/wikipedia/commons/3/38/Chicken_adobo.jpg',
            2, seedAuthor.id
        );
        await insertRecipe.run(
            'Sinigang na Baboy',
            'Savory sour tamarind soup with tender pork ribs, kangkong, and fresh vegetables.',
            '1 kg pork ribs\n1 packet tamarind mix\n2 tomatoes\n1 onion\n2 tbsp fish sauce\nKangkong leaves\nRadish\nOkra\nGreen chili',
            '1. Boil pork with onion until tender\n2. Add tomatoes, tamarind mix\n3. Add radish, okra, chili\n4. Season with fish sauce\n5. Add kangkong, simmer 2 min\n6. Serve hot',
            'https://upload.wikimedia.org/wikipedia/commons/c/ce/Sinigang_na_baboy.jpg',
            3, seedAuthor.id
        );
        await insertRecipe.run(
            'Tapsilog',
            'Classic Filipino breakfast with cured beef tapa, garlic fried rice, and sunny egg.',
            '500g beef sirloin\n1/2 cup soy sauce\n1/4 cup vinegar\n4 cloves garlic\n1 tsp sugar\n4 cups cooked rice\n4 eggs\nOil',
            '1. Slice beef thin, marinate in soy sauce, vinegar, garlic, sugar overnight\n2. Fry beef until caramelized\n3. Make garlic fried rice\n4. Fry eggs sunny side up\n5. Serve together',
            'https://upload.wikimedia.org/wikipedia/commons/thumb/0/0c/Tapsilog_in_saudi_arabia.jpg/500px-Tapsilog_in_saudi_arabia.jpg',
            1, seedAuthor.id
        );
        await insertRecipe.run(
            'Halo-Halo',
            'Refreshing shaved ice with sweet beans, sago, gulaman, leche flan, and ube ice cream.',
            'Shaved ice\nSweetened beans\nSago pearls\nGulaman\nLeche flan\nUbe ice cream\nEvaporated milk\nSugar\nPinipig',
            '1. Prepare all toppings separately\n2. Fill glass with sweet beans, sago, gulaman\n3. Add shaved ice\n4. Top with leche flan, ube ice cream\n5. Drizzle evaporated milk\n6. Add pinipig on top',
            'https://upload.wikimedia.org/wikipedia/commons/thumb/3/36/Halu-halo.jpg/500px-Halu-halo.jpg',
            4, seedAuthor.id
        );
        await insertRecipe.run(
            'Lumpiang Shanghai',
            'Crispy fried spring rolls filled with seasoned ground pork and vegetables.',
            '500g ground pork\n1 carrot\n1 onion\n4 cloves garlic\nSpring roll wrappers\n1 egg\nSalt and pepper\nOil for frying',
            '1. Mix pork, minced veggies, egg, seasonings\n2. Place filling on wrapper, roll tightly\n3. Seal edges with water\n4. Deep fry until golden brown\n5. Serve with sweet chili sauce',
            'https://upload.wikimedia.org/wikipedia/commons/a/aa/Tray_of_Lumpiang_Shanghai.JPG',
            6, seedAuthor.id
        );
        await insertRecipe.run(
            'Kare-Kare',
            'Oxtail and tripe in creamy peanut sauce with bagoong on the side.',
            '1 kg oxtail\n200g tripe\n1/2 cup peanut butter\n1 banana blossom\nEggplant\nString beans\nBagoong\nAnnatto seeds\nGarlic\nOnion',
            '1. Boil oxtail and tripe until tender\n2. Sauté garlic, onion, annatto\n3. Add peanut butter and broth\n4. Add vegetables\n5. Simmer until sauce thickens\n6. Serve with bagoong',
            'https://upload.wikimedia.org/wikipedia/commons/e/e2/Oxtail_kare-kare_1.JPG',
            3, seedAuthor.id
        );
    }

    console.log('Database initialized successfully');
}

async function closeDb() {
    if (db) {
        if (db.type === 'pg') {
            await db.close();
        } else {
            db.close();
        }
        db = null;
    }
}

module.exports = { getDb, initDb, closeDb };