const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const crypto = require('crypto');

// ===== CONFIGURACIÓN =====
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tu_secreto_super_seguro_cambiar_en_produccion';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_BOT_USERNAME = process.env.TELEGRAM_BOT_USERNAME || 'calienxxx_bot';

// ===== MIDDLEWARES =====
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Servir archivos estáticos
app.use('/uploads', express.static('uploads'));
app.use('/videos', express.static('videos'));
app.use('/thumbnails', express.static('thumbnails'));

// ===== CREAR DIRECTORIOS =====
const directories = ['uploads', 'videos', 'thumbnails'];
directories.forEach(dir => {
    if (!fsSync.existsSync(dir)) {
        fsSync.mkdirSync(dir, { recursive: true });
    }
});

// ===== BASE DE DATOS =====
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('❌ Error al conectar con la base de datos:', err);
    } else {
        console.log('✅ Conectado a la base de datos SQLite');
        initDatabase();
    }
});

// Promisificar métodos de la base de datos
const dbRun = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
};

const dbGet = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
};

const dbAll = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
};

// ===== INICIALIZAR BASE DE DATOS =====
async function initDatabase() {
    try {
        // Tabla de usuarios
        await dbRun(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                name TEXT,
                bio TEXT,
                avatar TEXT DEFAULT 'default_avatar.png',
                telegram_id TEXT UNIQUE,
                category_preference TEXT DEFAULT 'hetero',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Tabla de videos
        await dbRun(`
            CREATE TABLE IF NOT EXISTS videos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                category TEXT NOT NULL,
                video_path TEXT NOT NULL,
                thumbnail_path TEXT,
                duration INTEGER DEFAULT 0,
                views INTEGER DEFAULT 0,
                likes INTEGER DEFAULT 0,
                user_id INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);

        // Tabla de tokens de Telegram
        await dbRun(`
            CREATE TABLE IF NOT EXISTS telegram_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                expires_at DATETIME NOT NULL,
                used BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);

        console.log('✅ Base de datos inicializada correctamente');
    } catch (error) {
        console.error('❌ Error al inicializar la base de datos:', error);
    }
}

// ===== CONFIGURACIÓN DE MULTER =====
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 500 * 1024 * 1024 // 500MB
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['video/mp4', 'video/webm', 'video/ogg', 'video/quicktime', 'video/x-matroska'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Tipo de archivo no permitido'));
        }
    }
});

// ===== MIDDLEWARE DE AUTENTICACIÓN =====
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token no proporcionado' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await dbGet('SELECT id, username, email, name, bio, avatar, telegram_id, category_preference FROM users WHERE id = ?', [decoded.userId]);
        
        if (!user) {
            return res.status(401).json({ error: 'Usuario no encontrado' });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Token inválido' });
    }
};

// ===== FUNCIONES AUXILIARES =====

// Generar thumbnail de video
async function generateThumbnail(videoPath, thumbnailPath) {
    try {
        const command = `ffmpeg -i "${videoPath}" -ss 00:00:01 -vframes 1 -vf "scale=320:180:force_original_aspect_ratio=decrease,pad=320:180:(ow-iw)/2:(oh-ih)/2" "${thumbnailPath}"`;
        await execPromise(command);
        return true;
    } catch (error) {
        console.error('Error generando thumbnail:', error);
        return false;
    }
}

// Obtener duración del video
async function getVideoDuration(videoPath) {
    try {
        const command = `ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 "${videoPath}"`;
        const { stdout } = await execPromise(command);
        return Math.floor(parseFloat(stdout));
    } catch (error) {
        console.error('Error obteniendo duración:', error);
        return 0;
    }
}

// Generar token de Telegram
function generateTelegramToken() {
    return crypto.randomBytes(16).toString('hex');
}

// ===== RUTAS DE AUTENTICACIÓN =====

// Registro
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, email, name } = req.body;

        if (!username || !password || !email) {
            return res.status(400).json({ error: 'Faltan campos requeridos' });
        }

        // Verificar si el usuario ya existe
        const existingUser = await dbGet(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );

        if (existingUser) {
            return res.status(400).json({ error: 'El usuario o email ya existe' });
        }

        // Hash de la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insertar usuario
        const result = await dbRun(
            'INSERT INTO users (username, password, email, name) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, email, name || username]
        );

        // Generar token JWT
        const token = jwt.sign({ userId: result.lastID }, JWT_SECRET, { expiresIn: '7d' });

        // Obtener usuario creado
        const user = await dbGet('SELECT id, username, email, name, bio, avatar, category_preference FROM users WHERE id = ?', [result.lastID]);

        res.status(201).json({
            success: true,
            token,
            user
        });
    } catch (error) {
        console.error('Error en registro:', error);
        res.status(500).json({ error: 'Error al registrar usuario' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Faltan credenciales' });
        }

        // Buscar usuario
        const user = await dbGet(
            'SELECT * FROM users WHERE username = ? OR email = ?',
            [username, username]
        );

        if (!user) {
            return res.status(401).json({ error: 'Credenciales incorrectas' });
        }

        // Verificar contraseña
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ error: 'Credenciales incorrectas' });
        }

        // Generar token JWT
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });

        // Remover contraseña del objeto
        delete user.password;

        res.json({
            success: true,
            token,
            user
        });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ error: 'Error al iniciar sesión' });
    }
});

// Obtener usuario actual
app.get('/api/users/me', authenticateToken, (req, res) => {
    res.json(req.user);
});

// Actualizar preferencia de categoría
app.put('/api/users/update-category', authenticateToken, async (req, res) => {
    try {
        const { category } = req.body;

        if (!['hetero', 'bi', 'gay'].includes(category)) {
            return res.status(400).json({ error: 'Categoría inválida' });
        }

        await dbRun(
            'UPDATE users SET category_preference = ? WHERE id = ?',
            [category, req.user.id]
        );

        res.json({ success: true, category });
    } catch (error) {
        console.error('Error actualizando categoría:', error);
        res.status(500).json({ error: 'Error al actualizar categoría' });
    }
});

// ===== RUTAS DE VIDEOS =====

// Subir video
app.post('/api/videos/upload', authenticateToken, upload.single('video'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No se proporcionó ningún archivo' });
        }

        const { title, category } = req.body;
        const description = req.body.description || '';

        if (!category || !['hetero', 'bi', 'gay'].includes(category)) {
            await fs.unlink(req.file.path);
            return res.status(400).json({ error: 'Categoría inválida' });
        }

        // Usar nombre del archivo si no hay título
        const videoTitle = title && title.trim() ? title.trim() : path.parse(req.file.originalname).name;

        // Mover video a carpeta videos
        const videoFileName = req.file.filename;
        const videoPath = path.join('videos', videoFileName);
        await fs.rename(req.file.path, videoPath);

        // Generar thumbnail
        const thumbnailFileName = videoFileName.replace(path.extname(videoFileName), '.jpg');
        const thumbnailPath = path.join('thumbnails', thumbnailFileName);
        await generateThumbnail(videoPath, thumbnailPath);

        // Obtener duración
        const duration = await getVideoDuration(videoPath);

        // Guardar en base de datos
        const result = await dbRun(
            `INSERT INTO videos (title, description, category, video_path, thumbnail_path, duration, user_id) 
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [videoTitle, description, category, videoPath, thumbnailPath, duration, req.user.id]
        );

        // Obtener video creado
        const video = await dbGet('SELECT * FROM videos WHERE id = ?', [result.lastID]);

        res.status(201).json({
            success: true,
            video
        });
    } catch (error) {
        console.error('Error subiendo video:', error);
        if (req.file) {
            try {
                await fs.unlink(req.file.path);
            } catch (e) {
                console.error('Error eliminando archivo:', e);
            }
        }
        res.status(500).json({ error: 'Error al subir video' });
    }
});

// Obtener videos por categoría
app.get('/api/videos/:category', async (req, res) => {
    try {
        const { category } = req.params;

        if (!['hetero', 'bi', 'gay'].includes(category)) {
            return res.status(400).json({ error: 'Categoría inválida' });
        }

        const videos = await dbAll(
            `SELECT v.*, u.username as user_name, u.avatar as user_avatar 
             FROM videos v 
             JOIN users u ON v.user_id = u.id 
             WHERE v.category = ? 
             ORDER BY v.created_at DESC`,
            [category]
        );

        res.json({
            success: true,
            videos,
            pagination: {
                page: 1,
                totalPages: 1,
                total: videos.length
            }
        });
    } catch (error) {
        console.error('Error obteniendo videos:', error);
        res.status(500).json({ error: 'Error al obtener videos' });
    }
});

// Obtener todos los videos
app.get('/api/videos/all', async (req, res) => {
    try {
        const videos = await dbAll(
            `SELECT v.*, u.username as user_name, u.avatar as user_avatar 
             FROM videos v 
             JOIN users u ON v.user_id = u.id 
             ORDER BY v.created_at DESC`
        );

        res.json({
            success: true,
            videos
        });
    } catch (error) {
        console.error('Error obteniendo todos los videos:', error);
        res.status(500).json({ error: 'Error al obtener videos' });
    }
});

// Incrementar vistas de video
app.post('/api/videos/:id/view', async (req, res) => {
    try {
        const { id } = req.params;

        await dbRun('UPDATE videos SET views = views + 1 WHERE id = ?', [id]);

        res.json({ success: true });
    } catch (error) {
        console.error('Error incrementando vistas:', error);
        res.status(500).json({ error: 'Error al incrementar vistas' });
    }
});

// Obtener estadísticas por categoría
app.get('/api/stats/:category', async (req, res) => {
    try {
        const { category } = req.params;

        if (!['hetero', 'bi', 'gay'].includes(category)) {
            return res.status(400).json({ error: 'Categoría inválida' });
        }

        const result = await dbGet(
            'SELECT COUNT(*) as total, SUM(views) as total_views FROM videos WHERE category = ?',
            [category]
        );

        res.json({
            success: true,
            category,
            total: result.total || 0,
            total_views: result.total_views || 0
        });
    } catch (error) {
        console.error('Error obteniendo estadísticas:', error);
        res.status(500).json({ error: 'Error al obtener estadísticas' });
    }
});

// ===== RUTAS DE TELEGRAM =====

// Generar token de vinculación
app.post('/api/telegram/generate-link', authenticateToken, async (req, res) => {
    try {
        const token = generateTelegramToken();
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

        await dbRun(
            'INSERT INTO telegram_tokens (token, user_id, expires_at) VALUES (?, ?, ?)',
            [token, req.user.id, expiresAt.toISOString()]
        );

        const link = `https://t.me/${TELEGRAM_BOT_USERNAME}?start=${token}`;

        res.json({
            success: true,
            token,
            link,
            expires_at: expiresAt
        });
    } catch (error) {
        console.error('Error generando token de Telegram:', error);
        res.status(500).json({ error: 'Error al generar enlace' });
    }
});

// Verificar y vincular token de Telegram
app.post('/api/telegram/verify-token', async (req, res) => {
    try {
        const { token, telegram_id } = req.body;

        if (!token || !telegram_id) {
            return res.status(400).json({ error: 'Faltan parámetros' });
        }

        // Buscar token
        const tokenRecord = await dbGet(
            'SELECT * FROM telegram_tokens WHERE token = ? AND used = 0',
            [token]
        );

        if (!tokenRecord) {
            return res.status(404).json({ error: 'Token no encontrado o ya usado' });
        }

        // Verificar expiración
        if (new Date(tokenRecord.expires_at) < new Date()) {
            return res.status(400).json({ error: 'Token expirado' });
        }

        // Actualizar usuario con telegram_id
        await dbRun(
            'UPDATE users SET telegram_id = ? WHERE id = ?',
            [telegram_id, tokenRecord.user_id]
        );

        // Marcar token como usado
        await dbRun('UPDATE telegram_tokens SET used = 1 WHERE id = ?', [tokenRecord.id]);

        // Obtener usuario
        const user = await dbGet('SELECT id, username, email, name FROM users WHERE id = ?', [tokenRecord.user_id]);

        res.json({
            success: true,
            user
        });
    } catch (error) {
        console.error('Error verificando token:', error);
        res.status(500).json({ error: 'Error al verificar token' });
    }
});

// Obtener usuario por telegram_id
app.get('/api/telegram/user/:telegram_id', async (req, res) => {
    try {
        const { telegram_id } = req.params;

        const user = await dbGet(
            'SELECT id, username, email, name, category_preference FROM users WHERE telegram_id = ?',
            [telegram_id]
        );

        if (!user) {
            return res.status(404).json({ error: 'Usuario no vinculado' });
        }

        res.json({
            success: true,
            user
        });
    } catch (error) {
        console.error('Error obteniendo usuario:', error);
        res.status(500).json({ error: 'Error al obtener usuario' });
    }
});

// Subir video desde Telegram
app.post('/api/telegram/upload-video', async (req, res) => {
    try {
        const { telegram_id, title, category, video_url, file_id } = req.body;

        if (!telegram_id || !category) {
            return res.status(400).json({ error: 'Faltan parámetros' });
        }

        // Buscar usuario
        const user = await dbGet('SELECT id FROM users WHERE telegram_id = ?', [telegram_id]);

        if (!user) {
            return res.status(404).json({ error: 'Usuario no vinculado' });
        }

        // Aquí deberías descargar el video desde Telegram
        // Por ahora solo guardaremos la referencia
        const videoTitle = title || 'Video desde Telegram';

        const result = await dbRun(
            `INSERT INTO videos (title, category, video_path, user_id) 
             VALUES (?, ?, ?, ?)`,
            [videoTitle, category, file_id, user.id]
        );

        res.json({
            success: true,
            video_id: result.lastID
        });
    } catch (error) {
        console.error('Error subiendo video desde Telegram:', error);
        res.status(500).json({ error: 'Error al subir video' });
    }
});

// ===== RUTAS DE ARCHIVOS ESTÁTICOS =====

// Servir login.html
app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Servir web.html
app.get('/web.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'web.html'));
});

// Ruta raíz
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ===== MANEJO DE ERRORES =====
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: err.message || 'Error interno del servidor' });
});

// ===== INICIAR SERVIDOR =====
app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════╗
║     🔥 CalienXXX Server Iniciado 🔥          ║
╠═══════════════════════════════════════════════╣
║  Puerto:        ${PORT}                        ║
║  Base de datos: SQLite (database.db)          ║
║  Directorios:   ✓ uploads, videos, thumbnails║
╚═══════════════════════════════════════════════╝
    `);
    console.log(`\n✅ Servidor corriendo en http://localhost:${PORT}`);
    console.log(`📱 Login: http://localhost:${PORT}/login.html`);
    console.log(`🎬 Web: http://localhost:${PORT}/web.html\n`);
});

// Manejo de cierre graceful
process.on('SIGINT', () => {
    console.log('\n🛑 Cerrando servidor...');
    db.close((err) => {
        if (err) {
            console.error('Error cerrando la base de datos:', err);
        } else {
            console.log('✅ Base de datos cerrada correctamente');
        }
        process.exit(0);
    });
});