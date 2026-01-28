const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const db = require('./database');

const app = express();
const PORT = 3000;

// Configuración
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(session({
    secret: 'mi-secreto-super-seguro',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000 } // 1 hora
}));

const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// Ruta principal - redirige al dashboard si está logueado
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
    } else {
        res.send(`
            <h1>Sistema con 2FA</h1>
            <a href="/register">Registrarse</a> | <a href="/login">Iniciar sesión</a>
        `);
    }
});

// API: Obtener información del usuario
app.get('/api/user-info', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'No autenticado' });
    }
    
    db.get('SELECT id, email, is_2fa_enabled FROM users WHERE id = ?', 
        [req.session.userId], 
        (err, user) => {
            if (err || !user) {
                return res.status(404).json({ error: 'Usuario no encontrado' });
            }
            res.json(user);
        }
    );
});

// Cerrar sesión
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});
const bcrypt = require('bcrypt');

// Servir página de registro
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'register.html'));
});

// API de registro
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    
    // Validaciones básicas
    if (!email || !password) {
        return res.status(400).json({ error: 'Email y contraseña son requeridos' });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
    }
    
    try {
        // Encriptar contraseña
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Insertar usuario en la base de datos
        db.run(
            'INSERT INTO users (email, password) VALUES (?, ?)',
            [email, hashedPassword],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({ error: 'El email ya está registrado' });
                    }
                    return res.status(500).json({ error: 'Error al registrar usuario' });
                }
                
                res.json({ 
                    message: 'Usuario registrado correctamente. Redirigiendo al login...',
                    userId: this.lastID 
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// Servir página de login
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email y contraseña son requeridos' });
    }
    
    // Buscar usuario en la base de datos
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Error en el servidor' });
        }
        
        if (!user) {
            return res.status(401).json({ error: 'Credenciales incorrectas' });
        }
        
        // Verificar contraseña
        const passwordMatch = await bcrypt.compare(password, user.password);
        
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Credenciales incorrectas' });
        }
        
        // Si tiene 2FA activado, no iniciar sesión todavía
        if (user.is_2fa_enabled) {
            // Guardar temporalmente el ID del usuario
            req.session.tempUserId = user.id;
            req.session.tempEmail = user.email;
            
            return res.json({
                requires2FA: true,
                tempUserId: user.id,
                message: 'Credenciales correctas. Introduce tu código 2FA.'
            });
        }
        
        // Si no tiene 2FA, iniciar sesión directamente
        req.session.userId = user.id;
        req.session.email = user.email;
        
        res.json({ 
            message: 'Login exitoso',
            user: {
                id: user.id,
                email: user.email
            }
        });
    });
});
// Verificar código 2FA durante el login
app.post('/api/login/verify-2fa', (req, res) => {
    const { token, tempUserId } = req.body;
    
    if (!req.session.tempUserId || req.session.tempUserId !== tempUserId) {
        return res.status(401).json({ error: 'Sesión no válida. Vuelve a iniciar sesión.' });
    }
    
    db.get('SELECT * FROM users WHERE id = ?', [tempUserId], (err, user) => {
        if (err || !user) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        
        // Verificar límite de intentos
        const MAX_ATTEMPTS = 3;
        const LOCKOUT_TIME = 60000; // 1 minuto en milisegundos
        const now = Date.now();
        
        if (user.failed_attempts >= MAX_ATTEMPTS) {
            const timeSinceLastAttempt = now - (user.last_attempt_time || 0);
            
            if (timeSinceLastAttempt < LOCKOUT_TIME) {
                const remainingTime = Math.ceil((LOCKOUT_TIME - timeSinceLastAttempt) / 1000);
                return res.status(429).json({ 
                    error: `Demasiados intentos fallidos. Espera ${remainingTime} segundos.`,
                    blocked: true
                });
            } else {
                // Resetear intentos después del tiempo de bloqueo
                db.run('UPDATE users SET failed_attempts = 0 WHERE id = ?', [user.id]);
            }
        }
        
        // Verificar el token 2FA
        const verified = speakeasy.totp.verify({
            secret: user.secret_2fa,
            encoding: 'base32',
            token: token,
            window: 1
        });
        
        if (!verified) {
            // Incrementar intentos fallidos
            const newAttempts = (user.failed_attempts || 0) + 1;
            
            db.run(
                'UPDATE users SET failed_attempts = ?, last_attempt_time = ? WHERE id = ?',
                [newAttempts, now, user.id],
                (err) => {
                    const attemptsLeft = MAX_ATTEMPTS - newAttempts;
                    
                    if (attemptsLeft <= 0) {
                        return res.status(401).json({ 
                            error: 'Código incorrecto. Has alcanzado el límite de intentos. Vuelve a iniciar sesión en 1 minuto.',
                            blocked: true,
                            attemptsLeft: 0
                        });
                    }
                    
                    return res.status(401).json({ 
                        error: 'Código incorrecto',
                        attemptsLeft: attemptsLeft
                    });
                }
            );
        } else {
            // Código correcto - Resetear intentos e iniciar sesión
            db.run('UPDATE users SET failed_attempts = 0, last_attempt_time = NULL WHERE id = ?', [user.id]);
            
            // Establecer sesión real
            req.session.userId = user.id;
            req.session.email = user.email;
            
            // Limpiar sesión temporal
            delete req.session.tempUserId;
            delete req.session.tempEmail;
            
            res.json({ 
                message: 'Autenticación exitosa',
                user: {
                    id: user.id,
                    email: user.email
                }
            });
        }
    });
});



// Iniciar servidor

// ============== RUTAS 2FA ==============

// Configurar 2FA - Genera el secreto y el QR
app.post('/api/2fa/setup', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'No autenticado' });
    }
    
    db.get('SELECT * FROM users WHERE id = ?', [req.session.userId], async (err, user) => {
        if (err || !user) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        
        // Generar secreto
        const secret = speakeasy.generateSecret({
            name: `MiApp2FA (${user.email})`,
            length: 32
        });
        
        // Guardar el secreto temporalmente en la sesión
        req.session.tempSecret = secret.base32;
        
        // Generar código QR
        try {
            const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
            res.json({
                qrCode: qrCodeUrl,
                secret: secret.base32
            });
        } catch (error) {
            res.status(500).json({ error: 'Error al generar código QR' });
        }
    });
});

// Verificar código y activar 2FA
app.post('/api/2fa/verify-setup', (req, res) => {
    if (!req.session.userId || !req.session.tempSecret) {
        return res.status(401).json({ error: 'No autenticado o sesión expirada' });
    }
    
    const { token } = req.body;
    
    // Verificar el token
    const verified = speakeasy.totp.verify({
        secret: req.session.tempSecret,
        encoding: 'base32',
        token: token,
        window: 2 // Permite 2 códigos antes/después (60 segundos de margen)
    });
    
    if (!verified) {
        return res.status(400).json({ error: 'Código incorrecto. Inténtalo de nuevo.' });
    }
    
    // Guardar el secreto en la base de datos y activar 2FA
    db.run(
        'UPDATE users SET secret_2fa = ?, is_2fa_enabled = 1 WHERE id = ?',
        [req.session.tempSecret, req.session.userId],
        (err) => {
            if (err) {
                return res.status(500).json({ error: 'Error al activar 2FA' });
            }
            
            // Limpiar secreto temporal
            delete req.session.tempSecret;
            
            res.json({ message: '2FA activado correctamente' });
        }
    );
});

// Desactivar 2FA
app.post('/api/2fa/disable', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'No autenticado' });
    }
    
    db.run(
        'UPDATE users SET secret_2fa = NULL, is_2fa_enabled = 0, failed_attempts = 0 WHERE id = ?',
        [req.session.userId],
        (err) => {
            if (err) {
                return res.status(500).json({ error: 'Error al desactivar 2FA' });
            }
            
            res.json({ message: '2FA desactivado correctamente' });
        })
});
    
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});