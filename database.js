const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

// Crear/conectar a la base de datos
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error('Error al conectar con la base de datos:', err);
    } else {
        console.log('Conectado a la base de datos SQLite');
    }
});

// Crear tabla de usuarios
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            secret_2fa TEXT,
            is_2fa_enabled INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            last_attempt_time INTEGER
        )
    `, (err) => {
        if (err) {
            console.error('Error al crear tabla:', err);
        } else {
            console.log('Tabla users creada o ya existe');
        }
    });
});

module.exports = db;