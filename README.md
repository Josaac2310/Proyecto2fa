Sistema de Autenticación con 2FA

Sistema completo de registro, login y autenticación de dos factores (2FA) usando TOTP.

Características

-  Registro de usuarios con contraseñas encriptadas (bcrypt)
-  Login tradicional con sesiones
-  Autenticación de dos factores (2FA) con código QR
-  Compatible con Google Authenticator, Authy, Microsoft Authenticator
-  Límite de 3 intentos fallidos
-  Bloqueo temporal de 60 segundos tras fallos
-  Activar/Desactivar 2FA desde el dashboard

 Tecnologías

- Node.js + Express
- SQLite
- Speakeasy (TOTP)
- QRCode
- Bcrypt
- Express-session

 
Instalación

# Clonar repositorio
git clone https://github.com/TU-USUARIO/proyecto-2fa.git
cd proyecto-2fa

# Instalar dependencias
npm install

# Iniciar servidor
node server.js


Abre http://localhost:3000
