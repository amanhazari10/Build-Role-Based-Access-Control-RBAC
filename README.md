# Build Role-Based Access Control with Admin, User, and Moderator Roles

## Objective
Learn how to implement role-based access control (RBAC) in a Node.js and Express application to restrict access to routes/actions based on user roles.

This guide shows how to:
- Store user roles (Admin, User, Moderator) in JWT tokens
- Authenticate users and issue JWTs
- Build RBAC middleware to authorize routes by role
- Protect Admin-only, Moderator-only, and User routes
- Return clear errors for invalid/insufficient tokens
- Test end-to-end with sample users and requests

---

## Tech Stack
- Node.js 18+
- Express 4+
- jsonwebtoken
- bcryptjs (mock password hashing)
- dotenv

---

## Project Setup

1) Initialize project
- npm init -y
- npm i express jsonwebtoken bcryptjs dotenv
- npm i -D nodemon

2) Add scripts in package.json
- "dev": "nodemon src/server.js"
- "start": "node src/server.js"

3) Project structure
- src/
  - server.js
  - auth/
    - auth.controller.js
    - auth.routes.js
    - auth.service.js
    - rbac.js
    - jwt.js
  - users/
    - users.store.js
  - middleware/
    - error.js
  - config/
    - env.js

---

## Environment Variables (.env)
- PORT=3000
- JWT_SECRET=super_secret_change_me
- JWT_EXPIRES_IN=1h

---

## Core Code

Create the following files under src/ as shown above.

1) src/config/env.js
- require('dotenv').config();
- module.exports = {
  - port: process.env.PORT || 3000,
  - jwtSecret: process.env.JWT_SECRET || 'dev_secret',
  - jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1h',
- };

2) src/users/users.store.js (in-memory users for demo)
- const bcrypt = require('bcryptjs');
- const users = [
  - { id: 1, name: 'Alice Admin', email: 'admin@example.com', password: bcrypt.hashSync('Admin@123', 10), role: 'ADMIN' },
  - { id: 2, name: 'Mark Moderator', email: 'mod@example.com', password: bcrypt.hashSync('Mod@123', 10), role: 'MODERATOR' },
  - { id: 3, name: 'Uma User', email: 'user@example.com', password: bcrypt.hashSync('User@123', 10), role: 'USER' },
- ];
- module.exports = { users };

3) src/auth/jwt.js
- const jwt = require('jsonwebtoken');
- const { jwtSecret, jwtExpiresIn } = require('../config/env');
- const signToken = (payload) => jwt.sign(payload, jwtSecret, { expiresIn: jwtExpiresIn });
- const verifyToken = (token) => jwt.verify(token, jwtSecret);
- module.exports = { signToken, verifyToken };

4) src/auth/rbac.js
- const ROLES = {
  - ADMIN: 'ADMIN',
  - MODERATOR: 'MODERATOR',
  - USER: 'USER',
- };
- const allowRoles = (...allowed) => (req, res, next) => {
  - try {
    - if (!req.user) return res.status(401).json({ error: 'Unauthorized: no user in context' });
    - if (!allowed.includes(req.user.role)) {
      - return res.status(403).json({ error: 'Forbidden: insufficient role', required: allowed, got: req.user.role });
    - }
    - return next();
  - } catch (e) { return next(e); }
- };
- module.exports = { ROLES, allowRoles };

5) src/auth/auth.service.js
- const bcrypt = require('bcryptjs');
- const { users } = require('../users/users.store');
- const { signToken } = require('./jwt');
- async function authenticate(email, password) {
  - const user = users.find(u => u.email === email);
  - if (!user) return null;
  - const ok = await bcrypt.compare(password, user.password);
  - if (!ok) return null;
  - const token = signToken({ sub: user.id, role: user.role, email: user.email, name: user.name });
  - return { token, user: { id: user.id, name: user.name, email: user.email, role: user.role } };
- }
- module.exports = { authenticate };

6) src/auth/auth.controller.js
- const { verifyToken } = require('./jwt');
- const { authenticate } = require('./auth.service');
- async function login(req, res, next) {
  - try {
    - const { email, password } = req.body || {};
    - if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
    - const result = await authenticate(email, password);
    - if (!result) return res.status(401).json({ error: 'Invalid credentials' });
    - return res.json(result);
  - } catch (e) { next(e); }
- }
- function jwtGuard(req, res, next) {
  - const header = req.headers.authorization || '';
  - const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  - if (!token) return res.status(401).json({ error: 'Missing Bearer token' });
  - try {
    - const decoded = verifyToken(token);
    - req.user = decoded; // { sub, role, email, name }
    - return next();
  - } catch (e) {
    - return res.status(401).json({ error: 'Invalid or expired token' });
  - }
- }
- module.exports = { login, jwtGuard };

7) src/auth/auth.routes.js
- const express = require('express');
- const router = express.Router();
- const { login, jwtGuard } = require('./auth.controller');
- const { allowRoles, ROLES } = require('./rbac');
- router.post('/login', login);
- router.get('/admin', jwtGuard, allowRoles(ROLES.ADMIN), (req, res) => {
  - res.json({ message: 'Welcome Admin dashboard', user: req.user });
- });
- router.get('/moderator', jwtGuard, allowRoles(ROLES.ADMIN, ROLES.MODERATOR), (req, res) => {
  - res.json({ message: 'Moderator management area', user: req.user });
- });
- router.get('/profile', jwtGuard, allowRoles(ROLES.ADMIN, ROLES.MODERATOR, ROLES.USER), (req, res) => {
  - res.json({ message: 'User profile', user: req.user });
- });
- module.exports = router;

8) src/middleware/error.js
- function errorHandler(err, req, res, next) {
  - /* eslint-disable no-unused-vars */
  - console.error(err);
  - const status = err.status || 500;
  - res.status(status).json({ error: err.message || 'Internal Server Error' });
- }
- module.exports = { errorHandler };

9) src/server.js
- const express = require('express');
- const morgan = require('morgan');
- const cors = require('cors');
- const { port } = require('./config/env');
- const authRoutes = require('./auth/auth.routes');
- const { errorHandler } = require('./middleware/error');
- const app = express();
- app.use(cors());
- app.use(express.json());
- app.use(morgan('dev'));
- app.get('/', (req, res) => res.json({ status: 'ok', service: 'rbac-demo' }));
- app.use('/api', authRoutes);
- app.use(errorHandler);
- app.listen(port, () => console.log(`RBAC server running on http://localhost:${port}`));

---

## How RBAC Works Here
- On login, we embed the user role inside the JWT payload.
- Each protected route first runs jwtGuard to verify the token and attach req.user.
- allowRoles middleware checks req.user.role against the allowed list.
- If role is not allowed -> 403 with clear message.
- If token is missing/invalid -> 401 with clear message.

---

## Example Login Flows

Request: POST /api/login
- Body: { "email": "admin@example.com", "password": "Admin@123" }
- Response: { token, user: { id, name, email, role: "ADMIN" } }

Request: POST /api/login
- Body: { "email": "mod@example.com", "password": "Mod@123" }
- Response: role "MODERATOR"

Request: POST /api/login
- Body: { "email": "user@example.com", "password": "User@123" }
- Response: role "USER"

Use token as Authorization: Bearer <token>

---

## Testing Protected Routes

- GET /api/admin
  - Allowed: ADMIN only
- GET /api/moderator
  - Allowed: ADMIN, MODERATOR
- GET /api/profile
  - Allowed: ADMIN, MODERATOR, USER

Curl examples
- ADMIN dashboard:
  - curl -s -X POST http://localhost:3000/api/login -H "Content-Type: application/json" -d '{"email":"admin@example.com","password":"Admin@123"}' | jq -r .token | xargs -I {} curl -s http://localhost:3000/api/admin -H "Authorization: Bearer {}" | jq
- MODERATOR area:
  - curl -s -X POST http://localhost:3000/api/login -H "Content-Type: application/json" -d '{"email":"mod@example.com","password":"Mod@123"}' | jq -r .token | xargs -I {} curl -s http://localhost:3000/api/moderator -H "Authorization: Bearer {}" | jq
- USER profile:
  - curl -s -X POST http://localhost:3000/api/login -H "Content-Type: application/json" -d '{"email":"user@example.com","password":"User@123"}' | jq -r .token | xargs -I {} curl -s http://localhost:3000/api/profile -H "Authorization: Bearer {}" | jq

Common failure cases
- Missing token -> 401 { error: 'Missing Bearer token' }
- Expired/invalid token -> 401 { error: 'Invalid or expired token' }
- Insufficient role -> 403 { error: 'Forbidden: insufficient role' }

---

## Security Notes
- Always store JWT_SECRET securely (environment or secret manager)
- Prefer HTTPS in production
- Use proper password policies and rate limiting
- Replace in-memory users with a persistent DB (Postgres, MongoDB, etc.)
- Consider permission-based checks for finer-grained control

---

## Running the Project
- Copy .env.example to .env and fill values (see Environment Variables)
- npm run dev
- Visit GET / to verify service is running
- Use the login endpoints as shown above

---

## Reference Images
- https://s3.ap-south-1.amazonaws.com/static.bytexl.app/uploads/42vxd5kz7/content/43qnt88p4/7.png
- https://s3.ap-south-1.amazonaws.com/static.bytexl.app/uploads/42vxd5kz7/content/43qnt88p4/8.png
- https://s3.ap-south-1.amazonaws.com/static.bytexl.app/uploads/42vxd5kz7/content/43qnt88p4/9.png
- https://s3.ap-south-1.amazonaws.com/static.bytexl.app/uploads/42vxd5kz7/content/43qnt88p4/10.png
