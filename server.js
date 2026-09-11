import fs from 'node:fs/promises';
import path from 'node:path';
import { randomInt, randomUUID, X509Certificate } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import express from 'express';
import cors from 'cors';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const serverDirectory = path.dirname(fileURLToPath(import.meta.url));
const settingsText = await fs.readFile(path.join(serverDirectory, 'mysql.txt'), 'utf8');
const settings = Object.fromEntries(
  settingsText.split(/\r?\n/).filter(Boolean).map((line) => {
    const match = line.match(/^\s*(?:MySql\s+)?(username|password|hostname|port|Database name|Table name)\s+(.+)$/i);
    return match ? [match[1].toLowerCase().replaceAll(' ', '_'), match[2].trim()] : [];
  }).filter((entry) => entry.length),
);

const tableName = settings.table_name;
if (!tableName || !/^[a-zA-Z0-9_]+$/.test(tableName)) {
  throw new Error('mysql.txt must contain a valid MySql Table name');
}

const rejectUnauthorized = process.env.MYSQL_SSL_REJECT_UNAUTHORIZED !== 'false';
const jwtSecret = process.env.JWT_SECRET ?? 'local-development-only-change-this-secret';
const caCertificate = await fs.readFile(path.join(serverDirectory, 'ca.pem'), 'utf8');
new X509Certificate(caCertificate);

const pool = mysql.createPool({
  host: settings.hostname,
  user: settings.username,
  password: settings.password,
  port: Number(settings.port),
  database: settings.database_name,
  waitForConnections: true,
  connectionLimit: 5,
  ssl: { ca: caCertificate, rejectUnauthorized },
});

await pool.query(`CREATE TABLE IF NOT EXISTS \`${tableName}\` (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(120) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

const app = express();
app.use(cors());
app.use(express.json({ limit: '10kb' }));

const captchaChallenges = new Map();
const captchaLifetimeMs = 5 * 60 * 1000;

app.get('/api/captcha', (_request, response) => {
  const firstNumber = randomInt(2, 10);
  const secondNumber = randomInt(2, 10);
  const id = randomUUID();
  captchaChallenges.set(id, {
    answer: String(firstNumber + secondNumber),
    expiresAt: Date.now() + captchaLifetimeMs,
  });
  return response.json({ id, question: `What is ${firstNumber} + ${secondNumber}?` });
});

function isCaptchaValid(body) {
  const { captchaId, captchaAnswer } = body ?? {};
  if (typeof captchaId !== 'string' || typeof captchaAnswer !== 'string') return false;

  const challenge = captchaChallenges.get(captchaId);
  captchaChallenges.delete(captchaId);
  return challenge !== undefined && challenge.expiresAt > Date.now() && captchaAnswer.trim() === challenge.answer;
}

app.get('/api/health', (_request, response) => response.json({ ok: true }));

function authenticate(request, response, next) {
  const authorization = request.get('authorization') ?? '';
  const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : null;
  if (!token) return response.status(401).json({ message: 'Authentication required.' });

  try {
    request.user = jwt.verify(token, jwtSecret);
    return next();
  } catch {
    return response.status(401).json({ message: 'Your session has expired. Please sign in again.' });
  }
}

app.post('/api/register', async (request, response) => {
  const { name, email, password } = request.body ?? {};
  if (!isCaptchaValid(request.body)) {
    return response.status(400).json({ message: 'Please complete the CAPTCHA correctly.' });
  }
  if (typeof name !== 'string' || name.trim().length < 2 || typeof email !== 'string' || typeof password !== 'string' || password.length < 8) {
    return response.status(400).json({ message: 'Name, valid email, and an 8-character password are required.' });
  }

  try {
    const normalizedEmail = email.trim().toLowerCase();
    const [existingUsers] = await pool.execute(`SELECT id FROM \`${tableName}\` WHERE email = ? LIMIT 1`, [normalizedEmail]);
    if (existingUsers.length > 0) {
      return response.status(409).json({ message: 'This email is already registered. Please use another email or sign in.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    await pool.execute(`INSERT INTO \`${tableName}\` (name, email, password_hash, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)`, [name.trim(), normalizedEmail, passwordHash]);
    return response.status(201).json({ message: 'Account created. You can now sign in.' });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') return response.status(409).json({ message: 'An account with that email already exists.' });
    console.error(error);
    return response.status(500).json({ message: 'Could not create the account.' });
  }
});

app.post('/api/login', async (request, response) => {
  const { email, password } = request.body ?? {};
  if (!isCaptchaValid(request.body)) {
    return response.status(400).json({ message: 'Please complete the CAPTCHA correctly.' });
  }
  if (typeof email !== 'string' || typeof password !== 'string') {
    return response.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    const [rows] = await pool.execute(`SELECT id, name, email, password_hash FROM \`${tableName}\` WHERE email = ? LIMIT 1`, [email.trim().toLowerCase()]);
    const user = rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return response.status(401).json({ message: 'Email or password is incorrect.' });
    }
    const token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: '8h' });
    return response.json({ message: `Welcome back, ${user.name}.`, token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (error) {
    console.error(error);
    return response.status(500).json({ message: 'Could not complete sign in.' });
  }
});

app.patch('/api/me', authenticate, async (request, response) => {
  const { name, password } = request.body ?? {};
  if (typeof name !== 'string' || name.trim().length < 2) {
    return response.status(400).json({ message: 'Name must contain at least 2 characters.' });
  }
  if (password !== undefined && (typeof password !== 'string' || password.length < 8)) {
    return response.status(400).json({ message: 'A new password must contain at least 8 characters.' });
  }

  try {
    if (password) {
      const passwordHash = await bcrypt.hash(password, 12);
      await pool.execute(`UPDATE \`${tableName}\` SET name = ?, password_hash = ? WHERE id = ?`, [name.trim(), passwordHash, request.user.id]);
    } else {
      await pool.execute(`UPDATE \`${tableName}\` SET name = ? WHERE id = ?`, [name.trim(), request.user.id]);
    }
    return response.json({ message: 'Your account has been updated.', user: { name: name.trim() } });
  } catch (error) {
    console.error(error);
    return response.status(500).json({ message: 'Could not update your account.' });
  }
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => console.log(`Auth API listening on http://localhost:${port}`));
