import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import mysql from 'mysql2/promise';

/* ---------------------- DB connection ---------------------- */
const db = await mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'pwa_demo',
  port: 8889,
});
console.log('✅ DB connected');

/* ---------------------- Express setup ---------------------- */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

app.use(cors({ origin: `http://localhost:5500` })); // змінюй під фронт
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

const RP_NAME = 'Demo PWA';
const RP_ID = 'localhost';

/* ========================================================== */
/* ====================== РЕЄСТРАЦІЯ ======================== */
/* ========================================================== */
app.post('/generate-registration-options', async (req, res) => {
  const { username } = req.body;

  try {
    let [rows] = await db.execute('SELECT * FROM users WHERE username=?', [username]);

    if (rows.length === 0) {
      const userId = crypto.randomUUID();
      await db.execute('INSERT INTO users (id, username) VALUES (?, ?)', [userId, username]);
      [rows] = await db.execute('SELECT * FROM users WHERE username=?', [username]);
    }

    const user = rows[0];

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: Buffer.from(user.id, 'utf8'),
      userName: username,
      timeout: 60000,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'discouraged',
        userVerification: 'preferred',
      },
    });

    await db.execute('UPDATE users SET currentChallenge=? WHERE id=?', [
      options.challenge,
      user.id,
    ]);

    res.json(options);
  } catch (err) {
    console.error('❌ /generate-registration-options error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/verify-registration', async (req, res) => {
  const { username, ...attResp } = req.body;

  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE username=?', [username]);
    if (rows.length === 0) return res.status(400).send('User not found');

    const user = rows[0];

    const verification = await verifyRegistrationResponse({
      response: attResp,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: `http://localhost:${PORT}`,
      expectedRPID: RP_ID,
      requireUserVerification: false,
    });

    if (verification.verified) {
      const { registrationInfo } = verification;

      console.log('✅ registrationInfo:', registrationInfo);

      await db.execute(
        `INSERT INTO credentials 
         (user_id, credentialID, publicKey, counter, transports) 
         VALUES (?, ?, ?, ?, ?)`,
        [
          user.id,
          registrationInfo.credentialID || null,
          registrationInfo.credentialPublicKey || null,
          registrationInfo.counter ?? 0,
          JSON.stringify(registrationInfo.transports || []),
        ]
      );
    }

    res.json({ verified: verification.verified });
  } catch (err) {
    console.error('❌ verify-registration error:', err);
    res.status(500).json({ error: err.message });
  }
});

/* ========================================================== */
/* ================== АУТЕНТИФІКАЦІЯ ======================== */
/* ========================================================== */
app.post('/generate-authentication-options', async (req, res) => {
  const { username } = req.body;

  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE username=?', [username]);
    if (rows.length === 0) return res.status(400).send('User not found');

    const user = rows[0];
    const [creds] = await db.execute('SELECT * FROM credentials WHERE user_id=?', [user.id]);
    if (creds.length === 0) return res.status(400).send('No credentials');

    const options = await generateAuthenticationOptions({
      timeout: 60000,
      allowCredentials: creds.map(c => ({
        id: isoBase64URL.fromBuffer(c.credentialID), // ✅ конвертуємо Buffer → Base64URL
        type: 'public-key',
      })),
      userVerification: 'preferred',
    });

    await db.execute('UPDATE users SET currentChallenge=? WHERE id=?', [
      options.challenge,
      user.id,
    ]);

    res.json(options);
  } catch (err) {
    console.error('❌ /generate-authentication-options error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/verify-authentication', async (req, res) => {
  const { username, ...authResp } = req.body;

  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE username=?', [username]);
    if (rows.length === 0) return res.status(400).send('User not found');

    const user = rows[0];
    const [creds] = await db.execute('SELECT * FROM credentials WHERE user_id=?', [user.id]);
    if (creds.length === 0) return res.status(400).send('No credentials');

    const cred = creds[0];

    const verification = await verifyAuthenticationResponse({
      response: authResp,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: `http://localhost:${PORT}`,
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: cred.credentialID,         // ✅ Buffer напряму
        credentialPublicKey: cred.publicKey,     // ✅ Buffer напряму
        counter: cred.counter,
      },
      requireUserVerification: false,
    });

    if (verification.verified) {
      await db.execute('UPDATE credentials SET counter=? WHERE id=?', [
        verification.authenticationInfo.newCounter,
        cred.id,
      ]);
    }

    res.json({ verified: verification.verified });
  } catch (err) {
    console.error('⚠️ verify-authentication error:', err);
    res.status(400).json({ error: err.message });
  }
});

/* ========================================================== */
app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);
