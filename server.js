import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const app = express();
const PORT = 3000;

// Дозволяємо запити лише з нашого фронтенду (localhost)
app.use(cors({ origin: `http://localhost:${PORT}` }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

const users = new Map();          // тимчасове сховище в пам’яті
const RP_NAME = 'Demo PWA';
const RP_ID   = 'localhost';     // має збігатися з доменом, на якому працює сайт

/* ------------------------------------------------------------------ */
/* --------------------------- Реєстрація --------------------------- */
/* ------------------------------------------------------------------ */
app.post('/generate-registration-options', async (req, res) => {
  const { username } = req.body;
  console.log('🔹 /generate-registration-options →', req.body);

  if (!users.has(username)) {
    users.set(username, { id: crypto.randomUUID(), credentials: [] });
  }
  const user = users.get(username);

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: user.id,
    userName: username,
    timeout: 60000,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'discouraged',   // ← зміна
    },
  });

  console.log('🔹 generated registration options:', options);
  user.currentChallenge = options.challenge;
  res.json(options);
});

/* ---------- verify-registration ---------- */
app.post('/verify-registration', async (req, res) => {
  const { username, attResp } = req.body;
  const user = users.get(username);
  if (!user) return res.status(400).send('User not found');

  try {
    const verification = await verifyRegistrationResponse({
      response: attResp,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: `http://localhost:${PORT}`,
      expectedRPID: RP_ID,
      expectedUserVerification: 'discouraged', // ← (опціонально)
    });

    if (verification.verified) {
      user.credentials.push(verification.registrationInfo);
    }
    res.json({ verified: verification.verified });
  } catch (e) {
    console.error('⚠️ verify-registration error:', e);
    res.status(400).json({ error: e.message });
  }
});

/* ------------------------------------------------------------------ */
/* ------------------------ Аутентифікація ------------------------- */
/* ------------------------------------------------------------------ */
app.post('/generate-authentication-options', async (req, res) => {
  const { username } = req.body;
  const user = users.get(username);

  if (!user || user.credentials.length === 0) {
    return res.status(400).send('User not registered');
  }

  const options = await generateAuthenticationOptions({
    timeout: 60000,
    allowCredentials: user.credentials.map(cred => ({
      id: cred.credentialID,
      type: 'public-key',
    })),
    userVerification: 'preferred',
  });

  user.currentChallenge = options.challenge;
  res.json(options);
});

app.post('/verify-authentication', async (req, res) => {
  const { username, authResp } = req.body;
  const user = users.get(username);
  if (!user) return res.status(400).send('User not found');

  try {
    const verification = await verifyAuthenticationResponse({
      response: authResp,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: `http://localhost:${PORT}`,
      expectedRPID: RP_ID,
      authenticator: user.credentials[0], // у демо‑версії беремо перший credential
    });

    res.json({ verified: verification.verified });
  } catch (e) {
    console.error('⚠️ verify-authentication error:', e);
    res.status(400).json({ error: e.message });
  }
});

/* ------------------------------------------------------------------ */
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));