// server.js
const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
app.use(express.json({ limit: '1mb' }));

// Просте cookie-session (для локального тесту secure:false)
app.use(session({
  secret: 'replace-with-a-strong-secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// Serve static files (index.html + js)
app.use(express.static(path.join(__dirname, '/')));

// RP (relying party) конфігурація
const rpName = 'Foobar Corp.';
const rpID = 'localhost';
const rpOrigin = 'http://localhost:8080';

// Простенька in-memory "база"
const userDB = new Map();

/* --- утиліти для base64/url конвертацій --- */
function toBase64url(buffer) {
  if (!buffer) return '';
  return Buffer.from(buffer).toString('base64')
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function base64urlToBase64(input) {
  if (!input) return '';
  let s = input.replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4) s += '=';
  return s;
}
function base64ToBase64url(input) {
  if (!input) return '';
  return input.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

/* --- create user helper --- */
function createUser(username) {
  return {
    id: crypto.randomBytes(16), // Buffer
    username,
    displayName: username.split('@')[0] || username,
    credentials: []
  };
}

/* --- ROUTES --- */

// Begin registration
app.get('/register/begin/:username', (req, res) => {
  const username = req.params.username;
  if (!username) return res.status(400).json({ error: 'Username required' });

  let user = userDB.get(username);
  if (!user) {
    user = createUser(username);
    userDB.set(username, user);
  }

  const opts = generateRegistrationOptions({
    rpName,
    rpID,
    userID: user.id,
    userName: username,
    userDisplayName: user.displayName,
    timeout: 60000,
    attestationType: 'direct',
    authenticatorSelection: { userVerification: 'preferred' },
    excludeCredentials: user.credentials.map(c => ({
      id: c.credentialID,
      type: 'public-key'
    }))
  });

  // збережемо challenge
  req.session.challenge = opts.challenge;
  console.log("REG:", req);

  const publicKey = { ...opts };

  console.log('➡️ /register/begin response:', publicKey);
  res.json({ publicKey });
});

// Finish registration
app.post('/register/finish/:username', async (req, res) => {
  const username = req.params.username;
  const body = req.body;

  console.log('➡️ /register/finish body:', body);

  const user = userDB.get(username);
  if (!user) return res.status(400).json({ error: 'User not found' });

  try {
    const verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge: req.session.challenge,
      expectedOrigin: rpOrigin,
      expectedRPID: rpID,
    });

    const { verified, registrationInfo } = verification;
    if (!verified) return res.status(400).json({ error: 'Registration not verified' });

    const { credentialPublicKey, credentialID, counter } = registrationInfo;

    const credentialID_b64url = toBase64url(credentialID);
    const credentialPublicKey_b64url = toBase64url(credentialPublicKey);

    user.credentials.push({
      credentialID: credentialID_b64url,
      credentialPublicKey: credentialPublicKey_b64url,
      counter,
    });

    console.log(`✅ User ${username} registered credential:`, credentialID_b64url);
    return res.json({ status: 'ok' });
  } catch (e) {
    console.error('❌ Registration error:', e);
    return res.status(400).json({ error: e.toString() });
  }
});

// Begin login
app.get('/login/begin/:username', (req, res) => {
  const username = req.params.username;
  const user = userDB.get(username);
  if (!user) return res.status(400).json({ error: 'User not found' });

  const opts = generateAuthenticationOptions({
    timeout: 60000,
    rpID,
    userVerification: 'preferred',
    allowCredentials: user.credentials.map(c => ({
      id: c.credentialID,
      type: 'public-key'
    }))
  });

  req.session.challenge = opts.challenge;

  const publicKey = { ...opts };

  console.log('➡️ /login/begin response:', publicKey);
  res.json({ publicKey });
});

// Finish login
app.post('/login/finish/:username', async (req, res) => {
  const username = req.params.username;
  const body = req.body;

  console.log('➡️ /login/finish body:', body);

  const user = userDB.get(username);
  if (!user) return res.status(400).json({ error: 'User not found' });

  try {
    const rawId_b64url = body.rawId;
    const authenticator = user.credentials.find(
      c => c.credentialID === rawId_b64url || c.credentialID === body.id
    );

    if (!authenticator) return res.status(400).json({ error: 'Authenticator not registered' });

    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge: req.session.challenge,
      expectedOrigin: rpOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: authenticator.credentialID,
        credentialPublicKey: authenticator.credentialPublicKey,
        counter: authenticator.counter,
      },
    });

    const { verified, authenticationInfo } = verification;
    if (!verified) return res.status(400).json({ error: 'Authentication failed' });

    authenticator.counter = authenticationInfo.newCounter;

    console.log(`✅ User ${username} authenticated successfully`);
    return res.json({ status: 'ok' });
  } catch (e) {
    console.error('❌ Login error:', e);
    return res.status(400).json({ error: e.toString() });
  }
});

const port = 8080;
app.listen(port, () => {
  console.log(`🚀 Server started at http://localhost:${port}`);
});
