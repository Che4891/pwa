/**
 * An example Express server showing off a simple integration of @simplewebauthn/server.
 *
 * The webpages served from ./public use @simplewebauthn/browser.
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const memoryStore = require('memorystore');
const dotenv = require('dotenv');

dotenv.config();

const {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} = require('@simplewebauthn/server');

const MemoryStore = memoryStore(session);

const {
  ENABLE_CONFORMANCE,
  ENABLE_HTTPS,
  RP_ID = 'localhost',
} = process.env;

const app = express();

/**
 * RP ID represents the "scope" of websites on which a credential should be usable. The Origin
 * represents the expected URL from which registration or authentication occurs.
 */
const rpID = RP_ID;
// This value is set at the bottom of page as part of server initialization (the empty string is
// to appease TypeScript until we determine the expected origin based on whether or not HTTPS
// support is enabled)
let expectedOrigin = '';

/**
 * In-memory database for users (replace with real database in production)
 */
const inMemoryUserDB = {};

/**
 * Helper function to get or create user
 */
function getUser(login) {
  const username = `${login}@${rpID}`;
  const userId = `user_${login}`;
  
  if (!inMemoryUserDB[userId]) {
    inMemoryUserDB[userId] = {
      id: userId,
      username: username,
      login: login,
      credentials: [],
    };
  }
  
  return inMemoryUserDB[userId];
}

app.use(express.static('./public/'));
app.use(express.json());
app.use(
  session({
    secret: 'secret123',
    saveUninitialized: true,
    resave: false,
    cookie: {
      maxAge: 86400000,
      httpOnly: true, // Ensure to not expose session cookies to clientside scripts
    },
    store: new MemoryStore({
      checkPeriod: 86400000, // prune expired entries every 24h
    }),
  }),
);

/**
 * If the words "metadata statements" mean anything to you, you'll want to enable this route. It
 * contains an example of a more complex deployment of SimpleWebAuthn with support enabled for the
 * FIDO Metadata Service. This enables greater control over the types of authenticators that can
 * interact with the Rely Party (a.k.a. "RP", a.k.a. "this server").
 */
if (ENABLE_CONFORMANCE === 'true') {
  require('./fido-conformance').then(
    ({ fidoRouteSuffix, fidoConformanceRouter }) => {
      app.use(fidoRouteSuffix, fidoConformanceRouter);
    },
  );
}

/**
 * Registration (a.k.a. "Registration")
 */
app.get('/generate-registration-options', async (req, res) => {
  // Get login from query parameter
  const login = req.query.login;
  console.log('server',login);
  
  if (!login) {
    return res.status(400).send({ error: 'Login parameter is required' });
  }

  const user = getUser(login);

  const {
    username,
    credentials,
  } = user;

  const opts = {
    rpName: 'SimpleWebAuthn Example',
    rpID,
    userName: username,
    timeout: 60000,
    attestationType: 'none',
    /**
     * Passing in a user's list of already-registered credential IDs here prevents users from
     * registering the same authenticator multiple times. The authenticator will simply throw an
     * error in the browser if it's asked to perform registration when it recognizes one of the
     * credential ID's.
     */
    excludeCredentials: credentials.map((cred) => ({
      id: cred.id,
      type: 'public-key',
      transports: cred.transports,
    })),
    authenticatorSelection: {
      residentKey: 'discouraged',
      /**
       * Wondering why user verification isn't required? See here:
       *
       * https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
       */
      userVerification: 'preferred',
    },
    /**
     * Support the two most common algorithms: ES256, and RS256
     */
    supportedAlgorithmIDs: [-7, -257],
  };

  const options = await generateRegistrationOptions(opts);

  /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify the registration response.
   */
  req.session.currentChallenge = options.challenge;
  req.session.currentUser = user.id;

  res.send(options);
});

app.post('/verify-registration', async (req, res) => {
  const body = req.body;

  // Get login and password from request body
  const { login, password } = body;
  
  if (!login) {
    return res.status(400).send({ error: 'Login is required' });
  }

  const user = getUser(login);
  const expectedChallenge = req.session.currentChallenge;

  // Store password (in production, hash it first!)
  user.password = password;
  console.log(`User registered: ${login}, password: ${password}`);

  let verification;
  try {
    const opts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: false,
    };
    verification = await verifyRegistrationResponse(opts);
  } catch (error) {
    const _error = error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    const { credential } = registrationInfo;

    const existingCredential = user.credentials.find((cred) => cred.id === credential.id);

    if (!existingCredential) {
      /**
       * Add the returned credential to the user's list of credentials
       */
      const newCredential = {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: body.response.transports,
      };
      user.credentials.push(newCredential);
    }
  }

  req.session.currentChallenge = undefined;
  req.session.currentUser = undefined;

  res.send({ verified });
});

/**
 * Login (a.k.a. "Authentication")
 */
app.get('/generate-authentication-options', async (req, res) => {
  // Get login from query parameter
  const login = req.query.login;
  
  if (!login) {
    return res.status(400).send({ error: 'Login parameter is required' });
  }

  const user = getUser(login);

  const opts = {
    timeout: 60000,
    allowCredentials: user.credentials.map((cred) => ({
      id: cred.id,
      type: 'public-key',
      transports: cred.transports,
    })),
    /**
     * Wondering why user verification isn't required? See here:
     *
     * https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
     */
    userVerification: 'preferred',
    rpID,
  };

  const options = await generateAuthenticationOptions(opts);

  /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify the authentication response.
   */
  req.session.currentChallenge = options.challenge;
  req.session.currentUser = user.id;

  res.send(options);
});

app.post('/verify-authentication', async (req, res) => {
  const body = req.body;

  // Get login and password from request body
  const { login, password } = body;
  
  if (!login) {
    return res.status(400).send({ error: 'Login is required' });
  }

  const user = getUser(login);
  const expectedChallenge = req.session.currentChallenge;

  // Verify password (in production, compare hashed passwords!)
  if (user.password !== password) {
    return res.status(401).send({ error: 'Invalid password' });
  }

  let dbCredential;
  // "Query the DB" here for a credential matching `cred.id`
  for (const cred of user.credentials) {
    if (cred.id === body.id) {
      dbCredential = cred;
      break;
    }
  }

  if (!dbCredential) {
    return res.status(400).send({
      error: 'Authenticator is not registered with this site',
    });
  }

  let verification;
  try {
    const opts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      credential: dbCredential,
      requireUserVerification: false,
    };
    verification = await verifyAuthenticationResponse(opts);
  } catch (error) {
    const _error = error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    // Update the credential's counter in the DB to the newest count in the authentication
    dbCredential.counter = authenticationInfo.newCounter;
  }

  req.session.currentChallenge = undefined;
  req.session.currentUser = undefined;

  res.send({ verified });
});

if (ENABLE_HTTPS) {
  const host = '0.0.0.0';
  const port = 443;
  expectedOrigin = `https://${rpID}`;

  https
    .createServer(
      {
        /**
         * See the README on how to generate this SSL cert and key pair using mkcert
         */
        key: fs.readFileSync(`./${rpID}.key`),
        cert: fs.readFileSync(`./${rpID}.crt`),
      },
      app,
    )
    .listen(port, host, () => {
      console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
    });
} else {
  const host = '127.0.0.1';
  const port = 8000;
  expectedOrigin = `http://localhost:${port}`;

  http.createServer(app).listen(port, host, () => {
    console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
  });
}

module.exports = {
  rpID,
  expectedOrigin,
};