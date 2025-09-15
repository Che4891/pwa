const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

const usernameInput = document.getElementById('username');
const registerBtn = document.getElementById('register');
const loginBtn = document.getElementById('login');
const output = document.getElementById('output');

function log(msg) {
  output.textContent += msg + '\n';
}

// ---------- Реєстрація ----------
registerBtn.addEventListener('click', async () => {
  output.textContent = ''
  const username = usernameInput.value.trim();
  if (!username) return alert('Enter username');

  // 1. Отримуємо опції
  const resp = await fetch('/generate-registration-options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username }),
  });
  const options = await resp.json();

  // 2. Створюємо credential
  const attResp = await startRegistration({ optionsJSON: options });

  // 3. Відправляємо credential на сервер
  const verificationResp = await fetch('/verify-registration', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, ...attResp }),
  });
  const verificationJSON = await verificationResp.json();

  log('Registration verified: ' + verificationJSON.verified);
});

// ---------- Логін ----------
loginBtn.addEventListener('click', async () => {
  output.textContent = ''

  const username = usernameInput.value.trim();
  if (!username) return alert('Enter username');

  // 1. Отримуємо опції
  const resp = await fetch('/generate-authentication-options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username }),
  });
  const options = await resp.json();

  // 2. Виконуємо логін
  const authResp = await startAuthentication({ optionsJSON: options });

  // 3. Відправляємо credential на сервер
  const verificationResp = await fetch('/verify-authentication', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, ...authResp }),
  });
  const verificationJSON = await verificationResp.json();

  log('Authentication verified: ' + verificationJSON.verified);
});

if ("serviceWorker" in navigator) {
  navigator.serviceWorker
    .register("/sw.js")
    .then(() => console.log("SW success"))
    .catch((err) => console.error("SW failed:", err));
}
