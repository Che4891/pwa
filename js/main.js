// Отримуємо функції з глобальної змінної SimpleWebAuthnBrowser
const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

const output = document.getElementById("output");
const register = document.getElementById("register");
const login = document.getElementById("login");
const usernameInput = document.getElementById("username");
const inputContainer = document.getElementById("inputContainer");

const log = (msg) => (output.textContent += msg + "\n");

function validateInput() {
  const value = usernameInput.value.trim();
  const isValid = value !== "";
  inputContainer.classList.toggle("alert", !isValid);
  return isValid ? value : null;
}

usernameInput.addEventListener("blur", validateInput);

register.addEventListener("click", async () => {
  const username = validateInput();
  if (!username) return alert("Enter username");

  try {
    const resp = await fetch("/generate-registration-options", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
    });
    const options = await resp.json();

    const attResp = await startRegistration(options);

    const verificationResp = await fetch("/verify-registration", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, attResp }),
    });
    const verificationJSON = await verificationResp.json();

    log("Registration verified: " + verificationJSON.verified);
  } catch (err) {
    console.error("⚠️ Registration error:", err);
    log("Registration error: " + err.message);
  }
});

login.addEventListener("click", async () => {
  const username = validateInput();
  if (!username) return alert("Enter username");

  try {
    const resp = await fetch("/generate-authentication-options", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
    });
    const options = await resp.json();

    const authResp = await startAuthentication(options);

    const verificationResp = await fetch("/verify-authentication", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, authResp }),
    });
    const verificationJSON = await verificationResp.json();

    log("Authentication verified: " + verificationJSON.verified);
  } catch (err) {
    console.error("⚠️ Authentication error:", err);
    log("Authentication error: " + err.message);
  }
});
