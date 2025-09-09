const output = document.getElementById("output");
const register = document.getElementById("register");
const login = document.getElementById("login");
const userName = document.getElementById("username");
const inputContainer = document.getElementById("inputContainer");

const log = (msg) => (output.textContent += msg + "\n");

function validateInput() {
  const value = userName.value.trim();
  const isValid = value !== "";

  inputContainer.classList.toggle("alert", !isValid);

  return isValid ? value : null;
}

userName.addEventListener("blur", validateInput);

register.addEventListener("click", async () => {
  const text = validateInput();
  if (!text) return;

  try {
    const publicKey = {
      challenge: new Uint8Array(32),
      rp: { name: "Demo PWA" },
      user: {
        id: new Uint8Array([1, 2, 3, 4]),
        name: text,
        displayName: text,
      },
      pubKeyCredParams: [{ alg: -7, type: "public-key" }],
      authenticatorSelection: { userVerification: "preferred" },
      timeout: 60000,
      attestation: "direct",
    };

    console.log("publicKey", publicKey);

    const credential = await navigator.credentials.create({ publicKey });
    alert("Passkey success");
    log(JSON.stringify(credential, null, 2));
  } catch (err) {
    log("Error: " + err);
  }
});

login.addEventListener("click", async () => {
  const text = validateInput();
  if (!text) return;

  try {
    const publicKey = {
      challenge: new Uint8Array(32),
      timeout: 60000,
      userVerification: "preferred",
    };

    const assertion = await navigator.credentials.get({ publicKey });
    alert("Login success");
    log(JSON.stringify(assertion, null, 2));
  } catch (err) {
    log("Login error: " + err);
  }
});

// реєстрація service worker
if ("serviceWorker" in navigator) {
  navigator.serviceWorker
    .register("/sw.js")
    .then(() => console.log("SW success"))
    .catch((err) => console.error("SW failed:", err));
}

