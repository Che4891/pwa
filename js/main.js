const output = document.getElementById("output");
const log = (msg) => output.textContent += msg + "\n";

document.getElementById("register").addEventListener("click", async () => {
  try {
    const publicKey = {
      challenge: new Uint8Array(32), 
      rp: { name: "Demo PWA" },
      user: {
        id: new Uint8Array([1,2,3,4]), 
        name: "demo@example.com",
        displayName: "Demo User"
      },
      pubKeyCredParams: [{ alg: -7, type: "public-key" }], 
      authenticatorSelection: { userVerification: "preferred" },
      timeout: 60000,
      attestation: "direct"
    };

    const credential = await navigator.credentials.create({ publicKey });
    log("Passkey success");
    log(JSON.stringify(credential, null, 2));
  } catch (err) {
    log("Error" + err);
  }
});

document.getElementById("login").addEventListener("click", async () => {
  try {
    const publicKey = {
      challenge: new Uint8Array(32), 
      timeout: 60000,
      userVerification: "preferred"
    };

    const assertion = await navigator.credentials.get({ publicKey });
    log("Login success");
    log(JSON.stringify(assertion, null, 2));
  } catch (err) {
    log("Login error", err);
  }
});

if ("serviceWorker" in navigator) {
    navigator.serviceWorker
      .register("/sw.js")
      .then(() => console.log("SW success"))
      .catch((err) => console.error(" SW failed:", err));
  }