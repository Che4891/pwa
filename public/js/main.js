const { browserSupportsWebAuthn, startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

function stopSubmit(event) {
  event.preventDefault();
}

function showMessage(elementId, message, isError = false) {
  const element = document.getElementById(elementId);
  element.innerHTML = message;
  element.style.display = 'block';
  
  if (isError) {
    element.className = 'error';
  } else {
    element.className = 'success';
  }
}

function clearMessages() {
  document.getElementById('regSuccess').style.display = 'none';
  document.getElementById('regError').style.display = 'none';
  document.getElementById('authSuccess').style.display = 'none';
  document.getElementById('authError').style.display = 'none';
}

// Hide the Begin button if the browser is incapable of using WebAuthn
if (!browserSupportsWebAuthn()) {
  document.querySelector('.controls').style.display = 'none';
  document.querySelector('.systemError').innerText =
    "It seems this browser doesn't support WebAuthn...";
} else {
  /**
   * Registration
   */
  document.querySelector('#btnRegBegin').addEventListener('click', async () => {
    clearMessages();

    const login = document.getElementById('regLogin').value;
    const password = document.getElementById('regPassword').value;

    if (!login || !password) {
      showMessage('regError', 'Please enter login and password', true);
      return;
    }

    try {
      const resp = await fetch(`/generate-registration-options?login=${encodeURIComponent(login)}`);
      
      if (!resp.ok) {
        const errorData = await resp.json();
        throw new Error(errorData.error || 'Failed to get registration options');
      }
      
      const opts = await resp.json();

      const attResp = await startRegistration({ optionsJSON: opts });

      const verificationResp = await fetch('/verify-registration', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ...attResp,
          login: login,
          password: password
        }),
      });

      if (!verificationResp.ok) {
        const errorData = await verificationResp.json();
        throw new Error(errorData.error || 'Verification failed');
      }

      const verificationJSON = await verificationResp.json();

      if (verificationJSON && verificationJSON.verified) {
        showMessage('regSuccess', 'Authenticator registered successfully!');
        document.getElementById('regForm').reset();
      } else {
        showMessage('regError', 'Registration failed. Please try again.', true);
      }
    } catch (error) {
      if (error.name === 'InvalidStateError') {
        showMessage('regError', 'Error: Authenticator was probably already registered by user', true);
      } else {
        showMessage('regError', `Error: ${error.message}`, true);
      }
      console.error('Registration error:', error);
    }
  });

  /**
   * Authentication (manual)
   */
  document.querySelector('#btnAuthBegin').addEventListener('click', async () => {
    clearMessages();

    const login = document.getElementById('authLogin').value;
    const password = document.getElementById('authPassword').value;

    if (!login || !password) {
      showMessage('authError', 'Please enter login and password', true);
      return;
    }

    try {
      const resp = await fetch(`/generate-authentication-options?login=${encodeURIComponent(login)}`);
      
      if (!resp.ok) {
        const errorData = await resp.json();
        throw new Error(errorData.error || 'Failed to get authentication options');
      }
      
      const opts = await resp.json();

      const asseResp = await startAuthentication({ optionsJSON: opts });

      const verificationResp = await fetch('/verify-authentication', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ...asseResp,
          login: login,
          password: password
        }),
      });

      if (!verificationResp.ok) {
        const errorData = await verificationResp.json();
        throw new Error(errorData.error || 'Verification failed');
      }

      const verificationJSON = await verificationResp.json();

      if (verificationJSON && verificationJSON.verified) {
        showMessage('authSuccess', 'User authenticated successfully!');
        document.getElementById('authForm').reset();
      } else {
        showMessage('authError', 'Authentication failed. Please try again.', true);
      }
    } catch (error) {
      showMessage('authError', `Error: ${error.message}`, true);
      console.error('Authentication error:', error);
    }
  });
}

if ("serviceWorker" in navigator) {
  navigator.serviceWorker
    .register("/sw.js")
    .then(() => console.log("SW success"))
    .catch((err) => console.error("SW failed:", err));
}