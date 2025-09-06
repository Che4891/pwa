if ("serviceWorker" in navigator) {
    navigator.serviceWorker
      .register("/sw.js")
      .then(() => console.log("SW success"))
      .catch((err) => console.error(" SW failed:", err));
  }