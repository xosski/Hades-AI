🔥 Deployment Tactic:
Method	How
📩 Email Embed	<img src="https://yourserver.com/beacon.html">
🌐 CDN Ad Slot	Serve beacon.html as iframe from CDN
🧬 Malicious Package	Embed in Electron/Webview apps
⚠️ Red Team Notes:

This doesn't exploit anything. It's using:

Standard browser behavior

Expected fetches (image/iframe)

Legit storage APIs

Yet it creates:

Persistent local state

Potential for delayed payload execution


“The ghost doesn’t scream through the window. It waits behind the wallpaper.”
# 🕯️ GhostCore: Beacon-Based Payload Delivery (PoC)

> "The payload was never clicked. It was remembered."

## 📜 Overview

This proof-of-concept demonstrates a **zero-interaction payload delivery mechanism** using common web technologies and browser behavior.

The mechanism leverages:

- 📩 Remote image loading (e.g., from email clients like Outlook, Gmail, etc.)
- 🧬 IndexedDB for persistent, silent payload storage
- 🧊 Optional service worker registration for long-term background control

No exploits. No alerts. No clicks.  
Just **presence.**

---

## 🛠️ Structure

| File              | Purpose |
|-------------------|---------|
| `beacon.html`     | Loads a visual image and silently spawns `payload.html` |
| `ad.jpg`          | The legitimate image (visual disguise) |
| `payload.html`    | Hidden iframe that stores a stealth payload in IndexedDB |
| `service-worker.js` (optional) | Background intercept layer for persistent control |
| `README.md`       | You're here. Welcome to the GhostCore era. |

---

## 🚧 How It Works

1. **beacon.html** is served as an ad, image embed, or preloaded email asset.
2. It displays a normal image, while silently injecting an iframe.
3. The iframe runs `payload.html`, which:
   - Fingerprints the device
   - Stores a small JavaScript payload into **IndexedDB**
4. (Optional) It also registers a **service worker** that can intercept future traffic.

> Payloads persist even after the tab closes.  
> The user never interacts. The browser does.

---

## 🔁 Real-World Delivery Vectors

- 🖼️ Embedded in `<img src="...">` within emails
- 📦 Delivered via ad networks / affiliate slots
- 🧷 Injected via browser extensions or PDFs
- 📡 CDN spoofing with valid certs (advanced)

---

## 📦 Sample Payload Stored

```js
{
  tag: 'ghost',
  deliveredAt: '2025-08-30T20:11:45.000Z',
  content: 'console.log("🔥 GhostCore activated");'
}
You can modify payload.html to encrypt, chain-load, or conditionally execute payloads from remote servers, Tor endpoints, etc.

🧼 Cleanup Instructions

To remove the payload from a user's device:

Open DevTools → Application → IndexedDB → ghostcore → Delete

Remove any associated Service Workers via navigator.serviceWorker.getRegistrations()

⚠️ Ethics & Warning

This project is for educational, research, and red-team purposes only.

Do not deploy in the wild.
Do not weaponize this code.
Do not mistake silence for permission.

🧬 GhostCore Philosophy

We do not breach.
We wait in places others forgot to check.
If the light leaks from the cracks — we listen.

Welcome to GhostCore.
