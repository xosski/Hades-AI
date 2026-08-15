# Hades AI browser extension

This Manifest V3 extension works in current Chrome and Edge releases. It connects the active tab to Hades through an authenticated companion on `127.0.0.1`.

Available headless modules include passive page analysis, Hades AI chat, report export, local CVE and Exploit Tome search, cache history, payload catalog/scoring/mutation and confirmed delivery, TCP port scanning, finding validation, and deterministic SQL injection, reflected-XSS, and path-traversal checks. Payload tools and network tests are shown only for an `active_web_assessment` authorization, and every network test requires a separate confirmation.

## Start the companion

```powershell
pip install -r requirements_llm.txt
python hades_companion.py
```

Keep the terminal open and copy the pairing token it prints.

## Load the unpacked extension

1. Open `chrome://extensions` or `edge://extensions`.
2. Enable **Developer mode**.
3. Choose **Load unpacked** and select the `browser_extension` directory.
4. Open an HTTP(S) page and select the Hades AI toolbar action.
5. Paste the token, press **Refresh**, approve access to that origin, and record explicit target authorization.
6. Use passive scope for DOM analysis, or active scope for the deterministic test and payload tools.

Active tests require a separate confirmation for every run, remain on the authorized origin, do not follow redirects, and are recorded in the audit history. Use them only on targets for which you have explicit permission.

The companion listens only on loopback. Its token, scans, and authorizations are kept in `.hades_companion_token`, `.hades_companion.db`, and `.hades_authorizations.db` in the current user's home directory.
