Proof of Concept — Unsanitized Account Creation / Validation Gap
Vulnerability Title
Improper Input Validation in Account Creation Leading to Ghost Account Persistence and Potential Cross-Service Exploitation

Summary
The account creation process for the Google Workspace application in question accepts unsanitized input in critical fields (including Password) that contain high-order Unicode and special characters.
While the backend accepts and stores these values, the login interface applies stricter validation, preventing authentication with the same credentials.
This creates “ghost accounts” that are present in backend records and may propagate into other linked Google services, including Google Drive desktop sync, without being visible or manageable from the normal UI.

Steps to Reproduce (Safe)
Access the account creation form.

In the browser console, execute a harmless field injection script to fill all form fields with identifiable payloads, e.g.:

Copy
POC_INJECTION_¿_Δ_🔥
5_POC_TEST_¿_Δ_🔥
Submit the form.

Attempt to log in with the same credentials.

Observe that the account creation succeeds, but login fails, confirming mismatched validation between creation and authentication paths.

Observed Behavior
Creation path allows extended characters in all fields without rejecting the submission.

Backend records the data.

Login path enforces a stricter validation set, blocking access.

The account is now stored in backend systems but cannot be accessed via the standard UI.

Impact
Critical — Potential for cross-service injection and persistence.

Primary Risks
Ghost Accounts
Orphaned records that persist in backend data stores and may appear in admin exports or analytics.

Data Poisoning
Injected payloads could render in administrative tools, CSV/XML exports, or internal logs.

Cross-Surface Propagation
If metadata is synced to a Google Drive desktop client tied to the same account, payloads could reach local machine storage.

Local Exploitation Potential
Specially crafted payloads may cause crashes, parsing failures, or injection vulnerabilities in the local Drive client or other consuming tools.

Exploit Chain Potential
Cloud (App Creation Form) → Backend Storage → Admin/Drive Sync → Endpoint Exposure → Possible Return to Cloud

Risk Rating
Severity: Critical

Attack Complexity: Low (single form submission)

Privileges Required: None (public registration form)

Impact Scope: Cross-environment (cloud + endpoint)

Recommended Remediation
Enforce identical validation/sanitization rules at both account creation and login endpoints.

Reject high-order Unicode and control characters in authentication fields unless explicitly needed.

Apply strict server-side encoding/escaping before storing or rendering any user-supplied metadata in linked services.

Sanitize all exports and inter-service sync data to strip or escape potentially dangerous payloads.