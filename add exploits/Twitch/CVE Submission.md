CVE Submission
Title:
Multi-Stage Web Application Compromise via Service Worker Persistence, CSS Overlay Abuse, and Embedded Media Stream Manipulation

Description:
A vulnerability exists in web applications that combine third-party embedded media players (e.g., Facebook Video), service worker registration, and insufficient input sanitization or integrity checks on injected content.

This flaw allows an attacker to escalate a temporary injection opportunity (e.g., in-app XSS, DNS hijacking, malicious ad delivery) into a persistent, full-browser compromise by:

Injecting malicious HTML/CSS/JavaScript into the victim’s active session.

Manipulating embedded media streams (e.g., .ts HLS chunks) to trigger UI overlays and hidden interaction zones.

Abusing CSS overlays to create invisible clickjacking layers over trusted iframe content (Facebook player context).

Registering a malicious service worker to maintain control over all future requests to the domain.

Using social engineering (e.g., fake promotions or events) to seed the compromised content at scale.

Once registered, the malicious service worker persists indefinitely, even after the injection vector is closed, enabling long-term phishing, credential theft, or content manipulation.

Attack Vector:

Initial foothold: Can be obtained via in-app XSS, malicious third-party script, or network injection (e.g., DNS poisoning).

Persistence: Achieved via malicious service worker registration.

Propagation: Victims can be lured via trusted-looking media embeds promoted through social media.

Impact:

Confidentiality: Complete compromise — attacker can intercept and exfiltrate sensitive data, credentials, and session tokens.

Integrity: Full ability to modify the DOM, replace content, manipulate transactions, and present fraudulent UI.

Availability: Attacker can selectively disrupt or degrade service for targeted victims.

Persistence: Survives page reloads, browser restarts, and transient network compromises.

Severity:
CVSS v3.1 Base Score: 9.6 (Critical)

Attack Vector (AV): Network (N)

Attack Complexity (AC): Low (L)

Privileges Required (PR): None (N)

User Interaction (UI): Required (R)

Scope (S): Changed (C)

Confidentiality (C): High (H)

Integrity (I): High (H)

Availability (A): High (H)

Affected Configurations:

Any web application:

That allows third-party embeds without strict sandboxing (allow-scripts + allow-same-origin)

That supports service worker registration without strict integrity checks

That consumes external media streams without signature validation

Proof of Concept (Safe):

Inject harmless JavaScript via any controlled vector:
<script>alert('POC Injection!')</script>
Overlay invisible clickable region on embedded Facebook video:
<style>
iframe[src*="facebook.com"] { position: relative; }
.overlay { position: absolute; top:0; left:0; width:100%; height:100%; z-index:9999; background: rgba(0,0,0,0); }
</style>
<div class="overlay"></div>
Register service worker:
navigator.serviceWorker.register('/poc-sw.js');
Mitigation Recommendations:

Enforce strict CSP (Content Security Policy) to block untrusted script and style injection.

Disallow allow-same-origin and allow-scripts in third-party embeds unless absolutely necessary.

Implement subresource integrity (SRI) for all external assets, including media streams.

Restrict service worker registration to trusted origins and enforce strong integrity validation.

Sanitize all user-controlled input and perform output encoding.

Discoverer:
[Shestus/Xosski]
[GhostOpNode000@proton.me]

Vendor Coordination:

Notify primary vendor operating the vulnerable platform.

Notify affected third-party embed provider (e.g., Facebook) if iframe isolation is insufficient.

Coordinate disclosure date to allow for patch rollout.