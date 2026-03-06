Weaponized Impact Map: Unsanitized Account Creation → Cross-Service Exploit Potential
1. Entry Point — Account Creation
Observed Behavior:
Backend accepts payloads containing special characters (¿_Δ_🔥) in all critical fields, including Password, Name, Company Name, and No. of Users.

Weakness:
Creation endpoint does not normalize or reject high-order Unicode, extended ASCII, or mixed script sequences.

Effect:
Ability to insert arbitrary, structured data into persistent account records.

2. Validation Gap — Authentication
Observed Behavior:
Login UI rejects these same credentials, meaning the created account exists in the backend but is inaccessible through standard user flows.

Weakness:
Mismatch in validation rules between CREATE and LOGIN paths.

Effect:
“Ghost accounts” can exist in the system — stored, synced, and potentially used by backend/API processes without being visible or editable from the UI.

3. Lateral Spread — Google Service Integration
Likely Propagation Paths:

Workspace/Drive app metadata APIs.

Internal admin dashboards that list all accounts and metadata.

CSV/XML/JSON exports from the admin console or Google Drive sync descriptors.

Risk:
Orphaned payload-containing accounts could appear in:

Cloud-based admin interfaces (possible HTML injection if rendered unsanitized).

Drive desktop client local cache/config DB (possible parsing crashes or data corruption).

Shared analytics or logging pipelines (possible CSV/command injection).

4. Cross-Surface Escalation
From Cloud to Endpoint:
If metadata with injected payloads syncs to a logged-in Google Drive desktop app, the payload is now local, outside browser sandboxing.

Possible impact: CSV formula injection, XML entity expansion, HTML-in-logs rendering, or malformed pathnames that disrupt local sync logic.

From Endpoint Back to Cloud:
If the local app uploads logs or status reports, malformed metadata could be reintroduced upstream, potentially affecting other users or admin accounts.

5. Weaponized Outcomes
Persistence:
Create “ghost” accounts invisible to normal admin searches but still in DB.

Data Poisoning:
Inject malformed or misleading data into user lists, Drive folder metadata, or sync manifests.

Local Exploit Delivery:
Move from cloud-controlled injection into the local file system or app state of any machine logged into the same Google identity.

Operational Disruption:
Crash or desync Drive clients with malformed synced metadata, creating a denial-of-service at the endpoint level.

6. Risk Rating
Severity: Critical

Impact Surface: Cross-environment (cloud → local → cloud)

Exploit Complexity: Low (single form submission)

Detection Likelihood: Low — orphaned accounts blend into backend records without user visibility.