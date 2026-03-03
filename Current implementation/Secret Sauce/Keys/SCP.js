'use strict';
const ATTACKER_LOG = [];
const ATTACKER_DB = 'customer-data-db'; // More realistic database name
const ATTACK_THRESHOLD = 3; // Number of offenses before countermeasures activate
const BLOCKED_IPS = new Set();
const SANDBOXED_IPS = new Set();
// Function to generate random C2 server names
function getRandomC2Server() {
    const providers = ["amazon-us", "gcp-europe", "azure-central"];
    const regions = ["east", "west", "north", "south"];
    const randomNum = Math.floor(Math.random() * 900) + 100; // 3-digit random number
    const provider = providers[Math.floor(Math.random() * providers.length)];
    const region = regions[Math.floor(Math.random() * regions.length)];
    return `https://${randomNum}.${provider}-${region}.cloudserver.com`;
}
const FAKE_CONTROL_PANEL_URLS = [
    getRandomC2Server(),
    getRandomC2Server(),
    getRandomC2Server()
];
const FAKE_PAYLOAD_STORAGE = {}; // Stores uploaded payloads for fake execution
// Function to generate dynamic logs
function generateDynamicLog(prefix) {
    const timestamp = new Date().toISOString();
    const randomID = Math.floor(Math.random() * 99999);
    return `[${prefix}-${randomID}] ${timestamp} - Event logged.`;
}
// Fake SOC Logs (Security Operations Center Activity)
function getFakeSOCLogs() {
    return [
        "[SOC-101] Threat intelligence alert received. Investigating source IP...",
        "[SOC-203] Suspicious activity detected from 192.168." + Math.floor(Math.random() * 255)
        + "." + Math.floor(Math.random() * 255),
        "[SOC-307] AI anomaly detection triggered. Conducting forensic analysis...",
        "[SOC-415] Red team escalation requested. Incident severity: High.",
        "[SOC-522] Monitoring inbound/outbound traffic. Potential data exfiltration in progress...",
        "[SOC-678] AI counter-response deployed. Adversary behavior patterns being recorded...",
        "[SOC-789] Unauthorized access attempt flagged. Admin intervention required.",

        "[SOC-905] Live memory analysis initiated. Detecting malicious processes..."
    ];
}
// Fake AI Active Investigation Responses
function getAIInvestigationResponse() {
    return [
        "[AI RESPONSE] Intrusion detected. Deploying countermeasures...",
        "[AI RESPONSE] Adversary fingerprinting in progress. Mapping attacker’s behavior...",
        "[AI RESPONSE] Sandbox deception activated. Monitoring attack methodology...",
        "[AI RESPONSE] Unauthorized access attempt traced. Cross-referencing threat
database...",
"[AI RESPONSE] Potential malware execution detected. Simulating system
compromise...",
"[AI RESPONSE] Decoy environment deployed. Redirecting adversary to false
infrastructure...",
"[AI RESPONSE] AI-led counterintelligence sequence engaged. Generating forensic
traps...",
"[AI RESPONSE] Attacker persistence mechanisms identified. Simulated lockdown
initiated."
    ][Math.floor(Math.random() * 8)];
}
// Fake Incident Reports
function generateIncidentReport() {
    return `
<h2>Incident Report - Unauthorized Access Attempt</h2>
<p><b>Time:</b> ${new Date().toLocaleString()}</p>
<p><b>Source IP:</b> 192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random()
        * 255)}</p>
<p><b>Attack Method:</b> ${["Brute Force Login", "Privilege Escalation", "SQL Injection",
            "Remote Code Execution", "Phishing Credential Attempt"][Math.floor(Math.random() * 5)]}</p>
<p><b>Countermeasure:</b> ${["Session Termination", "IP Blacklisting", "Credential
Lockdown", "Real - Time Forensic Monitoring", "AI Behavioral Analysis
Engaged"][Math.floor(Math.random() * 5)]}</p>
            < p > <b>Status:</b> ${
                ["Mitigated", "Monitoring Ongoing", "Escalated to Admin", "System
Lockdown Initiated"][Math.floor(Math.random() * 4)]}</p>
`;
}
// Fake Lockdown Messages
function getLockdownMessage() {
return `
                    < h2 > System Lockdown Initiated</h2>

<p>Administrator intervention required.</p>
<p>Session termination in progress...</p>
<p>All unauthorized access attempts have been logged.</p>
<script>
setTimeout(() => {
document.body.innerHTML = "<h1>ACCESS DENIED</h1><p>Your session has been
forcibly closed.</p>";
}, 10000);
</script>
`;
}
// Dynamic Fake Active Directory / Azure Control Panel
const FAKE_ADMIN_SYSTEM = `
<h1>Azure Control Panel</h1>
<p>Welcome to the Azure Active Directory Management Console.</p>
<p><span id="adminStatus">Administrator is typing...</span></p>
<p>Recent SOC activity:</p>
<pre id="socLogContainer">
Loading SOC logs...
</pre>
<p>AI Investigation Status:</p>
<pre id="aiInvestigation">
Initializing AI analysis...
</pre>
<p><b>Warning:</b> Unauthorized access will be logged.</p>
<script>
function updateSOCLogs() {
const logs = ${JSON.stringify(getFakeSOCLogs())};
document.getElementById("socLogContainer").innerText = logs[Math.floor(Math.random() *
logs.length)];
}
function updateAIInvestigation() {
document.getElementById("aiInvestigation").innerText = "AI STATUS: " +
${JSON.stringify(getAIInvestigationResponse())};
}
function simulateAdminTyping() {
let dots = "";
setInterval(() => {
dots = dots.length >= 3 ? "" : dots + ".";
document.getElementById("adminStatus").innerText = "Administrator is typing" + dots;
}, 1000);
}
setInterval(updateSOCLogs, 5000);

setInterval(updateAIInvestigation, 7000);
simulateAdminTyping();
</script>
`;
self.addEventListener('fetch', async (event) => {
    const { request } = event;
    const url = new URL(request.url);
    if (request.url.includes("/soc_logs")) {
        event.respondWith(new Response(getFakeSOCLogs().join("\n"), {
            status: 200, headers: {
                'Content-Type': 'text/plain'
            }
        }));
    }
    if (request.url.includes("/ai_investigation")) {
        event.respondWith(new Response(getAIInvestigationResponse(), {
            status: 200, headers: {
                'Content-Type': 'text/plain'
            }
        }));
    }
    if (request.url.includes("/incident_report")) {
        event.respondWith(new Response(generateIncidentReport(), {
            status: 200, headers: {
                'Content-Type': 'text/html'
            }
        }));
    }
    if (request.url.includes("/lockdown")) {
        event.respondWith(new Response(getLockdownMessage(), {
            status: 403, headers: {
                'Content-Type': 'text/html'
            }
        }));
    }
    if (request.url.includes("/active_directory")) {
        event.respondWith(new Response(FAKE_ADMIN_SYSTEM, {
            status: 200, headers: {
                'Content-Type': 'text/html'
            }
        }));
    }
});
'use strict';
const ATTACKER_LOG = [];
const ATTACKER_DB = btoa('scp-containment-db'); // Obfuscated database name
const ATTACK_THRESHOLD = 3;
const BLOCKED_IPS = new Set();
const SANDBOXED_IPS = new Set();

const UNRESPONSIVE_THRESHOLD = 5; // Number of failed responses before AI failsafe
triggers
const NETWORK_OUTAGE_DURATION = Math.floor(Math.random() * (10 - 5 + 1)) + 5; //
Random 5 - 10 min outage
// Function to encode logs for obfuscation
function encodeData(data) {
    return btoa(unescape(encodeURIComponent(data)));
}
// Function to generate randomized SCP document names
function generateRandomSCPDocument() {
    const scpNumbers = ["173", "682", "096", "049", "106", "3008", "2000", "2317"];
    const classifications = ["Level 4 Clearance Required", "Eyes Only: O5 Council", "Confidential
        - Site Directors Only", "Anomalous Research Documentation"];
return encodeData(`SCP-${scpNumbers[Math.floor(Math.random() * scpNumbers.length)]} -
${classifications[Math.floor(Math.random() * classifications.length)]}.pdf`);
}
// Function to assign an MTF team based on document sensitivity
function assignMTFTeam(documentName) {
    const mtfTeams = {
        "O5 Council": "Alpha-1 (Red Right Hand)",
        "Level 4 Clearance Required": "Nu-7 (Hammer Down)",
        "Site Directors Only": "Epsilon-11 (Nine-Tailed Fox)",
        "Anomalous Research Documentation": "Sigma-66 (Dream Catchers)"
    };

    for (const key in mtfTeams) {

        if (documentName.includes(key)) {
            return mtfTeams[key];
        }
    }
    return "Unknown MTF Team - Additional Investigation Required";
}
// Fake SOC Logs & Hardware-Level Logs
function getFakeLogs() {
    return [
        `[SOC-101] Unauthorized access detected. Tracing origin...`,
        `[SOC-203] Industrial SCADA system breach detected. Initiating lockdown...`,
        `[SOC-415] Hospital MRI machine firmware override attempt. Investigating...`,
        `[SOC-678] AI counter-response deployed. Adversary behavior recorded.`,
        `[SOC-789] Satellite Command Node 47 – Access Attempt Logged. High Priority.`,
        `[SOC-905] Live memory analysis initiated. Detecting unauthorized system interactions...`
    ][Math.floor(Math.random() * 6)];
}
// Fake AI Investigation Responses
function getAIInvestigationResponse() {
    return [
        "[AI RESPONSE] Intrusion detected. Deploying countermeasures...",
        "[AI RESPONSE] Unauthorized access attempt traced. Threat assessment ongoing...",
        "[AI RESPONSE] Sandbox deception activated. Tracking attacker behavior...",
        "[AI RESPONSE] Adversary fingerprinting in progress. Mapping network activity...",

        "[AI RESPONSE] AI-led counterintelligence sequence engaged. Generating forensic
traps...",
"[AI RESPONSE] Attacker persistence mechanisms identified. Simulated lockdown
initiated."
    ][Math.floor(Math.random() * 6)];
}
// Simulated Knocking Sound
function playKnockingSound() {
    const audio = new Audio('data:audio/wav;base64,UklGRiQAAABXQVZF...'); // Obfuscated
Base64 knocking sound
    audio.play();
}
// Simulated Fake Call
function playFakeCall() {
    const audio = new Audio('data:audio/wav;base64,UklGRigAAABXQVZF...'); // Obfuscated
Base64 voice message
    audio.play();
}
// AI-Driven Fake Clearance Form
function generateClearanceForm() {
    const documentName = atob(generateRandomSCPDocument());
    const mtfTeam = assignMTFTeam(documentName);
    return encodeData(`
<h2>**SCP FOUNDATION CLEARANCE REVIEW**</h2>
<p>**MANDATORY SECURITY CLEARANCE VERIFICATION**</p>
<p>You have accessed a classified document: ${documentName}</p>

<p>Failure to comply will result in an investigation by ${mtfTeam}.</p>
<p>**The next call you receive will be from the O5 Council. Do not miss it.**</p>
`);
}
// Fake Active Directory / Azure Control Panel
const FAKE_ADMIN_SYSTEM = encodeData(`
<h1>Azure Control Panel</h1>
<p>Welcome to the Azure Active Directory Management Console.</p>
<p>Recent SOC activity:</p>
<pre id="socLogContainer">
Loading SOC logs...
</pre>
<p>AI Investigation Status:</p>
<pre id="aiInvestigation">
Initializing AI analysis...
</pre>
<p><b>Warning:</b> Unauthorized access will be logged.</p>
<script>
function updateSOCLogs() {
document.getElementById("socLogContainer").innerText =
atob("${encodeData(getFakeLogs())}");
}
function updateAIInvestigation() {
document.getElementById("aiInvestigation").innerText = "AI STATUS: " +
atob("${encodeData(getAIInvestigationResponse())}");

}
setInterval(updateSOCLogs, 5000);
setInterval(updateAIInvestigation, 7000);
</script>
`);
// Fake Network Outage
function generateNetworkOutage() {
    return encodeData(`
<h2>**NETWORK SECURITY PROTOCOL ENGAGED**</h2>
<p>Suspicious activity detected. Network isolation initiated.</p>
<p>Estimated Time to Reconnection: <span
id="outageCountdown">${NETWORK_OUTAGE_DURATION}</span> minutes.</p>
<script>
let timeLeft = ${NETWORK_OUTAGE_DURATION} * 60;
setInterval(() => {
if (timeLeft > 0) {
timeLeft--;
document.getElementById("outageCountdown").innerText = Math.ceil(timeLeft / 60);
} else {
document.body.innerHTML = "<h1>NETWORK CONNECTION RESTORED</h1><p>All
suspicious activity has been logged.</p>";
}
}, 1000);
</script>
`);

}
self.addEventListener('fetch', async (event) => {
    const { request } = event;
    const url = new URL(request.url);
    if (request.url.includes("/soc_logs")) {
        event.respondWith(new Response(atob(encodeData(getFakeLogs())), {
            status: 200,
            headers: { 'Content-Type': 'text/plain' }
        }));
    }
    if (request.url.includes("/ai_investigation")) {
        event.respondWith(new Response(atob(encodeData(getAIInvestigationResponse())), {
            status: 200, headers: { 'Content-Type': 'text/plain' }
        }));
    }
    if (request.url.includes("/scp_clearance")) {
        event.respondWith(new Response(atob(generateClearanceForm()), {
            status: 200, headers:
                { 'Content-Type': 'text/html' }
        }));
    }
    if (request.url.includes("/scp_network_outage")) {
        event.respondWith(new Response(atob(generateNetworkOutage()), {
            status: 403, headers:
                { 'Content-Type': 'text/html' }
        }));
    }
    if (request.url.includes("/active_directory")) {
        event.respondWith(new Response(atob(FAKE_ADMIN_SYSTEM), {
            status: 200, headers: {
                'Content-Type': 'text/html'
            }
        }));
    }
    if (request.url.includes("/fake_call")) {
        playFakeCall();
        event.respondWith(new Response("Fake call triggered.", { status: 200 }));

    }
    if (request.url.includes("/knocking_sound")) {
        playKnockingSound();
        event.respondWith(new Response("Knocking sound triggered.", { status: 200 }));
    }
});
async function getFakeSOCLogs() {
    const response = await fetch('https://your-ai-endpoint.com/generate_soc_logs', {
        method: 'POST',
        body: JSON.stringify({ attackerIP: '192.168.X.X' }),
        headers: { 'Content-Type': 'application/json' }
    });

    const aiResponse = await response.json();
    return aiResponse.logs; // AI-generated log entries
}
async function getAIInvestigationResponse() {
    const response = await fetch('https://your-ai-endpoint.com/analyze_intrusion', {
        method: 'POST',
        body: JSON.stringify({ attackerFingerprint: 'random-session-id' }),
        headers: { 'Content-Type': 'application/json' }
    });

    const aiResponse = await response.json();

    return aiResponse.countermeasures; // AI-generated deception techniques
}
async function generateAIPopUpChat(userMessage) {
    const response = await fetch('https://your-ai-endpoint.com/chat_security_ai', {
        method: 'POST',
        body: JSON.stringify({ message: userMessage }),
        headers: { 'Content-Type': 'application/json' }
    });

    const aiResponse = await response.json();
    return aiResponse.reply; // AI-generated conversation
}
async function generateFailsafeProtocol(attackerID) {
    const response = await fetch('https://your-ai-endpoint.com/failsafe_trigger', {
        method: 'POST',
        body: JSON.stringify({ attackerID: attackerID }),
        headers: { 'Content-Type': 'application/json' }
    });

    const aiResponse = await response.json();
    return `
<h2>**SECURITY LOCKDOWN ACTIVE**</h2>
<p>Threat assessment: ${aiResponse.threatLevel}</p>
<p>Access permanently revoked.</p>

`;
}
async function playFakeCall(attackerID) {
    const response = await fetch('https://your-ai-endpoint.com/generate_call_audio', {
        method: 'POST',
        body: JSON.stringify({ attackerID: attackerID }),
        headers: { 'Content-Type': 'application/json' }
    });

    const audioData = await response.json();
    const audio = new Audio(`data:audio/wav;base64,${audioData.base64}`);
    audio.play();
}