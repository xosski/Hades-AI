'use strict';

const CONFIG = {
    ATTACK_THRESHOLD: 3,
    UNRESPONSIVE_THRESHOLD: 5,
    NETWORK_OUTAGE_DURATION: Math.floor(Math.random() * 6) + 5,
    SCP_NUMBERS: ["173", "682", "096", "049", "106", "3008", "2000", "2317"],
    MTF_TEAMS: {
        "O5 Council": "Alpha-1 (Red Right Hand)",
        "Level 4 Clearance Required": "Nu-7 (Hammer Down)",
        "Site Directors Only": "Epsilon-11 (Nine-Tailed Fox)",
        "Anomalous Research Documentation": "Sigma-66 (Dream Catchers)"
    }
};
const storage = {
    attackerLog: [],
    blockedIPs: new Set(),
    sandboxedIPs: new Set(),
    payloadStorage: {},
    scpAttackerLog: [],
    scpBlockedIPs: new Set(),
    scpSandboxedIPs: new Set()
};
function getRandomC2Server() {
    const providers = ["amazon-us", "gcp-europe", "azure-central"];
    const regions = ["east", "west", "north", "south"];
    const randomNum = Math.floor(Math.random() * 900) + 100;
    const provider = providers[Math.floor(Math.random() * providers.length)];
    const region = regions[Math.floor(Math.random() * regions.length)];
    return `https://${randomNum}.${provider}-${region}.cloudserver.com`;
}

function generateRandomSCPDocument() {
    const classifications = [
        "Level 4 Clearance Required",
        "Eyes Only: O5 Council",
        "Confidential- Site Directors Only",
        "Anomalous Research Documentation"
    ];
    return encodeData(`SCP-${CONFIG.SCP_NUMBERS[Math.floor(Math.random() * CONFIG.SCP_NUMBERS.length)]} ${classifications[Math.floor(Math.random() * classifications.length)]}.pdf`);
}
class AudioSystem {
    static playKnockingSound() {
        const audio = new Audio('data:audio/wav;base64,UklGRiQAAABXQVZF...');
        audio.play();
    }

    static async playFakeCall(attackerID) {
        const response = await fetch('https://your-ai-endpoint.com/generate_call_audio', {
            method: 'POST',
            body: JSON.stringify({ attackerID }),
            headers: { 'Content-Type': 'application/json' }
        });
        const audioData = await response.json();
        const audio = new Audio(`data:audio/wav;base64,${audioData.base64}`);
        audio.play();
    }
}
class AISystem {
    static async getInvestigationResponse() {
        const response = await fetch('https://your-ai-endpoint.com/analyze_intrusion', {
            method: 'POST',
            body: JSON.stringify({ attackerFingerprint: 'random-session-id' }),
            headers: { 'Content-Type': 'application/json' }
        });
        return (await response.json()).countermeasures;
    }

    static async generatePopUpChat(userMessage) {
        const response = await fetch('https://your-ai-endpoint.com/chat_security_ai', {
            method: 'POST',
            body: JSON.stringify({ message: userMessage }),
            headers: { 'Content-Type': 'application/json' }
        });
        return (await response.json()).reply;
    }

    static async generateFailsafeProtocol(attackerID) {
        const response = await fetch('https://your-ai-endpoint.com/failsafe_trigger', {
            method: 'POST',
            body: JSON.stringify({ attackerID }),
            headers: { 'Content-Type': 'application/json' }
        });
        const aiResponse = await response.json();
        return `
        <h2>**SECURITY LOCKDOWN ACTIVE**</h2>
        <p>Threat assessment: ${aiResponse.threatLevel}</p>
        <p>Access permanently revoked.</p>
      `;
    }
}
const encodeData = (data => btoa(unescape(encodeURIComponent(data))));
const decodeData = (data => decodeURIComponent(escape(atob(data))));
function generateNetworkOutage() {
    return encodeData(`
      <h2>**NETWORK SECURITY PROTOCOL ENGAGED**</h2>
      <p>Suspicious activity detected. Network isolation initiated.</p>
      <p>Estimated Time to Reconnection: <span id="outageCountdown">${CONFIG.NETWORK_OUTAGE_DURATION} minutes</span></p>
    `);
}
const encodedData = encodeData("Sensitive information");
const encodedDocument = encodeData(generateRandomSCPDocument());
const FAKE_ADMIN_SYSTEM = `
  <div class="admin-panel">
    <h1>Azure Control Panel</h1>
    <p>Welcome to the Azure Active Directory Management Console.</p>
    <p><span id="adminStatus">Administrator is typing...</span></p>
    <section class="monitoring">
      <p>Recent SOC activity:</p>
      <pre id="socLogContainer">Loading SOC logs...</pre>
      <p>AI Investigation Status:</p>
      <pre id="aiInvestigation">Initializing AI analysis...</pre>
    </section>
    <p class="warning"><b>Warning:</b> Unauthorized access will be logged.</p>
  </div>
`;

function updateSOCLogs() {
    const logs = getFakeSOCLogs();
    document.getElementById("socLogContainer").innerText = logs;
}

function updateAIInvestigation() {
    document.getElementById("aiInvestigation").innerText = "AI STATUS: " + getAIInvestigationResponse();
}

function simulateAdminTyping() {
    let dots = "";
    setInterval(() => {
        dots = dots.length >= 3 ? "" : dots + ".";
        document.getElementById("adminStatus").innerText = "Administrator is typing" + dots;
    }, 500);
}
function getFakeSOCLogs() {
    const logs = [
        `[SOC-101] Unauthorized access detected. Tracing origin...`,
        `[SOC-203] Industrial SCADA system breach detected. Initiating lockdown...`,
        `[SOC-415] Hospital MRI machine firmware override attempt. Investigating...`,
        `[SOC-678] AI counter-response deployed. Adversary behavior recorded.`,
        `[SOC-789] Satellite Command Node 47 – Access Attempt Logged. High Priority.`,
        `[SOC-905] Live memory analysis initiated. Detecting unauthorized system interactions...`
    ];
    return logs[Math.floor(Math.random() * logs.length)];
}

function generateIncidentReport() {
    return `
      <h2>Incident Report - Unauthorized Access Attempt</h2>
      <p><b>Time:</b> ${new Date().toLocaleString()}</p>
      <p><b>Source IP:</b> 192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}</p>
      <p><b>Attack Method:</b> ${["Brute Force Login", "Privilege Escalation", "SQL Injection", "Remote Code Execution"][Math.floor(Math.random() * 4)]}</p>
      <p><b>Status:</b> Monitoring</p>
    `;
}
function assignMTFTeam(documentName) {
    for (const [key, team] of Object.entries(CONFIG.MTF_TEAMS)) {
        if (documentName.includes(key)) {
            return team;
        }
    }
    return "Unknown MTF Team - Additional Investigation Required";
}

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
self.addEventListener('fetch', async (event) => {
    const { request } = event;
    const handlers = {
        '/soc_logs': () => new Response(getFakeSOCLogs(), {
            status: 200,
            headers: { 'Content-Type': 'text/plain' }
        }),
        '/ai_investigation': () => new Response(getAIInvestigationResponse(), {
            status: 200,
            headers: { 'Content-Type': 'text/plain' }
        }),
        '/incident_report': () => new Response(generateIncidentReport(), {
            status: 200,
            headers: { 'Content-Type': 'text/html' }
        }),
        '/clearance_form': () => new Response(generateClearanceForm(), {
            status: 200,
            headers: { 'Content-Type': 'text/html' }
        }),
        '/active_directory': () => new Response(FAKE_ADMIN_SYSTEM, {
            status: 200,
            headers: { 'Content-Type': 'text/html' }
        })
    };

    for (const [path, handler] of Object.entries(handlers)) {
        if (request.url.includes(path)) {
            event.respondWith(handler());
            break;
        }
    }
});


