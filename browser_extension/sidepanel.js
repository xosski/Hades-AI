const API="http://127.0.0.1:8765/api/v1";
const state={token:"",page:null,findings:[],scanId:null,conversationId:null,portScanTimer:null};
const $=id=>document.getElementById(id);
function toast(message){$("toast").textContent=message;$("toast").classList.add("show");setTimeout(()=>$("toast").classList.remove("show"),2600)}
async function api(path,options={}){
  const response=await fetch(`${API}${path}`,{...options,headers:{...(options.body?{"Content-Type":"application/json"}:{}),Authorization:`Bearer ${state.token}`,...(options.headers||{})}});
  if(!response.ok){let message=response.status===404&&path.startsWith("/modules")?"Companion is outdated. Stop it and restart: python hades_companion.py":`Companion returned ${response.status}`;try{message=(await response.json()).error||message}catch(_){}throw new Error(message)}
  return response;
}
function collectPage(){
  const absolute=value=>{try{return new URL(value,document.baseURI).href}catch(_){return ""}};
  const forms=[...document.forms].slice(0,50).map(form=>({action:absolute(form.getAttribute("action")||location.href),method:(form.method||"get").toUpperCase(),inputs:[...form.elements].slice(0,50).map(input=>({name:input.name||"",type:input.type||input.tagName.toLowerCase()}))}));
  const resources=[...[...document.scripts].map(n=>n.src),...[...document.querySelectorAll("link[href],img[src]")].map(n=>n.href||n.src)].filter(Boolean);
  const metaHeaders={};document.querySelectorAll("meta[http-equiv]").forEach(meta=>{metaHeaders[meta.httpEquiv.toLowerCase()]=meta.content});
  return {url:location.href,title:document.title,forms,metaHeaders,mixedContent:location.protocol==="https:"?resources.filter(url=>url.startsWith("http://")).slice(0,20):[],passwordFormsOnHttp:location.protocol==="http:"&&Boolean(document.querySelector('input[type="password"]')),targetBlankWithoutNoopener:[...document.querySelectorAll('a[target="_blank"]')].filter(a=>!a.rel.toLowerCase().split(/\s+/).includes("noopener")).length};
}
async function readActivePage(requestPermission=true){
  const [tab]=await chrome.tabs.query({active:true,currentWindow:true});
  if(!tab?.id)throw new Error("Hades could not identify the active tab");
  if(!/^https?:/.test(tab.url||""))throw new Error("Open a normal HTTP or HTTPS page first. Browser and extension pages are protected.");
  const originPattern=`${new URL(tab.url).origin}/*`;
  let allowed=await chrome.permissions.contains({origins:[originPattern]});
  if(!allowed&&requestPermission){
    try{allowed=await chrome.permissions.request({origins:[originPattern]})}catch(error){throw new Error(`Could not request access to ${new URL(tab.url).origin}: ${error.message}`)}
  }
  if(!allowed)throw new Error(`Press Refresh and allow Hades to access ${new URL(tab.url).origin}`);
  let result;
  try{[result]=await chrome.scripting.executeScript({target:{tabId:tab.id},func:collectPage})}catch(error){throw new Error(`Hades could not access this tab: ${error.message}`)}
  const page=result?.result;
  if(!page?.url||!/^https?:/.test(page.url))throw new Error("Hades could not read this HTTP(S) page");
  state.page=page;$("target-title").textContent=state.page.title||new URL(state.page.url).hostname;$("target-url").textContent=state.page.url;
}
function setPageUnavailable(message){
  state.page=null;$("target-title").textContent="Open an HTTP or HTTPS page";$("target-url").textContent="";$("authorization-state").textContent=message;$("authorization-state").className="notice warning";$("authorization-form").classList.add("hidden");$("analyze").disabled=true;$("revoke").classList.add("hidden");$("findings-card").classList.add("hidden");$("chat-card").classList.add("hidden");$("modules-card").classList.add("hidden");
}
async function refreshAuthorization(){
  if(!state.page?.url)throw new Error("No active HTTP(S) page is available");
  const {authorizations}=await (await api("/authorizations")).json();const origin=new URL(state.page.url).origin;
  const authorization=authorizations.find(item=>item.target_url===origin&&item.approved);const allowed=Boolean(authorization);
  $("authorization-state").textContent=allowed?`Authorized for ${authorization.scope}`:"Authorization required before analysis";
  $("authorization-state").className=`notice ${allowed?"success":"warning"}`;$("authorization-form").classList.toggle("hidden",allowed);$("revoke").classList.toggle("hidden",!allowed);$("analyze").disabled=!allowed;$("findings-card").classList.toggle("hidden",!allowed);$("chat-card").classList.toggle("hidden",!allowed);$("modules-card").classList.toggle("hidden",!allowed);
  document.querySelectorAll(".active-only").forEach(node=>node.classList.toggle("hidden",!allowed||authorization.scope!=="active_web_assessment"));
}
async function connect(){
  state.token=$("token").value.trim();if(!state.token)return toast("Enter the pairing token");
  try{const session=await (await api("/session")).json();if((session.companion_version||0)<3)throw new Error("Companion is outdated. Stop it with Ctrl+C and restart: python hades_companion.py")}catch(error){state.token="";return toast(error.message)}
  await chrome.storage.local.set({companionToken:state.token});$("status").textContent="Connected";$("status").className="status online";$("pairing-card").classList.add("hidden");$("target-card").classList.remove("hidden");
  try{await loadModules()}catch(error){toast(`Module status unavailable: ${error.message}`)}
  try{await readActivePage(false);await refreshAuthorization()}catch(error){setPageUnavailable(error.message);toast(error.message)}
}
async function authorize(){
  const owner=$("authorized-by").value.trim();if(!owner||!$("acknowledged").checked)return toast("Name the authorizer and confirm permission");
  try{await readActivePage()}catch(error){setPageUnavailable(error.message);return toast(error.message)}
  try{await api("/authorizations",{method:"POST",body:JSON.stringify({target_url:state.page.url,authorized_by:owner,scope:$("scope").value,acknowledged:true})});await refreshAuthorization();toast("Target authorized")}catch(error){toast(error.message)}
}
async function refreshTarget(){try{await readActivePage();await refreshAuthorization()}catch(error){setPageUnavailable(error.message);toast(error.message)}}
async function revoke(){try{await readActivePage();await api("/authorizations/revoke",{method:"POST",body:JSON.stringify({target_url:state.page.url})});state.findings=[];state.scanId=null;renderFindings();await refreshAuthorization();toast("Authorization revoked")}catch(error){toast(error.message)}}
function renderFindings(){
  const container=$("findings");container.replaceChildren();
  if(!state.findings.length){container.className="findings empty";container.textContent=state.scanId?"No issues were observed by the passive checks.":"Run a passive analysis to inspect this page."}
  else{container.className="findings";state.findings.forEach(finding=>{const item=document.createElement("article");item.className=`finding ${finding.severity}`;const heading=document.createElement("h3"),badge=document.createElement("span");badge.className="badge";badge.textContent=finding.severity;heading.append(badge,document.createTextNode(finding.title));const evidence=document.createElement("p"),fix=document.createElement("p");evidence.textContent=finding.evidence;fix.textContent=`Fix: ${finding.remediation}`;item.append(heading,evidence,fix);container.append(item)})}$("report").disabled=!state.scanId;
}
async function analyze(){
  $("analyze").disabled=true;$("analyze").textContent="Analyzing…";
  try{await readActivePage();const scan=await (await api("/analyze",{method:"POST",body:JSON.stringify(state.page)})).json();state.findings=scan.findings;state.scanId=scan.id;renderFindings()}catch(error){toast(error.message)}finally{$("analyze").disabled=false;$("analyze").textContent="Run passive analysis"}
}
async function exportReport(){try{const response=await api(`/scans/${state.scanId}/report`),blob=await response.blob(),url=URL.createObjectURL(blob);await chrome.downloads.download({url,filename:`hades-report-${state.scanId.slice(0,8)}.md`,saveAs:true});setTimeout(()=>URL.revokeObjectURL(url),30000)}catch(error){toast(error.message)}}
async function sendChat(event){
  event.preventDefault();const message=$("message").value.trim();if(!message)return;const user=document.createElement("p");user.className="user";user.textContent=message;$("messages").append(user);$("message").value="";
  try{const result=await (await api("/chat",{method:"POST",body:JSON.stringify({message,page:state.page,findings:state.findings,conversation_id:state.conversationId})})).json();state.conversationId=result.conversation_id;const assistant=document.createElement("p");assistant.className="assistant";assistant.textContent=result.content;$("messages").append(assistant);$("messages").scrollTop=$("messages").scrollHeight}catch(error){toast(error.message)}
}
async function loadModules(){
  const {modules}=await (await api("/modules")).json(),container=$("module-status");container.replaceChildren();
  modules.forEach(module=>{const pill=document.createElement("div");pill.className=`module-pill ${module.available?"":"unavailable"}`;pill.textContent=`${module.available?"●":"○"} ${module.id}`;pill.title=module.reason||module.name;container.append(pill)});
}
function showModuleResult(value){$("module-output").textContent=typeof value==="string"?value:JSON.stringify(value,null,2)}
async function searchKnowledge(){
  const query=$("knowledge-query").value.trim();if(!query)return toast("Enter a CVE or product");
  try{showModuleResult(await (await api("/modules/knowledge/search",{method:"POST",body:JSON.stringify({page:state.page,query})})).json())}catch(error){toast(error.message)}
}
async function loadPayloads(){
  const vulnerabilityType=$("payload-type").value;
  try{const result=await (await api("/modules/payloads",{method:"POST",body:JSON.stringify({page:state.page,vulnerability_type:vulnerabilityType})})).json();showModuleResult(result);if(result.payloads?.[0]){$("send-payload-value").value=result.payloads[0].payload;$("mutation-payload").value=result.payloads[0].payload;$("payload-parameter").value={sql_injection:"id",xss:"q",path_traversal:"file"}[vulnerabilityType]||"input"}}catch(error){toast(error.message)}
}
async function mutatePayload(){
  const payload=$("mutation-payload").value;if(!payload)return toast("Enter a payload to mutate");
  try{showModuleResult(await (await api("/modules/mutations",{method:"POST",body:JSON.stringify({page:state.page,payload})})).json())}catch(error){toast(error.message)}
}
async function sendTestPayload(){
  const payload=$("send-payload-value").value;if(!payload)return toast("Select or enter a payload");
  if(!$("send-payload-confirm").checked)return toast("Confirm this individual payload request");
  $("send-payload").disabled=true;$("payload-output").textContent="Sending one same-origin request…";
  try{await readActivePage();const response=await api("/modules/send-payload",{method:"POST",body:JSON.stringify({page:state.page,target_url:state.page.url,method:$("payload-method").value,parameter:$("payload-parameter").value,payload,confirmed:true})});const result=await response.json();$("payload-output").textContent=JSON.stringify(result,null,2);$("send-payload-confirm").checked=false}catch(error){$("payload-output").textContent=error.message;toast(error.message)}finally{$("send-payload").disabled=false}
}
function renderPortScan(job){
  const ports=job.open_ports.length?job.open_ports.map(item=>`${item.port}/tcp (${item.service})`).join("\n"):"None found yet";
  $("port-output").textContent=`Status: ${job.status}
Progress: ${job.scanned}/${job.total} (${job.progress}%)
Host: ${job.host}${job.resolved_address?` (${job.resolved_address})`:""}

Open ports:
${ports}${job.error?`

Error: ${job.error}`:""}`;
}
async function pollPortScan(jobId){
  try{const {job}=await (await api(`/modules/port-scans/${jobId}`)).json();renderPortScan(job);if(["queued","running"].includes(job.status)){state.portScanTimer=setTimeout(()=>pollPortScan(jobId),750)}else{$("start-port-scan").disabled=false}}catch(error){$("port-output").textContent=error.message;$("start-port-scan").disabled=false;toast(error.message)}
}
async function startPortScan(){
  if(!$("port-scan-confirm").checked)return toast("Confirm this port scan");
  if(state.portScanTimer)clearTimeout(state.portScanTimer);$("start-port-scan").disabled=true;$("port-output").textContent="Starting port scan…";
  try{await readActivePage();const {job}=await (await api("/modules/port-scans",{method:"POST",body:JSON.stringify({page:state.page,start_port:Number($("port-start").value),end_port:Number($("port-end").value),timeout_ms:Number($("port-timeout").value),confirmed:true})})).json();$("port-scan-confirm").checked=false;renderPortScan(job);pollPortScan(job.id)}catch(error){$("port-output").textContent=error.message;$("start-port-scan").disabled=false;toast(error.message)}
}
async function loadCache(){try{showModuleResult(await (await api("/modules/cache")).json())}catch(error){toast(error.message)}}
async function runActiveTest(){
  if(!$("active-confirm").checked)return toast("Confirm this individual active test");
  $("run-active-test").disabled=true;showModuleResult("Running deterministic baseline and test requests…");
  try{const result=await (await api("/modules/active-test",{method:"POST",body:JSON.stringify({page:state.page,target_url:state.page.url,test_type:$("active-test-type").value,parameter:$("active-parameter").value,confirmed:true})})).json();showModuleResult(result);$("active-confirm").checked=false}catch(error){toast(error.message);showModuleResult(error.message)}finally{$("run-active-test").disabled=false}
}
$("connect").addEventListener("click",connect);$("refresh-target").addEventListener("click",refreshTarget);$("authorize").addEventListener("click",authorize);$("revoke").addEventListener("click",revoke);$("analyze").addEventListener("click",analyze);$("report").addEventListener("click",exportReport);$("chat-form").addEventListener("submit",sendChat);$("knowledge-search").addEventListener("click",searchKnowledge);$("payload-search").addEventListener("click",loadPayloads);$("mutate-payload").addEventListener("click",mutatePayload);$("send-payload").addEventListener("click",sendTestPayload);$("start-port-scan").addEventListener("click",startPortScan);$("cache-summary").addEventListener("click",loadCache);$("run-active-test").addEventListener("click",runActiveTest);
chrome.storage.local.get("companionToken").then(({companionToken})=>{if(companionToken){$("token").value=companionToken;connect()}});
