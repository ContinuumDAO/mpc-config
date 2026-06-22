(function(){const e=document.createElement("link").relList;if(e&&e.supports&&e.supports("modulepreload"))return;for(const r of document.querySelectorAll('link[rel="modulepreload"]'))n(r);new MutationObserver(r=>{for(const i of r)if(i.type==="childList")for(const c of i.addedNodes)c.tagName==="LINK"&&c.rel==="modulepreload"&&n(c)}).observe(document,{childList:!0,subtree:!0});function s(r){const i={};return r.integrity&&(i.integrity=r.integrity),r.referrerPolicy&&(i.referrerPolicy=r.referrerPolicy),r.crossOrigin==="use-credentials"?i.credentials="include":r.crossOrigin==="anonymous"?i.credentials="omit":i.credentials="same-origin",i}function n(r){if(r.ep)return;r.ep=!0;const i=s(r);fetch(r.href,i)}})();function ye(){const t=window==null?void 0:window.ddClient;if(!t)throw new Error("Are you using this extension in a browser? Extensions can only be used in Docker DesktopIf you are using Docker Desktop, please make sure you are using the latest version.");return t}const de="m-0 rounded-[4px] border px-3 py-2 font-sans text-[0.8125rem]",ke=`${de} border-[var(--muted)] text-[var(--muted)]`,Ee=`${de} border-[color-mix(in_srgb,var(--accent3)_55%,var(--muted))] text-[var(--accent3)]`,fe="m-0 rounded-[4px] border bg-[color-mix(in_srgb,var(--surface)_88%,var(--bg))] p-3 font-sans text-[0.8125rem] leading-relaxed",Le=`${fe} border-[color-mix(in_srgb,var(--accent2)_55%,var(--muted))] text-[var(--text)]`,be=`${fe} border-[color-mix(in_srgb,var(--accent3)_55%,var(--muted))] text-[var(--accent3)]`,ve="flex flex-col gap-2",xe="https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/desktop-local-orchestrate.sh",N="continuum-wsl.cmd",ne="continuum-register-watcher.cmd",We="continuum-linux.sh",V="continuum-macos.sh",se="continuum-register-launchagent.sh",K="/tmp/continuum-desktop-orchestrate.sh",f={WINDOWS:"windows",LINUX:"linux",MACOS:"macos"},H={[f.WINDOWS]:"Windows",[f.LINUX]:"Linux",[f.MACOS]:"macOS"},U="~/mpc-config",z="Ready (macOS) — the macOS install script is now available on Docker Desktop. Requires passwordless sudo for /var/lib/mpc-auth-docker. Enter keys and public IPv4, then Install node.",Oe=new Set(["docker-desktop","docker-desktop-data"]);function $e(){var s,n;const t=ye(),e=(n=(s=t==null?void 0:t.extension)==null?void 0:s.host)==null?void 0:n.cli;if(!(e!=null&&e.exec))throw new Error("Docker Desktop host CLI API unavailable — update Docker Desktop and reload the extension.");return{ddClient:t,cli:e}}const Y="@continuum/progress	",B="@continuum/progress",Pe=new Set(["init","sync","topic","overall","finish"]);function me(t){const e=t.trimEnd();return e?e.startsWith(Y)?e.slice(Y.length):e.startsWith(B)?e.slice(B.length).replace(/^\s+/,"")||null:e.startsWith("{")?e:null:null}function he(t){if(!t)return!1;try{const e=JSON.parse(t);return!!(e&&typeof e=="object"&&Pe.has(e.type))}catch{return!1}}function Ie(t){const e=me(t);return e!==null&&he(e)}function re(t,e){const s=me(t);return!s||!he(s)?!1:(e.handleEvent(JSON.parse(s)),!0)}function Ae(t){let e=!1;function s(n){if(e){if(e=!1,re(`${Y}${n}`,t))return!0;n=`${B}	${n}`}if(re(n,t))return!0;const r=n.trim();return r===B||r==="@continuum/progress"?(e=!0,!0):!!Ie(n)}return{handleLine:s,flushPending(){e=!1}}}function oe(t){return t.startsWith("pull:")?`2:${t}`:t==="start-stack"?"3:start-stack":`1:${t}`}function Ne({progressPanel:t,progressTopics:e,progressOverall:s}){const n=new Map;let r=0,i=!1,c=null;function u(){if(c)return c;if(!s)return null;const o=document.createElement("div");o.className="install-progress-overall-row";const h=document.createElement("span");h.className="install-progress-label font-medium",h.textContent="Overall";const P=document.createElement("div");P.className="install-progress-track";const d=document.createElement("div");d.className="install-progress-fill",P.appendChild(d);const W=document.createElement("span");W.className="install-progress-pct flex items-center justify-end gap-1";const v=document.createElement("span"),m=document.createElement("span");return m.className="install-progress-spinner",m.setAttribute("aria-hidden","true"),m.hidden=!0,W.append(v,m),o.append(h,P,W),s.appendChild(o),c={fill:d,pctSpan:v,spinner:m},c}function E(o,{replace:h=!1}={}){var P,d,W,v;h&&n.clear();for(const m of o??[])m!=null&&m.id&&n.set(m.id,{label:m.label??((P=n.get(m.id))==null?void 0:P.label)??m.id,pct:typeof m.pct=="number"?m.pct:((d=n.get(m.id))==null?void 0:d.pct)??0,state:m.state??((W=n.get(m.id))==null?void 0:W.state)??"pending",weight:m.weight??((v=n.get(m.id))==null?void 0:v.weight)??1})}function S(){for(const o of n.values())o.pct=100,o.state!=="failed"&&(o.state="done")}function p(){return[...n.entries()].sort(([o],[h])=>oe(o).localeCompare(oe(h)))}function y(o,h,P,d){const W=document.createElement("div");W.className="install-progress-row",W.dataset.topicId=o;const v=document.createElement("span");v.className="install-progress-label",(d==="done"||d==="skipped")&&v.classList.add("is-done"),d==="failed"&&v.classList.add("is-failed"),v.textContent=h,v.title=h;const m=document.createElement("div");m.className="install-progress-track";const L=document.createElement("div");L.className="install-progress-fill",d==="active"&&L.classList.add("is-active"),d==="failed"&&L.classList.add("is-failed"),L.style.width=`${Math.max(0,Math.min(100,P))}%`,m.appendChild(L);const O=document.createElement("span");return O.className="install-progress-pct",O.textContent=`${Math.round(P)}%`,W.append(v,m,O),W}function g(){const o=u();o&&(o.fill.style.width=`${Math.max(0,Math.min(100,r))}%`,o.fill.classList.toggle("is-active",i),o.pctSpan.textContent=`${Math.round(r)}%`,o.spinner.hidden=!i,i?o.spinner.setAttribute("aria-label","Working"):o.spinner.removeAttribute("aria-label"))}function D(){if(e){e.replaceChildren();for(const[o,h]of p())e.appendChild(y(o,h.label,h.pct??0,h.state??"pending"));g()}}function x(){t&&(t.hidden=!1,t.classList.remove("hidden"))}function a(o){if(!(!o||typeof o!="object"))switch(o.type){case"init":E(o.topics,{replace:!0}),x(),D();break;case"sync":E(o.topics),x(),D();break;case"topic":{if(!o.id)break;const h=n.get(o.id)??{label:o.id,pct:0,state:"pending"};h.pct=typeof o.pct=="number"?o.pct:h.pct,h.state=o.state??h.state,n.set(o.id,h),x(),D();break}case"overall":r=typeof o.pct=="number"?o.pct:r,i=o.spinner===!0,x(),g();break;case"finish":i=!1,o.ok===!0&&(S(),r=100),D();break}}function w(){n.clear(),r=0,i=!1,c=null,e&&e.replaceChildren(),s&&s.replaceChildren(),t&&(t.hidden=!0,t.classList.add("hidden"))}return{handleEvent:a,reset:w}}function l(t,e){t.textContent+=e,t.scrollTop=t.scrollHeight}function pe(t){return String(t??"").replace(/\u0000/g,"").trim()}function _(t){return pe(`${(t==null?void 0:t.stdout)??""}${(t==null?void 0:t.stderr)??""}`)}function De({nodeMgtKey:t,publicMgtKey:e,nodeIp:s}){const n=t.trim(),r=e.trim(),i=s.trim();if(!n&&!r)throw new Error("Provide NodeMgtKey and/or PublicMgtKey");if(!i)throw new Error("Public IPv4 is required");const c=[];return n&&c.push("--node-mgt-key",n),r&&c.push("--public-mgt-key",r),c.push("--ip",i),c}function _e(t){const e=t.trim();return!e||e.length>64?!1:/^[\w.-]+$/.test(e)}function Re(t){const e=[];let s=null;const n=pe(t);for(const r of n.split(/\r?\n/)){const i=r.match(/^\s*(\*?)\s*([^\s]+)\s+/);if(!i)continue;const c=i[1],u=i[2];u==="NAME"||Oe.has(u)||(e.push(u),c==="*"&&(s=u))}return{distros:e,defaultDistro:s??e[0]??null}}function A(t,e){t.hidden=!1,t.className=be,t.textContent=e}function $(t,e,s=!1){t&&(t.hidden=!1,t.className=s?Ee:ke,t.textContent=e)}function Te(t){t.hidden=!1,t.className=ve}function J(t){var s,n,r;const e=((s=t==null?void 0:t.host)==null?void 0:s.platform)??((r=(n=t==null?void 0:t.desktopUI)==null?void 0:n.host)==null?void 0:r.platform);return e==="win32"?f.WINDOWS:e==="linux"?f.LINUX:e==="darwin"?f.MACOS:null}async function Ce(t,e){var r;const s=J(e);if(s===f.WINDOWS)return!0;if(s===f.LINUX||s===f.MACOS)return!1;const n=await R(t,"cmd",["/c","ver"]);return n.ok&&((r=n.result)==null?void 0:r.code)===0}function q(t,e){var r;const s=J(t);if(s)return s;const n=(r=e==null?void 0:e.value)==null?void 0:r.trim();return n===f.WINDOWS||n===f.LINUX||n===f.MACOS?n:null}function X({hostOs:t,hostOsRow:e,hostOsSelect:s,wslDistroRow:n,installBtn:r,bootStatus:i}){if(e&&s){const c=t===null;e.hidden=!c,c?e.classList.remove("hidden"):e.classList.add("hidden"),t&&s.value!==t&&(s.value=t)}if(n){const c=t===f.WINDOWS;n.hidden=!c,c?n.classList.remove("hidden"):n.classList.add("hidden")}r&&(r.disabled=!1),i&&t===f.MACOS&&$(i,z,!1)}async function R(t,e,s){try{return{ok:!0,result:await t.exec(e,s)}}catch(n){return n&&typeof n=="object"&&("code"in n||"stdout"in n||"stderr"in n)?{ok:!0,result:n}:{ok:!1,error:n}}}function ge(t){const e=t==null?void 0:t.code;if(e==null)return null;const s=Number(e);return Number.isFinite(s)?s:null}function C(t,{expectSubstring:e}={}){if(!t)return!1;const s=_(t),n=ge(t);return e&&s.includes(e)?n===null||n===0:n===null?!/sorry|password is required|a password is required/i.test(s):n===0}function M(t,e){return["-d",t,...e]}function ie(t,e){return`Passwordless sudo required for Docker Desktop install on Windows.

WSL user: ${e}
WSL distro: ${t}

The Docker extension runs the installer as your default WSL user and cannot type your sudo password.
Host automation (/var/lib/mpc-auth-docker), apt packages, and maintenance restart/update all need sudo -n.

Configure passwordless sudo from Windows PowerShell:

  wsl -d ${t} -u root

Then in the root WSL shell:

  visudo

Add this line (replace ${e} if your username differs):

  ${e} ALL=(ALL) NOPASSWD: ALL

Verify as your normal WSL user (exit the root shell first):

  wsl -d ${t}
  sudo -n true && echo OK

Then click Install again in the Docker extension.`}async function Me(t,e,s){var E;l(s,`Checking passwordless sudo for default WSL user in "${e}"…
`);const n=await R(t,N,M(e,["whoami"])),r=n.ok&&n.result?_(n.result).trim():"<your-wsl-user>",i=await R(t,N,M(e,["bash","-lc","command -v sudo >/dev/null && sudo -n true"]));if(!i.ok)return l(s,`[host exec error: ${i.error instanceof Error?i.error.message:String(i.error)}]
`),l(s,`
${ie(e,r)}
`),!1;const c=_(i.result),u=(E=i.result)==null?void 0:E.code;return l(s,`[exit ${u??"unknown"}] user=${r}${c?` ${c}`:""}
`),C(i.result)?(l(s,`Passwordless sudo OK for WSL user "${r}".

`),!0):(l(s,`
${ie(e,r)}
`),!1)}function G(t){return`Passwordless sudo required for Docker Desktop install on macOS.

macOS user: ${t}

The Docker extension runs the installer as your user and cannot type your sudo password.
Host automation (/var/lib/mpc-auth-docker) and VPN (wg-quick) need sudo -n.

Configure passwordless sudo in Terminal:

  sudo visudo

Add a NOPASSWD line for the user shown above. On macOS the default %admin rule requires a password — put your line in /etc/sudoers.d/ (loaded after the main file) or after %admin in visudo:

  ${t} ALL=(ALL) NOPASSWD: ALL

Verify (clears any cached sudo ticket first — Terminal "OK" with a recent sudo password is not enough):

  sudo -k
  sudo -n true && echo OK

The visudo line must match the macOS user Docker Desktop runs as (shown in the install log).

Then click Install again in the Docker extension.`}async function He(t,e){var u;l(e,`Checking passwordless sudo on macOS…
`);const s=await R(t,V,["/usr/bin/whoami"]),n=s.ok&&s.result?_(s.result).trim():"<your-macos-user>";if(!s.ok)return l(e,`[host exec error (whoami): ${s.error instanceof Error?s.error.message:String(s.error)}]
`),l(e,`
${G(n)}
`),!1;l(e,`Docker Desktop host exec user: ${n}
`);const r=await R(t,V,["check-passwordless-sudo"]);if(!r.ok)return l(e,`[host exec error (sudo): ${r.error instanceof Error?r.error.message:String(r.error)}]
`),l(e,`
${G(n)}
`),!1;const i=_(r.result),c=ge(r.result);return l(e,`[exit ${c??((u=r.result)==null?void 0:u.code)??"unknown"}] user=${n}${i?` ${i}`:""}
`),C(r.result)?(l(e,`Passwordless sudo OK for macOS user "${n}".

`),!0):(l(e,`sudo -n failed in Docker Desktop host exec (Terminal may still work via a cached sudo ticket, sudoers rule order, or a different user).
`),l(e,`
${G(n)}
`),!1)}async function ae(t,e){if(!await Ce(t,e))return{isWindows:!1,wslAvailable:!1,distros:[],defaultDistro:null,listOutput:""};const n=await R(t,N,["-l","-v"]);if(!n.ok||!n.result)return{isWindows:!0,wslAvailable:!1,distros:[],defaultDistro:null,listOutput:""};const r=_(n.result);if(!r||/no installed distributions/i.test(r))return{isWindows:!0,wslAvailable:!1,distros:[],defaultDistro:null,listOutput:""};const{distros:i,defaultDistro:c}=Re(r);return{isWindows:!0,wslAvailable:i.length>0,distros:i,defaultDistro:c,listOutput:r}}function j(t,e,s,n,r,i={}){return new Promise((c,u)=>{let E=!1,S="";const p=r?Ae(r):null,y=(a=!1)=>{let w;for(;(w=S.indexOf(`
`))!==-1;){const o=S.slice(0,w);S=S.slice(w+1),!(p!=null&&p.handleLine(o))&&o.length>0&&l(n,`${o}
`)}if(a&&S.length>0){if(p!=null&&p.handleLine(S)){S="";return}l(n,`${S}
`),S=""}},g=a=>{if(!a)return;const w=a.endsWith(`
`)?a:`${a}
`;for(const o of w.split(/\r?\n/))o&&(p!=null&&p.handleLine(o)||l(n,`${o}
`))},D=a=>{E||(E=!0,y(!0),p==null||p.flushPending(),l(n,`
[process exited ${a}]
`),c({code:a}))},x={onOutput({stdout:a,stderr:w}){a&&(p?(S+=a,y(!1)):l(n,a.endsWith(`
`)?a:`${a}
`)),w&&(p?g(w):l(n,w.endsWith(`
`)?w:`${w}
`))},onError(a){if(E)return;E=!0;const w=(a==null?void 0:a.message)??String(a);l(n,`
[stream error] ${w}
`),u(a instanceof Error?a:new Error(w))},onClose(a){D(typeof a=="number"?a:1)}};try{t.exec(e,s,{stream:x,splitOutputLines:!0,...i})}catch(a){u(a instanceof Error?a:new Error(String(a)))}})}async function Ue(t,e,s){var c;l(s,`Checking WSL distro "${e}" via ${N}…
`);const n=await R(t,N,M(e,["-e","echo","ok"]));if(!n.ok)return l(s,`[host exec error: ${n.error instanceof Error?n.error.message:String(n.error)}]
`),!1;const r=_(n.result),i=(c=n.result)==null?void 0:c.code;return l(s,`[exit ${i??"unknown"}]${r?` ${r}`:""}
`),C(n.result,{expectSubstring:"ok"})?(l(s,`WSL distro "${e}" is reachable.

`),!0):!1}async function ce(t,{useWsl:e,wslDistro:s,profile:n,scriptArgs:r},i,c){const u=["--profile",n,...r];if(e){l(i,`Downloading orchestrator script…
`);const p=M(s,["curl","-fsSL",xe,"-o",K]),y=await j(t,N,p,i,null);if(y.code!==0)return y;l(i,`
Running orchestrator via ${N}…

`);const g=M(s,["env","CONTINUUM_INSTALL_PROGRESS=json","bash",K,...u]);return j(t,N,g,i,c)}const E=n==="macos"?V:We;l(i,`Running bundled orchestrator via ${E}…

`);const S=["env","CONTINUUM_INSTALL_PROGRESS=json","bash",K,...u];return j(t,E,S,i,c)}function le(t,e){if(!t||!e.defaultDistro)return;const s=t.value.trim();(!s||s==="Ubuntu")&&(t.value=e.defaultDistro)}function ue(){const t=document.getElementById("install-form"),e=document.getElementById("install-btn"),s=document.getElementById("log-panel"),n=document.getElementById("log-output"),r=document.getElementById("progress-panel"),i=document.getElementById("progress-topics"),c=document.getElementById("progress-overall"),u=document.getElementById("result-panel"),E=document.getElementById("wsl-distro-row"),S=document.getElementById("wsl-distro"),p=document.getElementById("host-os-row"),y=document.getElementById("host-os"),g=document.getElementById("boot-status");if(!t||!e||!s||!n||!u){$(g,"Extension UI failed to initialize (missing DOM). Rebuild the extension image.",!0);return}let D;try{D=$e()}catch(d){$(g,d instanceof Error?d.message:String(d),!0),e.disabled=!0;return}const{ddClient:x,cli:a}=D,w=Ne({progressPanel:r,progressTopics:i,progressOverall:c});let o={distros:[],defaultDistro:null},h=J(x);y&&h&&(y.value=h),(async()=>{o=await ae(a,x);const d=q(x,y);if(X({hostOs:d,hostOsRow:p,hostOsSelect:y,wslDistroRow:E,installBtn:e,bootStatus:g}),d===f.WINDOWS&&S&&le(S,o),d===f.MACOS){$(g,z);return}if(d===null){$(g,"Select your host OS, then enter keys and public IPv4.");return}if(d===f.WINDOWS&&o.distros.length>0){$(g,`Ready (${H[d]}) — detected WSL distros: ${o.distros.join(", ")}. Enter keys and public IPv4, then Install node.`);return}if(d===f.WINDOWS){$(g,"Ready (Windows) — enter the exact WSL distro name from wsl -l -v, keys, and public IPv4."),A(u,`Could not list WSL distros via ${N}. Reinstall the extension so Docker copies the host binary, then quit and restart Docker Desktop.`);return}if(d===f.LINUX){$(g,"Ready (Linux) — install uses sudo for packages, UFW, and systemd. Passwordless sudo recommended. Enter keys and public IPv4.");return}$(g,"Ready — enter keys and public IPv4, then Install node.")})(),y==null||y.addEventListener("change",()=>{const d=q(x,y);if(X({hostOs:d,hostOsRow:p,hostOsSelect:y,wslDistroRow:E,installBtn:e,bootStatus:g}),d===f.WINDOWS&&le(S,o),u.hidden=!0,u.textContent="",d===f.MACOS){$(g,z);return}if(d===null){$(g,"Select your host OS, then enter keys and public IPv4.");return}if(d===f.LINUX){$(g,"Ready (Linux) — install uses sudo for packages, UFW, and systemd. Passwordless sudo recommended.");return}$(g,`Ready (${H[d]}) — enter keys and public IPv4, then Install node.`)});async function P(){var Q,Z,ee;u.hidden=!0,u.textContent="",Te(s),n.textContent="",w.reset(),e.disabled=!0;const d=((Q=document.getElementById("node-mgt-key"))==null?void 0:Q.value)??"",W=((Z=document.getElementById("public-mgt-key"))==null?void 0:Z.value)??"",v=((ee=document.getElementById("node-ip"))==null?void 0:ee.value)??"";let m;try{m=De({nodeMgtKey:d,publicMgtKey:W,nodeIp:v})}catch(k){A(u,k instanceof Error?k.message:String(k)),e.disabled=!1;return}o=await ae(a,x);const L=q(x,y);if(X({hostOs:L,hostOsRow:p,hostOsSelect:y,wslDistroRow:E,installBtn:e,bootStatus:g}),!L){A(u,"Select your host OS (Windows, Linux, or macOS)."),e.disabled=!1;return}if(L===f.MACOS&&!await He(a,n)){A(u,"Passwordless sudo is required on macOS. See the install log for visudo steps, then retry Install."),e.disabled=!1;return}const O=L===f.WINDOWS,F=L===f.LINUX?"linux":L===f.MACOS?"macos":"windows",I=((S==null?void 0:S.value)??o.defaultDistro??"").trim();if(O&&!I){A(u,"Enter your WSL distro name (run wsl -l -v in PowerShell — e.g. Ubuntu-26.04)."),e.disabled=!1;return}if(O&&!_e(I)){A(u,"Enter a valid WSL distro name (e.g. Ubuntu-26.04). Run wsl -l -v in PowerShell."),e.disabled=!1;return}if(O){if(!await Ue(a,I,n)){A(u,`Could not run commands in WSL distro "${I}" via ${N}. Confirm the distro name matches wsl -l -v exactly. Reinstall the extension if the host binary is missing.`),e.disabled=!1;return}if(!await Me(a,I,n)){A(u,`Passwordless sudo is required for WSL user in "${I}". See the install log for visudo steps, then retry Install.`),e.disabled=!1;return}}l(n,O?`Using WSL distro "${I}" (${H[L]}) — clone/install at ${U}, then docker compose up…

`:`Using ${H[L]} host — clone/install at ${U}, then docker compose up…

`);try{let k;if(O?k=await ce(a,{useWsl:!0,wslDistro:I,profile:F,scriptArgs:m},n,w):k=await ce(a,{useWsl:!1,wslDistro:null,profile:F,scriptArgs:m},n,w),u.hidden=!1,(k==null?void 0:k.code)===0){if(O&&I){l(n,`
Registering Windows logon task for WSL pending-update watcher (${ne})…
`);try{const b=await R(a,ne,[I]),T=_(b.result);T&&l(n,`${T}
`),(!b.ok||!C(b.result))&&l(n,`warning: logon task registration failed — run manually in WSL: ~/mpc-config/wsl-desktop/start-watcher.sh
`)}catch(b){l(n,`warning: could not register logon task (${b instanceof Error?b.message:String(b)}). Start watcher manually: ~/mpc-config/wsl-desktop/start-watcher.sh
`)}}else if(L===f.MACOS){l(n,`
Registering macOS launchd LaunchAgent for pending-update watcher (${se})…
`);try{const b=await R(a,se,[]),T=_(b.result);T&&l(n,`${T}
`),(!b.ok||!C(b.result))&&l(n,`warning: LaunchAgent registration failed — run manually: ~/mpc-config/macos-desktop/install-launchagent.sh --repo-dir ~/mpc-config
`)}catch(b){l(n,`warning: could not register LaunchAgent (${b instanceof Error?b.message:String(b)}). Start watcher manually: ~/mpc-config/macos-desktop/start-watcher.sh
`)}}u.className=Le;const te=O?`<code class="font-mono text-[0.6875rem] text-[var(--text)]">${U}</code> in WSL (${I})`:`<code class="font-mono text-[0.6875rem] text-[var(--text)]">${U}</code> on this machine`,Se=O?' Host restart automation: WSL pending-update watcher (status: <code class="font-mono text-[0.6875rem] text-[var(--text)]">~/mpc-config/wsl-desktop/status-watcher.sh</code> in WSL).':L===f.MACOS?' Host restart automation: macOS pending-update watcher (status: <code class="font-mono text-[0.6875rem] text-[var(--text)]">~/mpc-config/macos-desktop/status-watcher.sh</code>).':L===f.LINUX?" Host restart automation: systemd pending-update.path on this Linux host.":"",we=O?" under that WSL directory":" on this machine";u.innerHTML='<p class="m-0"><strong>Install finished.</strong> mpc-config is at '+te+'. Stack containers (mongo, mpc-auth, continuum-mcp, continuumdao-node-app) appear in Docker Desktop → Containers. Open continuumdao-node-app at <code class="font-mono text-[0.6875rem] text-[var(--text)]">http://127.0.0.1:3333</code> for Plain HTTP attach. Back up <code class="font-mono text-[0.6875rem] text-[var(--text)]">bootstrap_key/</code>'+we+" if a new key was generated."+Se+"</p>"}else A(u,`Install failed (exit ${(k==null?void 0:k.code)??"unknown"}). See log above.`)}catch(k){A(u,k instanceof Error?k.message:String(k))}finally{e.disabled=!1}}e.addEventListener("click",()=>{P()}),t.addEventListener("submit",d=>{d.preventDefault(),P()})}document.readyState==="loading"?document.addEventListener("DOMContentLoaded",ue):ue();
