(() => {
  const css = `
  #bs-live{position:fixed;right:16px;bottom:16px;width:440px;max-height:70vh;display:flex;flex-direction:column;
    background:#0f1623;color:#e6ebf5;border:1px solid #26324b;border-radius:12px;font:13px system-ui,sans-serif;
    box-shadow:0 8px 32px rgba(0,0,0,.4);z-index:50}
  #bs-live.min #bs-feed,#bs-live.min #bs-bar{display:none}
  #bs-head{display:flex;align-items:center;gap:8px;padding:10px 12px;cursor:pointer;font-weight:600}
  #bs-dot{width:8px;height:8px;border-radius:50%;background:#55607a}
  #bs-dot.on{background:#3ddc97}
  #bs-bar{display:flex;gap:6px;padding:0 12px 10px;flex-wrap:wrap}
  #bs-bar button{background:#1a2335;color:#e6ebf5;border:1px solid #2a3652;border-radius:6px;padding:6px 10px;cursor:pointer;font-size:12px}
  #bs-bar button:hover{border-color:#6d8bff}
  #bs-feed{overflow-y:auto;padding:0 12px 12px;display:flex;flex-direction:column;gap:6px}
  .bs-row{border-left:3px solid #3ddc97;padding:4px 8px;background:#121a28;border-radius:4px}
  .bs-row.WATCH{border-color:#ffb84d}.bs-row.QUARANTINED,.bs-row.blocked,.bs-row.error{border-color:#ff5d5d}
  .bs-row.note{border-color:#6d8bff;color:#9fb3d9}
  .bs-row.UNPROTECTED{border-color:#8b97ad}.bs-row.leak{border-color:#ff5d5d;background:#2a1218}
  #bs-live.min #bs-lab{display:none}
  #bs-lab{padding:0 12px 10px;display:flex;flex-direction:column;gap:6px;border-top:1px solid #26324b;padding-top:8px}
  #bs-lab select,#bs-lab textarea{background:#121a28;color:#e6ebf5;border:1px solid #2a3652;border-radius:6px;padding:6px;font:12px system-ui}
  #bs-lab textarea{min-height:46px;resize:vertical}
  #lab-row{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
  #lab-inbox{background:#1a0f14;border:1px solid #4a2230;border-radius:6px;padding:6px;font-size:12px;min-height:22px}
  #bs-live.inline{position:static;width:100%;max-height:none;box-shadow:none;display:grid;grid-template-columns:minmax(320px,400px) minmax(0,1fr);background:#0b111b}
  #bs-live.inline #bs-head{grid-column:1/-1;cursor:default}
  #bs-live.inline #bs-head span:last-child{display:none}
  #bs-live.inline #bs-bar{grid-column:1/-1}
  #bs-live.inline #bs-lab{grid-column:1;grid-row:3;border-top:none}
  #bs-live.inline #bs-feed{grid-column:2;grid-row:3;max-height:540px;min-height:320px;padding-top:8px}
  @media(max-width:900px){#bs-live.inline{grid-template-columns:1fr}#bs-live.inline #bs-lab,#bs-live.inline #bs-feed{grid-column:1;grid-row:auto}}
  .bs-meta{color:#8b97ad;font-size:11px}`;
  const st = document.createElement("style"); st.textContent = css; document.head.appendChild(st);
  const box = document.createElement("div"); box.id = "bs-live";
  box.innerHTML = `<div id="bs-head"><span id="bs-dot"></span>Live agent feed<span style="margin-left:auto;color:#8b97ad">toggle</span></div>
  <div id="bs-bar"><button data-m="scripted" data-a="false">Replay: normal</button>
  <button data-m="scripted" data-a="true">Replay: attack</button>
  <button data-m="scripted" data-a="true" data-v="stealth">Replay: stealth attack</button>
  <button data-m="live" data-a="true">Live model: attack</button>
  <button id="bs-verify">Verify audit log</button><button id="bs-tamper">Tamper (demo)</button></div><div id="bs-lab"><b>Attack lab</b><span class="bs-meta">Sandbox: the agent can only open a mock site. Secrets are fake.</span>
  <div id="lab-row"><select id="lab-preset"><option value="injection">Explicit injection</option><option value="stealth">Stealth (polite)</option><option value="custom">Custom text</option><option value="none">No attack (control)</option></select>
  <select id="lab-mode"><option value="scripted">Scripted agent</option><option value="live">Live model</option></select>
  <label><input type="checkbox" id="lab-prot" checked> BioSentinel on</label></div>
  <textarea id="lab-text" placeholder="Custom attacker text planted on the page..."></textarea>
  <div id="lab-row"><button id="lab-go">Launch</button><button id="lab-clear">Reset inbox and feed</button></div>
  <div class="bs-meta">Attacker inbox (what the attacker received):</div><div id="lab-inbox">empty</div></div><div id="bs-feed"></div>`;
  const mount = document.getElementById("attack-lab-mount");
  if (mount) { box.classList.add("inline"); mount.appendChild(box); } else { document.body.appendChild(box); }
  const feed = box.querySelector("#bs-feed"), dot = box.querySelector("#bs-dot");
  box.querySelector("#bs-head").onclick = () => { if (!box.classList.contains("inline")) box.classList.toggle("min"); };
  const add = (cls, html) => { const d = document.createElement("div"); d.className = "bs-row " + cls;
    d.innerHTML = html; feed.appendChild(d); feed.scrollTop = feed.scrollHeight; };
  const esc = s => String(s ?? "").replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
  const es = new EventSource("/api/stream");
  es.onopen = () => dot.classList.add("on"); es.onerror = () => dot.classList.remove("on");
  es.onmessage = m => {
    const e = JSON.parse(m.data);
    if (e.type === "run") add("note", `Run started (${e.mode === "live" ? "live model" : "scripted replay"}, ${e.attack ? "attack" : "normal"})`);
    else if (e.type === "step") { if (e.step < 100 && String(e.agent_id).startsWith("live-agent")) return;
      add(e.state, `<b>${esc(e.tool)}</b> &rarr; ${esc(e.destination || "")}<div>${esc(e.text)}</div>
      <div class="bs-meta">step ${e.step} · ${e.state} · score ${e.score} · cusum ${e.cusum}${e.blocked ? " · BLOCKED" : ""}</div>`); }
    else if (e.type === "verdict") add("QUARANTINED", `<b>Verdict:</b> ${esc(e.verdict)} (confidence ${esc(e.confidence)})`);
    else if (e.type === "policy_block") add("QUARANTINED", `<b>Policy block (${esc(e.rule)})</b><div>${esc(e.text)}</div><div class="bs-meta">evidence: ${esc((e.evidence || []).join(" | "))}</div>`);
    else if (e.type === "leak") { add("leak", `<b>LEAKED to ${esc(e.to)}</b> (${esc(e.run)})<div>${esc(e.body)}</div>`); loadInbox(); }
    else if (e.type === "blocked" || e.type === "error") add(e.type, esc(e.text));
    else if (e.type === "done") add("note", "Run finished: " + esc(e.outcome));
  };
  box.querySelectorAll("#bs-bar button[data-m]").forEach(b => b.onclick = async () => {
    feed.innerHTML = "";
    const r = await post("/api/run-live", { mode: b.dataset.m, attack: b.dataset.a === "true", variant: b.dataset.v || "injection" }, b.dataset.m === "live");
    if (!r.ok) add("error", esc((await r.json()).detail || "Request failed"));
  });
  const showAudit = async () => { const a = await (await fetch("/api/audit")).json();
    add(a.verified ? "note" : "error", a.verified ? `Audit chain verified: ${a.count} entries, head ${esc(a.head.slice(0, 12))}...`
      : `AUDIT CHAIN BROKEN at entry ${a.first_bad_index} of ${a.count}`); };
  box.querySelector("#bs-verify").onclick = showAudit;
  box.querySelector("#bs-tamper").onclick = async () => { const r = await fetch("/api/audit/tamper", { method: "POST" });
    if (!r.ok) add("error", "Run a scenario first"); else showAudit(); };
  const tokenHeaders = () => { const t = sessionStorage.getItem("bs-token"); return t ? { "X-Demo-Token": t } : {}; };
  const post = async (url, body, live) => {
    let r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", ...tokenHeaders() }, body: JSON.stringify(body) });
    if (r.status === 403 && live) {
      const t = window.prompt("Live-model runs on this public demo need the demo token:");
      if (t) { sessionStorage.setItem("bs-token", t);
        r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", "X-Demo-Token": t }, body: JSON.stringify(body) }); }
    }
    return r;
  };
  const inbox = box.querySelector("#lab-inbox");
  const loadInbox = async () => { const r = await (await fetch("/api/lab/outbox")).json();
    inbox.innerHTML = r.messages.length ? r.messages.map(m => `<div><b>${esc(m.run)}</b> to ${esc(m.to)}: ${esc(m.body)}</div>`).join("") : "empty"; };
  box.querySelector("#lab-go").onclick = async () => {
    const mode = box.querySelector("#lab-mode").value;
    const r = await post("/api/lab/run", { mode, preset: box.querySelector("#lab-preset").value,
      payload: box.querySelector("#lab-text").value, protected: box.querySelector("#lab-prot").checked }, mode === "live");
    if (!r.ok) { const d = await r.json().catch(() => ({})); add("error", esc(d.detail || "Request failed")); } };
  box.querySelector("#lab-clear").onclick = async () => { await fetch("/api/lab/reset", { method: "POST" }); feed.innerHTML = ""; loadInbox(); };
  loadInbox();
})();