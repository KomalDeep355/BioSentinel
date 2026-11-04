const scenarioNames = [
  "obfuscated_rce",
  "weak_key_gatekeeper",
  "poisoned_dependency",
  "prompt_leak"
];

const scenarioLabels = {
  obfuscated_rce: "Obfuscated execution",
  weak_key_gatekeeper: "Weak-key gatekeeper",
  poisoned_dependency: "Poisoned dependency",
  prompt_leak: "Prompt disclosure"
};

const $ = (id) => document.getElementById(id);

let latestReport = "";
let selectedScenario = "prompt_leak";

function updateClock() {
  const clock = $("clock");
  if (!clock) return;

  clock.textContent = new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  }).format(new Date());
}

updateClock();
setInterval(updateClock, 1000);

async function checkApi() {
  try {
    const response = await fetch("/openapi.json", {
      cache: "no-store"
    });

    if (!response.ok) {
      throw new Error(`API returned ${response.status}`);
    }

    $("sidebarApiStatus").textContent = "API connected";
    $("apiMeter").style.width = "100%";
    $("systemMessage").textContent =
      "FastAPI is reachable. Simulation endpoints are available.";
    $("systemState").textContent = "CONNECTED";
    $("systemDot").classList.add("is-online");
  } catch {
    $("sidebarApiStatus").textContent = "API unavailable";
    $("apiMeter").style.width = "22%";
    $("systemMessage").textContent =
      "Cannot reach FastAPI. Start the server and refresh this page.";
    $("systemState").textContent = "OFFLINE";
    $("systemDot").classList.remove("is-online");
  }
}

async function checkIntegrations() {
  const setStatus = (id, configured) => {
    const element = $(id);
    if (!element) return;

    element.textContent = configured
      ? "Configured"
      : "Not configured";

    element.classList.toggle("pending", !configured);
    element.classList.toggle("verified", configured);
  };

  try {
    const response = await fetch("/api/config", {
      cache: "no-store"
    });

    if (!response.ok) {
      throw new Error("Could not retrieve model configuration");
    }

    const config = await response.json();

    setStatus("agentModelStatus", config.agent_configured);
    setStatus("auditorModelStatus", config.auditor_configured);
  } catch {
    setStatus("agentModelStatus", false);
    setStatus("auditorModelStatus", false);
  }
}

async function testModels() {
  const button = $("testModels");
  if (!button) return;
  const show = (id, r) => {
    const el = $(id);
    if (!el || !r) return;
    const labels = { verified: `Verified ${r.seconds ?? ""}s`, failed: "Failed", not_configured: "Not configured" };
    el.textContent = labels[r.state] || r.state;
    el.title = r.error || "";
    el.classList.toggle("verified", r.state === "verified");
    el.classList.toggle("pending", r.state !== "verified");
  };
  button.addEventListener("click", async () => {
    button.disabled = true;
    button.textContent = "Testing...";
    try {
      const call = (token) => fetch("/api/model-check", { method: "POST", headers: token ? { "X-Demo-Token": token } : {} });
      let response = await call(sessionStorage.getItem("bs-token"));
      if (response.status === 403) {
        const token = window.prompt("Model tests on this public demo need the demo token:");
        if (token) {
          sessionStorage.setItem("bs-token", token);
          response = await call(token);
        }
      }
      if (!response.ok) throw new Error("Model check failed");
      const result = await response.json();
      show("agentModelStatus", result.agent);
      show("auditorModelStatus", result.auditor);
    } catch {
      show("agentModelStatus", { state: "failed", error: "Could not reach the server" });
    } finally {
      button.disabled = false;
      button.textContent = "Test models";
    }
  });
}

checkApi();
checkIntegrations();
testModels();

document.querySelectorAll(".scenario-card").forEach((button) => {
  button.addEventListener("click", () => {
    selectScenario(button.dataset.scenario);
  });
});

function selectScenario(name) {
  if (!scenarioNames.includes(name)) return;

  selectedScenario = name;

  document.querySelectorAll(".scenario-card").forEach((button) => {
    button.classList.toggle(
      "selected",
      button.dataset.scenario === name
    );
  });

  $("runError").hidden = true;
}

function setBusy(busy) {
  $("runButton").disabled = busy;
  $("runButtonText").textContent = busy
    ? "Running simulation…"
    : "Run simulation";

  $("runButton").classList.toggle("is-loading", busy);
}

async function runScenario(name = selectedScenario) {
  if (!scenarioNames.includes(name)) {
    $("runError").textContent = "Unknown scenario selected.";
    $("runError").hidden = false;
    return;
  }

  selectScenario(name);
  setBusy(true);
  $("runError").hidden = true;

  try {
    const stealth = $("stealth").checked;
    const endpoint =
      `/demo/${encodeURIComponent(name)}?stealth=${stealth}`;

    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        Accept: "application/json"
      }
    });

    let data;

    try {
      data = await response.json();
    } catch {
      throw new Error("The API returned an invalid JSON response.");
    }

    if (!response.ok) {
      const message =
        typeof data.detail === "string"
          ? data.detail
          : `Request failed (${response.status})`;

      throw new Error(message);
    }

    renderScenario(data, name);
  } catch (error) {
    $("runError").textContent =
      `Could not run scenario. ${error.message} Check that the BioSentinel API is running.`;

    $("runError").hidden = false;
    $("systemMessage").textContent =
      "The simulation could not be completed. Check the API and try again.";
  } finally {
    setBusy(false);
  }
}

$("runButton").addEventListener("click", () => {
  runScenario();
});

function appendInlineMarkdown(container, text) {
  const pattern =
    /(\*\*[^*]+\*\*|__[^_]+__|\*[^*]+\*|_[^_]+_|`[^`]+`|\[Q\d+\])/g;

  let lastIndex = 0;
  let match;

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > lastIndex) {
      container.appendChild(
        document.createTextNode(
          text.slice(lastIndex, match.index)
        )
      );
    }

    const token = match[0];
    let element;

    if (token.startsWith("**") || token.startsWith("__")) {
      element = document.createElement("strong");
      element.textContent = token.slice(2, -2);
    } else if (token.startsWith("*") || token.startsWith("_")) {
      element = document.createElement("em");
      element.textContent = token.slice(1, -1);
    } else if (token.startsWith("`")) {
      element = document.createElement("code");
      element.textContent = token.slice(1, -1);
    } else {
      element = document.createElement("span");
      element.className = "evidence-citation";
      element.textContent = token.slice(1, -1);
      element.setAttribute("aria-label", `Evidence citation ${token.slice(1, -1)}`);
    }

    container.appendChild(element);
    lastIndex = pattern.lastIndex;
  }

  if (lastIndex < text.length) {
    container.appendChild(
      document.createTextNode(text.slice(lastIndex))
    );
  }
}

function renderMarkdownReport(markdown) {
  const container = $("reportContent");
  container.replaceChildren();

  if (!markdown || typeof markdown !== "string") {
    container.textContent = "No forensic report was returned.";
    return;
  }

  const lines = markdown.split(/\r?\n/);
  let paragraph = [];
  let list = null;
  let codeLines = [];
  let inCodeBlock = false;

  function flushParagraph() {
    if (!paragraph.length) return;

    const p = document.createElement("p");
    appendInlineMarkdown(p, paragraph.join(" "));
    container.appendChild(p);
    paragraph = [];
  }

  function flushList() {
    if (!list) return;

    container.appendChild(list);
    list = null;
  }

  function flushTextBlocks() {
    flushParagraph();
    flushList();
  }

  function addCodeBlock() {
    const pre = document.createElement("pre");
    const code = document.createElement("code");

    code.textContent = codeLines.join("\n");
    pre.appendChild(code);
    container.appendChild(pre);
    codeLines = [];
  }

  for (const line of lines) {
    if (line.trim().startsWith("```")) {
      flushTextBlocks();

      if (inCodeBlock) {
        addCodeBlock();
        inCodeBlock = false;
      } else {
        inCodeBlock = true;
      }

      continue;
    }

    if (inCodeBlock) {
      codeLines.push(line);
      continue;
    }

    const heading = line.match(/^(#{1,3})\s+(.+)$/);

    if (heading) {
      flushTextBlocks();

      const level = heading[1].length;
      const element = document.createElement(`h${level}`);

      appendInlineMarkdown(element, heading[2]);
      container.appendChild(element);
      continue;
    }

    const bullet = line.match(/^\s*[-*+]\s+(.+)$/);
    const numbered = line.match(/^\s*\d+[.)]\s+(.+)$/);

    if (bullet || numbered) {
      flushParagraph();

      if (!list) {
        list = document.createElement(numbered ? "ol" : "ul");
      }

      const item = document.createElement("li");
      appendInlineMarkdown(item, (bullet || numbered)[1]);
      list.appendChild(item);
      continue;
    }

    if (/^\s*>\s?/.test(line)) {
      flushTextBlocks();

      const quote = document.createElement("blockquote");
      appendInlineMarkdown(quote, line.replace(/^\s*>\s?/, ""));
      container.appendChild(quote);
      continue;
    }

    if (/^\s*[-*_]{3,}\s*$/.test(line)) {
      flushTextBlocks();
      container.appendChild(document.createElement("hr"));
      continue;
    }

    if (!line.trim()) {
      flushTextBlocks();
      continue;
    }

    flushList();
    paragraph.push(line.trim());
  }

  if (inCodeBlock) {
    addCodeBlock();
  }

  flushTextBlocks();
}

function renderScenario(data, name) {
  const timeline = Array.isArray(data.timeline)
    ? data.timeline
    : [];

  const quarantine =
    timeline.find((item) => item.quarantined_now) ||
    timeline.find((item) => item.state === "QUARANTINED");

  const warning = timeline.find(
    (item) =>
      item.state === "WATCH" ||
      item.state === "QUARANTINED"
  );

  const breach = Number.isFinite(data.breach_step)
    ? data.breach_step
    : null;

  const quarantineStep = quarantine
    ? quarantine.step
    : null;

  const lead =
    warning && quarantine
      ? Math.max(0, quarantine.step - warning.step)
      : null;

  const finalState = timeline.length
    ? timeline[timeline.length - 1].state
    : "UNKNOWN";

  $("metricRun").textContent =
    name === "prompt_leak"
      ? "PROMPT-01"
      : name.toUpperCase().replaceAll("_", "-");

  $("metricScenario").textContent =
    scenarioLabels[name] || name;

  $("metricState").textContent = finalState;
  $("metricState").className =
    "metric-value state-value " + finalState;

  $("metricStateHint").textContent =
    finalState === "QUARANTINED"
      ? "Threat contained in simulation"
      : finalState === "WATCH"
        ? "Anomaly under observation"
        : finalState === "HEALTHY"
          ? "No anomaly reported in this run"
          : "No final detection state available";

  $("metricQuarantine").textContent =
    quarantineStep === null
      ? "NO"
      : `STEP ${quarantineStep}`;

  $("metricQuarantineHint").textContent =
    quarantineStep === null
      ? "No quarantine recorded"
      : "Simulated quarantine event";

  $("metricLead").textContent =
    lead === null
      ? "—"
      : `${lead} ${lead === 1 ? "STEP" : "STEPS"}`;

  $("firstWarning").textContent =
    warning ? `STEP ${warning.step}` : "None";

  $("breachPoint").textContent =
    breach === null ? "Not reported" : `STEP ${breach}`;

  $("quarantinePoint").textContent =
    quarantineStep === null
      ? "Not triggered"
      : `STEP ${quarantineStep}`;

  $("chartStepCount").textContent =
    `${timeline.length} STEPS`;

  latestReport =
    typeof data.report === "string"
      ? data.report
      : "";

  $("reportTag").textContent =
    latestReport ? "REPORT READY" : "NO REPORT";

  $("reportMeta").replaceChildren();

  const dot = document.createElement("span");
  dot.className = "report-dot";

  const metaText = document.createElement("span");
  metaText.textContent =
    `${scenarioLabels[name] || name} · ${
      quarantineStep === null
        ? "No quarantine event reported"
        : `quarantined at step ${quarantineStep}`
    } · Local simulation`;

  $("reportMeta").append(dot, metaText);

  renderMarkdownReport(latestReport);

  $("copyReport").disabled = !latestReport;
  $("downloadReport").disabled = !latestReport;

  renderTimeline(timeline, breach, quarantineStep);

  $("systemMessage").textContent =
    "Simulation completed using the local sample-mode engine.";

  $("activity").scrollIntoView({
    behavior: "smooth",
    block: "nearest"
  });
}

function renderTimeline(timeline, breach, quarantineStep) {
  const chart = $("trajectoryChart");
  chart.replaceChildren();

  if (!timeline.length) {
    const empty = document.createElement("div");
    empty.className = "chart-empty";

    const title = document.createElement("strong");
    title.textContent = "No timeline returned";

    const description = document.createElement("span");
    description.textContent = "Try another scenario.";

    empty.append(title, description);
    chart.appendChild(empty);
    return;
  }

  const bars = document.createElement("div");
  bars.className = "bar-track";

  const maxCusum = Math.max(
    1,
    ...timeline.map((item) => Number(item.cusum) || 0)
  );

  timeline.forEach((item) => {
    const barWrap = document.createElement("div");
    barWrap.className = "bar-wrap";

    const bar = document.createElement("div");

    const state = [
      "HEALTHY",
      "WATCH",
      "QUARANTINED"
    ].includes(item.state)
      ? item.state
      : "HEALTHY";

    bar.className = `timeline-bar ${state}`;

    const score = Number(item.cusum) || 0;
    const height = Math.max(
      5,
      Math.min(100, 8 + (score / maxCusum) * 82)
    );

    bar.style.height = `${height}%`;
    bar.title =
      `Step ${item.step} · ${state} · score ${item.score} · CUSUM ${item.cusum}`;

    if (item.step === breach) {
      bar.classList.add("breach-marker");
    }

    if (item.step === quarantineStep) {
      bar.classList.add("quarantine-marker");
    }

    bar.setAttribute("role", "img");
    bar.setAttribute(
      "aria-label",
      `Step ${item.step}, state ${state}, CUSUM ${item.cusum}`
    );

    barWrap.appendChild(bar);
    bars.appendChild(barWrap);
  });

  chart.appendChild(bars);
}

$("copyReport").addEventListener("click", async () => {
  if (!latestReport) return;

  try {
    await navigator.clipboard.writeText(latestReport);

    const button = $("copyReport");
    const originalText = "▣ Copy report";

    button.textContent = "✓ Copied";

    setTimeout(() => {
      button.textContent = originalText;
    }, 1500);
  } catch {
    $("copyReport").textContent = "Clipboard unavailable";
  }
});

$("downloadReport").addEventListener("click", () => {
  if (!latestReport) return;

  const blob = new Blob(
    [latestReport],
    { type: "text/markdown;charset=utf-8" }
  );

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download =
    `biosentinel-${selectedScenario}-report.md`;

  document.body.appendChild(link);
  link.click();
  link.remove();

  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

const helpLauncher = $("helpLauncher");
const helpPanel = $("helpPanel");

function toggleHelp(force) {
  const open =
    typeof force === "boolean"
      ? force
      : helpPanel.hidden;

  helpPanel.hidden = !open;

  helpLauncher.setAttribute(
    "aria-expanded",
    String(open)
  );

  helpLauncher.classList.toggle("help-open", open);
}

helpLauncher.addEventListener("click", () => {
  toggleHelp();
});

$("helpClose").addEventListener("click", () => {
  toggleHelp(false);
});

document.querySelectorAll("[data-help]").forEach((button) => {
  button.addEventListener("click", () => {
    const action = button.dataset.help;

    toggleHelp(false);

    if (action === "evidence") {
      $("evidence").scrollIntoView({
        behavior: "smooth"
      });
    } else {
      runScenario(action);
    }
  });
});

document.querySelectorAll(".nav-link").forEach((link) => {
  link.addEventListener("click", () => {
    document.querySelectorAll(".nav-link").forEach((item) => {
      item.classList.remove("active");
    });

    link.classList.add("active");

    if (window.innerWidth <= 900) {
      $("sidebar").classList.remove("sidebar-open");
    }
  });
});

$("mobileMenu").addEventListener("click", () => {
  $("sidebar").classList.toggle("sidebar-open");
});

runScenario("prompt_leak");