(function () {
  const STORAGE_ACTIVE = "vmstig_tour_active";
  const STORAGE_INDEX = "vmstig_tour_index";
  const STORAGE_IMAGES = "vmstig_tour_images";

  const STORAGE_QUOTES = "vmstig_tour_quotes";

  const GUIDE_IMAGES = [
    "/static/tour-guide-1.png",
    "/static/tour-guide-2.png",
    "/static/tour-guide-3.png",
    "/static/tour-guide-4.png",
  ];

  const HUTCH_QUOTES = [
    "Don't Be Scared",
    "Reboot 3 Times",
    "It's a NOC issue",
    "I'm in training",
    "So........",
  ];

  const STEP_DEFS = [
    {
      id: "welcome",
      paths: ["/"],
      title: "Welcome to the VMware STIG Tool",
      body: "Hi, I'm Hutch. I'll walk you through connecting vCenter, running scans, reviewing results, and remediating findings.",
      center: true,
      panelPos: "tour-panel-cr",
    },
    {
      id: "nav-vcenters",
      paths: ["/", "/vcenters", "/scans", "/scans/new"],
      selector: '[data-tour="nav-vcenters"]',
      title: "Step 1 — vCenter connections",
      body: "Administrators add vCenter systems here. You'll need API credentials for PowerCLI scans.",
      requires: "admin",
      navigate: "/vcenters",
      panelPos: "tour-panel-bl",
    },
    {
      id: "vcenter-form",
      paths: ["/vcenters"],
      selector: '[data-tour="vcenter-form"]',
      title: "Register your vCenter",
      body: "Enter a display name, hostname, and API username/password. SSH credentials are optional for VCSA appliance scans.",
      requires: "admin",
      panelPos: "tour-panel-tl",
    },
    {
      id: "nav-new-scan",
      paths: ["/", "/vcenters", "/scans", "/scans/new"],
      selector: '[data-tour="nav-new-scan"]',
      title: "Step 2 — Start a scan",
      body: "Scanners launch STIG compliance jobs from the New Scan page.",
      requires: "scan",
      navigate: "/scans/new",
      panelPos: "tour-panel-bl",
    },
    {
      id: "scan-setup",
      paths: ["/scans/new"],
      selector: '[data-tour="scan-form"]',
      title: "Configure the scan",
      body: "Pick a vCenter, load the inventory tree, and select ESXi hosts, VMs, or vCenter targets to include.",
      requires: "scan",
      panelPos: "tour-panel-tr",
    },
    {
      id: "scan-inventory",
      paths: ["/scans/new"],
      selector: '[data-tour="scan-inventory"]',
      title: "Choose scan targets",
      body: "Check the hosts and VMs you want assessed. The selected targets drive which STIG profiles run.",
      requires: "scan",
      panelPos: "tour-panel-tl",
    },
    {
      id: "nav-scans",
      paths: ["/", "/vcenters", "/scans", "/scans/new"],
      selector: '[data-tour="nav-scans"]',
      title: "Step 3 — Track scan jobs",
      body: "Open Scans to monitor progress and open completed results.",
      navigate: "/scans",
      panelPos: "tour-panel-bl",
    },
    {
      id: "scans-list",
      paths: ["/scans"],
      selector: '[data-tour="scans-list"]',
      title: "Review scan history",
      body: "Click a scan name for per-target results. Failed or cancelled jobs can be re-run with Rescan.",
      panelPos: "tour-panel-br",
    },
    {
      id: "scan-results",
      paths: ["/scans", "/scans/*"],
      selector: '[data-tour="scan-results"]',
      title: "View findings",
      body: "Open any scan to see per-target results. Click View checklist for STIG rule status, evidence, and JSON/CKL exports.",
      fallbackCenter: true,
      panelPos: "tour-panel-tl",
    },
    {
      id: "remediation",
      paths: ["/scans", "/scans/*", "/scans/*/results/*"],
      title: "Step 4 — Remediate findings",
      body: "On a checklist, select an Open finding with a linked PowerCLI script, choose peer targets if needed, then click Remediate selected.",
      requires: "remediate",
      center: true,
      panelPos: "tour-panel-cr",
    },
    {
      id: "finish",
      paths: ["/", "/vcenters", "/scans", "/scans/new"],
      title: "You're ready to go",
      body: "Restart this tour anytime from the Take a tour button in the navigation bar.",
      center: true,
      panelPos: "tour-panel-cr",
    },
  ];

  const PANEL_POS_CLASSES = [
    "tour-panel-br",
    "tour-panel-bl",
    "tour-panel-tr",
    "tour-panel-tl",
    "tour-panel-cr",
    "tour-panel-dynamic",
  ];

  let steps = [];
  let stepImages = [];
  let stepQuotes = [];
  let index = 0;
  let overlayEl = null;
  let spotlightEl = null;
  let panelEl = null;
  let avatarImgEl = null;
  let bubbleEl = null;
  let activeTarget = null;

  function cfg() {
    return window.VMSTIG_TOUR || {};
  }

  function currentPath() {
    const base = window.APP_BASE || "";
    let path = window.location.pathname || "/";
    if (base && path.startsWith(base)) {
      path = path.slice(base.length) || "/";
    }
    return path.replace(/\/+$/, "") || "/";
  }

  function pageUrl(path) {
    return (window.pageUrl || window.apiUrl)(path);
  }

  function staticAssetUrl(path) {
    const base = pageUrl(path);
    const name = path.split("/").pop();
    const version = (cfg().assetVersions || {})[name];
    return version ? `${base}?v=${encodeURIComponent(version)}` : base;
  }

  function canAccess(requires) {
    const c = cfg();
    if (!requires) return true;
    if (requires === "admin") return !!c.canAdmin;
    if (requires === "scan") return !!c.canScan;
    if (requires === "remediate") return !!c.canRemediate;
    return true;
  }

  function buildSteps() {
    return STEP_DEFS.filter((step) => canAccess(step.requires));
  }

  function shuffle(items) {
    const copy = items.slice();
    for (let i = copy.length - 1; i > 0; i -= 1) {
      const j = Math.floor(Math.random() * (i + 1));
      [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy;
  }

  function buildSequence(items, stepCount, storageKey, reuseSaved) {
    if (reuseSaved) {
      try {
        const saved = JSON.parse(sessionStorage.getItem(storageKey) || "[]");
        if (Array.isArray(saved) && saved.length >= stepCount) {
          return saved.slice(0, stepCount);
        }
      } catch (_) {
        /* ignore */
      }
    }

    const sequence = [];
    while (sequence.length < stepCount) {
      sequence.push(...shuffle(items));
    }
    const trimmed = sequence.slice(0, stepCount);
    sessionStorage.setItem(storageKey, JSON.stringify(trimmed));
    return trimmed;
  }

  function buildImageSequence(stepCount, reuseSaved) {
    return buildSequence(GUIDE_IMAGES, stepCount, STORAGE_IMAGES, reuseSaved);
  }

  function buildQuoteSequence(stepCount, reuseSaved) {
    return buildSequence(HUTCH_QUOTES, stepCount, STORAGE_QUOTES, reuseSaved);
  }

  function saveState() {
    sessionStorage.setItem(STORAGE_ACTIVE, "1");
    sessionStorage.setItem(STORAGE_INDEX, String(index));
  }

  function clearState() {
    sessionStorage.removeItem(STORAGE_ACTIVE);
    sessionStorage.removeItem(STORAGE_INDEX);
    sessionStorage.removeItem(STORAGE_IMAGES);
    sessionStorage.removeItem(STORAGE_QUOTES);
  }

  function isActive() {
    return sessionStorage.getItem(STORAGE_ACTIVE) === "1";
  }

  function pathPatternMatch(pattern, path) {
    if (!pattern.includes("*")) {
      return pattern === path;
    }
    const regex = new RegExp(
      "^" + pattern.replace(/\//g, "\\/").replace(/\*/g, "[^/]+") + "\\/?$"
    );
    return regex.test(path);
  }

  function stepMatchesPath(step) {
    const path = currentPath();
    return (step.paths || [step.path || "/"]).some((candidate) => pathPatternMatch(candidate, path));
  }

  function resolveNavigation(step) {
    if (step.navigate) {
      return step.navigate;
    }
    const paths = step.paths || [step.path || "/"];
    const concrete = paths.find((candidate) => !candidate.includes("*"));
    return concrete || "/";
  }

  function clearPanelPosition() {
    if (!panelEl) return;
    panelEl.style.top = "";
    panelEl.style.left = "";
    panelEl.style.right = "";
    panelEl.style.bottom = "";
    panelEl.style.transform = "";
  }

  function applyLayout(step) {
    if (!panelEl) return;
    clearPanelPosition();
    panelEl.classList.remove(...PANEL_POS_CLASSES);
    panelEl.classList.add(step.panelPos || "tour-panel-cr");
  }

  function positionPanelNearTarget(step, target) {
    if (!panelEl || !target) return false;

    const rect = target.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const pad = 16;
    const inward = 0.38;
    const panelWidth = Math.min(544, vw - pad * 2);
    const panelHeight = 280;

    const targetCx = rect.left + rect.width / 2;
    const targetCy = rect.top + rect.height / 2;
    const screenCx = vw / 2;
    const screenCy = vh / 2;

    const anchorX = targetCx + (screenCx - targetCx) * inward;
    const anchorY = targetCy + (screenCy - targetCy) * inward;

    let left = anchorX - panelWidth * 0.42;
    left = Math.max(pad, Math.min(left, vw - panelWidth - pad));

    let top = anchorY - panelHeight * 0.55;
    if (top < 72) {
      top = Math.min(rect.bottom + pad, vh - panelHeight - pad);
    }
    top = Math.max(72, Math.min(top, vh - panelHeight - pad));

    clearPanelPosition();
    panelEl.classList.remove(...PANEL_POS_CLASSES);
    panelEl.classList.add("tour-panel-dynamic");
    panelEl.style.left = `${left}px`;
    panelEl.style.top = `${top}px`;
    return true;
  }

  function applyStepImage(stepIndex) {
    if (!avatarImgEl || !stepImages.length) return;
    const imagePath = stepImages[stepIndex] || GUIDE_IMAGES[stepIndex % GUIDE_IMAGES.length];
    const nextSrc = staticAssetUrl(imagePath);
    if (avatarImgEl.getAttribute("src") !== nextSrc) {
      avatarImgEl.setAttribute("src", nextSrc);
    }
  }

  function applyStepQuote(stepIndex) {
    if (!bubbleEl) return;
    const quote = stepQuotes[stepIndex] || HUTCH_QUOTES[stepIndex % HUTCH_QUOTES.length];
    bubbleEl.textContent = quote;
    bubbleEl.classList.remove("tour-bubble-animate");
    void bubbleEl.offsetWidth;
    bubbleEl.classList.add("tour-bubble-animate");
  }

  function ensureUi() {
    if (panelEl) return;

    overlayEl = document.createElement("div");
    overlayEl.className = "tour-overlay";
    overlayEl.id = "tour-overlay";
    overlayEl.hidden = true;

    spotlightEl = document.createElement("div");
    spotlightEl.className = "tour-spotlight";
    spotlightEl.id = "tour-spotlight";
    spotlightEl.hidden = true;

    panelEl = document.createElement("div");
    panelEl.className = "tour-guide-panel tour-panel-cr";
    panelEl.id = "tour-guide-panel";
    panelEl.hidden = true;
    panelEl.innerHTML = `
      <div class="tour-guide-shell">
        <div class="tour-guide-avatar-side">
          <div class="tour-guide-bubble" id="tour-guide-bubble">${HUTCH_QUOTES[0]}</div>
          <img id="tour-guide-avatar-img" src="${staticAssetUrl(GUIDE_IMAGES[0])}" alt="Tour guide Hutch">
        </div>
        <div class="tour-guide-card">
          <div class="tour-guide-header">
            <div class="tour-guide-title" id="tour-guide-title"></div>
            <div class="tour-guide-body" id="tour-guide-body"></div>
          </div>
          <div class="tour-guide-footer">
            <div class="tour-guide-progress" id="tour-guide-progress"></div>
            <div class="tour-guide-actions">
              <button type="button" class="tour-btn tour-btn-ghost" id="tour-skip-btn">Skip</button>
              <button type="button" class="tour-btn tour-btn-secondary" id="tour-back-btn">Back</button>
              <button type="button" class="tour-btn tour-btn-primary" id="tour-next-btn">Next</button>
            </div>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(overlayEl);
    document.body.appendChild(spotlightEl);
    document.body.appendChild(panelEl);

    avatarImgEl = document.getElementById("tour-guide-avatar-img");
    bubbleEl = document.getElementById("tour-guide-bubble");

    document.getElementById("tour-skip-btn").addEventListener("click", endTour);
    document.getElementById("tour-back-btn").addEventListener("click", prevStep);
    document.getElementById("tour-next-btn").addEventListener("click", nextStep);
    window.addEventListener("resize", renderCurrentStep);
    window.addEventListener("scroll", renderCurrentStep, true);
  }

  function clearHighlight() {
    if (activeTarget) {
      activeTarget.classList.remove("tour-target-pulse");
      activeTarget = null;
    }
  }

  function findTarget(step) {
    if (step.center || !step.selector) return null;
    const el = document.querySelector(step.selector);
    if (!el) return null;
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) return null;
    return el;
  }

  function renderCurrentStep() {
    if (!panelEl || !steps.length) return;
    const step = steps[index];
    const titleEl = document.getElementById("tour-guide-title");
    const bodyEl = document.getElementById("tour-guide-body");
    const progressEl = document.getElementById("tour-guide-progress");
    const backBtn = document.getElementById("tour-back-btn");
    const nextBtn = document.getElementById("tour-next-btn");

    applyStepImage(index);
    applyStepQuote(index);
    titleEl.textContent = step.title;
    bodyEl.textContent = step.body;
    progressEl.textContent = `Step ${index + 1} of ${steps.length}`;
    backBtn.disabled = index === 0;
    nextBtn.textContent = index === steps.length - 1 ? "Finish" : "Next";

    clearHighlight();
    overlayEl.hidden = false;
    panelEl.hidden = false;

    if (!stepMatchesPath(step)) {
      applyLayout(step);
      spotlightEl.hidden = true;
      return;
    }

    const target = findTarget(step);
    const useCenter = step.center || (step.fallbackCenter && !target);

    if (target && !useCenter) {
      target.classList.add("tour-target-pulse");
      activeTarget = target;
      target.scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" });
      const rect = target.getBoundingClientRect();
      if (!positionPanelNearTarget(step, target)) {
        applyLayout(step);
      }
      const pad = 8;
      spotlightEl.hidden = false;
      spotlightEl.style.top = `${Math.max(8, rect.top - pad)}px`;
      spotlightEl.style.left = `${Math.max(8, rect.left - pad)}px`;
      spotlightEl.style.width = `${rect.width + pad * 2}px`;
      spotlightEl.style.height = `${rect.height + pad * 2}px`;
    } else {
      applyLayout(step);
      spotlightEl.hidden = true;
    }
  }

  function goToStep(newIndex) {
    index = Math.max(0, Math.min(newIndex, steps.length - 1));
    saveState();
    const step = steps[index];
    if (!stepMatchesPath(step)) {
      window.location.href = pageUrl(resolveNavigation(step));
      return;
    }
    renderCurrentStep();
  }

  function nextStep() {
    if (index >= steps.length - 1) {
      endTour();
      return;
    }

    const upcoming = steps[index + 1];
    if (upcoming && !stepMatchesPath(upcoming)) {
      index += 1;
      saveState();
      window.location.href = pageUrl(resolveNavigation(upcoming));
      return;
    }

    goToStep(index + 1);
  }

  function prevStep() {
    if (index <= 0) return;
    const upcoming = steps[index - 1];
    if (!stepMatchesPath(upcoming)) {
      index -= 1;
      saveState();
      window.location.href = pageUrl(resolveNavigation(upcoming));
      return;
    }
    goToStep(index - 1);
  }

  function prepareTourSteps(reuseSaved) {
    steps = buildSteps();
    stepImages = buildImageSequence(steps.length, reuseSaved);
    stepQuotes = buildQuoteSequence(steps.length, reuseSaved);
  }

  function startTour() {
    ensureUi();
    clearState();
    prepareTourSteps(false);
    index = 0;
    saveState();
    const first = steps[0];
    if (first && !stepMatchesPath(first)) {
      window.location.href = pageUrl(resolveNavigation(first));
      return;
    }
    renderCurrentStep();
  }

  function endTour() {
    clearHighlight();
    clearState();
    if (overlayEl) overlayEl.hidden = true;
    if (spotlightEl) spotlightEl.hidden = true;
    if (panelEl) panelEl.hidden = true;
  }

  function resumeIfNeeded() {
    if (!isActive()) return;
    ensureUi();
    prepareTourSteps(true);
    const saved = parseInt(sessionStorage.getItem(STORAGE_INDEX) || "0", 10);
    index = Number.isFinite(saved) ? Math.min(saved, steps.length - 1) : 0;
    const step = steps[index];
    if (step && !stepMatchesPath(step)) {
      const destination = resolveNavigation(step);
      if (destination !== currentPath()) {
        window.location.href = pageUrl(destination);
        return;
      }
    }
    renderCurrentStep();
  }

  window.initVmstigTour = function initVmstigTour() {
    ensureUi();
    const startBtn = document.getElementById("tour-start-btn");
    if (startBtn) {
      startBtn.addEventListener("click", startTour);
    }
    resumeIfNeeded();
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => window.initVmstigTour());
  } else {
    window.initVmstigTour();
  }
})();
