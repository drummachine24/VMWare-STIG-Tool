(function () {
  const STATUS_STYLE = {
    NF: "bg-emerald-900/60 text-emerald-300",
    O: "bg-red-900/60 text-red-300",
    NR: "bg-amber-900/60 text-amber-300",
    NA: "bg-slate-700 text-slate-300",
  };

  const STATUS_LABEL = {
    NF: "Not A Finding",
    O: "Open",
    NR: "Not Reviewed",
    NA: "Not Applicable",
  };

  function escapeHtml(text) {
    const d = document.createElement("div");
    d.textContent = text ?? "";
    return d.innerHTML;
  }

  function formatCounts(c) {
    return `${c.nf || 0} NF · ${c.open || 0} Open · ${c.nr || 0} NR · ${c.na || 0} NA`;
  }

  window.initChecklistViewer = function (options) {
    const jobId = options.jobId;
    const resultId = options.resultId;
    const canRemediate = options.canRemediate === true;
    let items = [];
    let filtered = [];
    let activeFilter = "all";
    let selectedIndex = 0;
    let checklistMeta = {};
    let peerCache = {};
    let peerSelections = {};
    let activeRemediationJobId = null;
    let remediationPollTimer = null;
    let variablesPreviewCache = {};
    let variablesPreviewDefault = "";

    const loading = document.getElementById("checklist-loading");
    const app = document.getElementById("checklist-app");
    const countsEl = document.getElementById("checklist-counts");
    const listEl = document.getElementById("checklist-rule-list");
    const searchEl = document.getElementById("checklist-search");
    const detail = document.getElementById("checklist-detail");
    const detailEmpty = document.getElementById("checklist-detail-empty");

    function applyFilters() {
      const q = (searchEl?.value || "").trim().toLowerCase();
      filtered = items.filter((item) => {
        if (activeFilter !== "all" && item.status !== activeFilter) return false;
        if (!q) return true;
        const hay = `${item.rule_id} ${item.rule_title} ${item.stig_title}`.toLowerCase();
        return hay.includes(q);
      });
      if (selectedIndex >= filtered.length) selectedIndex = 0;
      renderList();
      renderDetail();
    }

    function renderCounts(data) {
      if (!countsEl) return;
      const c = data.counts;
      countsEl.innerHTML = `
        <span class="px-2 py-1 rounded bg-slate-800">${escapeHtml(formatCounts(c))}</span>
        <span class="text-slate-500">${filtered.length} / ${items.length} rules shown</span>`;
    }

    function renderList() {
      if (!listEl) return;
      if (!filtered.length) {
        listEl.innerHTML = '<li class="p-3 text-slate-500 text-sm">No matching rules.</li>';
        return;
      }
      listEl.innerHTML = filtered
        .map((item, idx) => {
          const active = idx === selectedIndex ? "border-emerald-700 bg-slate-800" : "border-transparent hover:bg-slate-800/60";
          const st = STATUS_STYLE[item.status] || STATUS_STYLE.NR;
          return `
            <li>
              <button type="button" data-idx="${idx}" class="checklist-rule w-full text-left rounded-lg border px-2 py-2 ${active}">
                <div class="flex items-start gap-2">
                  <span class="shrink-0 px-1.5 py-0.5 rounded text-[10px] font-medium ${st}">${escapeHtml(item.status)}</span>
                  <div class="min-w-0">
                    <div class="font-mono text-xs text-slate-400 truncate">${escapeHtml(item.rule_id)}</div>
                    <div class="text-slate-200 truncate">${escapeHtml(item.rule_title || item.control_id)}</div>
                  </div>
                </div>
              </button>
            </li>`;
        })
        .join("");

      listEl.querySelectorAll(".checklist-rule").forEach((btn) => {
        btn.addEventListener("click", () => {
          selectedIndex = parseInt(btn.dataset.idx, 10);
          renderList();
          renderDetail();
        });
      });
    }

    function renderDetail() {
      const item = filtered[selectedIndex];
      if (!item) {
        detail?.classList.add("hidden");
        detailEmpty?.classList.remove("hidden");
        return;
      }
      detailEmpty?.classList.add("hidden");
      detail?.classList.remove("hidden");

      const statusEl = document.getElementById("detail-status");
      const titleEl = document.getElementById("detail-title");
      const metaEl = document.getElementById("detail-meta");
      const checkEl = document.getElementById("detail-check");
      const findingEl = document.getElementById("detail-finding");
      const fixEl = document.getElementById("detail-fix");
      const remEl = document.getElementById("detail-remediation");
      const remMetaEl = document.getElementById("detail-remediation-meta");

      if (statusEl) {
        statusEl.textContent = STATUS_LABEL[item.status] || item.status;
        statusEl.className = `inline-block px-2 py-0.5 rounded text-xs font-medium mb-2 ${STATUS_STYLE[item.status] || STATUS_STYLE.NR}`;
      }
      if (titleEl) titleEl.textContent = item.rule_title || item.rule_id;
      if (metaEl) {
        metaEl.textContent = `${item.rule_id} · ${item.severity || "unknown severity"} · ${item.stig_title || ""}`;
      }
      if (checkEl) checkEl.textContent = item.check_content || "—";
      if (findingEl) findingEl.textContent = item.finding_details || "—";
      if (fixEl) fixEl.textContent = item.fix_text || "—";

      const rem = item.remediation || {};
      const snippet =
        rem.snippet ||
        item.remediation_script ||
        rem.variables_hint ||
        item.remediation_note ||
        "No automated remediation snippet found in the mounted profile repository for this control.";

      if (remEl) remEl.textContent = snippet;

      if (remMetaEl) {
        const links = [];
        if (rem.github_script_url) {
          links.push(`<a href="${rem.github_script_url}" target="_blank" rel="noopener" class="text-sky-400 hover:underline">PowerCLI script on GitHub</a>`);
        }
        if (rem.github_variables_url) {
          links.push(`<a href="${rem.github_variables_url}" target="_blank" rel="noopener" class="text-sky-400 hover:underline">Variables file</a>`);
        }
        if (rem.github_global_variables_url) {
          links.push(`<a href="${rem.github_global_variables_url}" target="_blank" rel="noopener" class="text-sky-400 hover:underline">Global variables</a>`);
        }
        links.push(`<a href="${rem.github_search || 'https://github.com/search?q=repo%3Avmware%2Fdod-compliance-and-automation+remediation&type=code'}" target="_blank" rel="noopener" class="text-sky-400 hover:underline">Search on GitHub</a>`);
        (rem.ansible_matches || []).forEach((m) => {
          links.push(`<a href="${m.github_url}" target="_blank" rel="noopener" class="text-violet-400 hover:underline">Ansible: ${escapeHtml(m.path)}</a>`);
        });

        const meta = [];
        if (rem.vcf_control_id) meta.push(`Control: ${escapeHtml(rem.vcf_control_id)}`);
        if (rem.type) meta.push(`Type: ${escapeHtml(rem.type)}`);
        if (rem.script_name) meta.push(`Script: ${escapeHtml(rem.script_name)}`);
        if (rem.variables_hint) meta.push(`Variables: ${escapeHtml(rem.variables_hint)}`);
        if (rem.run_command) meta.push(`Run: ${escapeHtml(rem.run_command)}`);
        if (rem.docs) meta.push(escapeHtml(rem.docs));

        remMetaEl.innerHTML = [
          meta.map((m) => `<div>${m}</div>`).join(""),
          links.length ? `<div class="pt-1 flex flex-wrap gap-3">${links.join("")}</div>` : "",
        ].join("");
      }

      renderRemediatePanel(item);
    }

    function canRemediateItem(item) {
      const rem = item.remediation || {};
      return item.status === "O" && rem.type === "powercli" && rem.vcf_control_id && checklistMeta.remediation_status?.synced && canRemediate;
    }

    async function loadPeers(item) {
      const rem = item.remediation || {};
      const cacheKey = `${item.rule_id}|${item.control_id || ""}|${rem.vcf_control_id || ""}`;
      if (peerCache[cacheKey]) return peerCache[cacheKey];

      const params = new URLSearchParams({
        rule_id: item.rule_id,
        control_id: item.control_id || "",
        vcf_control_id: rem.vcf_control_id || "",
      });
        const resp = await fetch(apiUrl(`/api/scans/${jobId}/results/${resultId}/remediation/peers?${params.toString()}`));
      if (!resp.ok) throw new Error(await resp.text());
      const data = await resp.json();
      peerCache[cacheKey] = data;
      data.peers.forEach((peer) => {
        if (peerSelections[peer.result_id] === undefined) {
          peerSelections[peer.result_id] = peer.selected;
        }
      });
      return data;
    }

    function renderPeerCheckboxes(peers) {
      const peersEl = document.getElementById("detail-remediate-peers");
      if (!peersEl) return;
      if (!peers.length) {
        peersEl.innerHTML = '<p class="text-xs text-slate-500">No other targets in this scan have this open finding.</p>';
        return;
      }
      peersEl.innerHTML = peers
        .map((peer) => {
          const checked = peerSelections[peer.result_id] ? "checked" : "";
          const current = peer.is_current ? ' <span class="text-violet-300">(this checklist)</span>' : "";
          return `
            <label class="flex items-center gap-2 text-sm text-slate-200">
              <input type="checkbox" class="remediate-peer rounded border-slate-600 bg-slate-900" data-result-id="${peer.result_id}" ${checked}>
              <span>${escapeHtml(peer.target_name)}${current}</span>
            </label>`;
        })
        .join("");

      peersEl.querySelectorAll(".remediate-peer").forEach((input) => {
        input.addEventListener("change", () => {
          peerSelections[parseInt(input.dataset.resultId, 10)] = input.checked;
        });
      });
    }

    async function loadVariablesPreview(item) {
      const rem = item.remediation || {};
      const wrap = document.getElementById("detail-remediate-variables-wrap");
      const textarea = document.getElementById("detail-remediate-variables");
      const notesEl = document.getElementById("detail-remediate-variables-notes");
      if (!wrap || !textarea) return;

      const cacheKey = `${item.rule_id}|${item.control_id || ""}|${rem.vcf_control_id || ""}`;
      const params = new URLSearchParams({
        rule_id: item.rule_id,
        control_id: item.control_id || "",
        vcf_control_id: rem.vcf_control_id || "",
      });
      const resp = await fetch(
        apiUrl(`/api/scans/${jobId}/results/${resultId}/remediation/preview?${params.toString()}`)
      );
      if (!resp.ok) throw new Error(await resp.text());
      const preview = await resp.json();
      variablesPreviewCache[cacheKey] = preview;
      variablesPreviewDefault = preview.variables_content || "";
      textarea.value = variablesPreviewDefault;
      if (notesEl) {
        const hint = preview.variables_hint ? ` Hint: ${preview.variables_hint}` : "";
        notesEl.textContent = `${preview.notes || ""}${hint}`;
      }
      wrap.classList.remove("hidden");
    }

    async function renderRemediatePanel(item) {
      const panel = document.getElementById("detail-remediate-panel");
      const btn = document.getElementById("detail-remediate-btn");
      const statusEl = document.getElementById("detail-remediate-status");
      if (!panel) return;

      if (!canRemediateItem(item)) {
        panel.classList.add("hidden");
        return;
      }

      panel.classList.remove("hidden");
      if (statusEl && !activeRemediationJobId) statusEl.classList.add("hidden");

      try {
        if (btn) btn.disabled = true;
        const data = await loadPeers(item);
        renderPeerCheckboxes(data.peers || []);
        try {
          await loadVariablesPreview(item);
        } catch (previewErr) {
          const wrap = document.getElementById("detail-remediate-variables-wrap");
          const notesEl = document.getElementById("detail-remediate-variables-notes");
          if (wrap) wrap.classList.add("hidden");
          if (notesEl) notesEl.textContent = `Could not load variables preview: ${previewErr.message}`;
        }
        if (btn) btn.disabled = !!activeRemediationJobId;
      } catch (err) {
        const peersEl = document.getElementById("detail-remediate-peers");
        if (peersEl) peersEl.innerHTML = `<p class="text-xs text-red-300">${escapeHtml(err.message)}</p>`;
      }
    }

    async function startRemediation(item) {
      const rem = item.remediation || {};
      const selectedIds = Object.entries(peerSelections)
        .filter(([, checked]) => checked)
        .map(([id]) => parseInt(id, 10));

      if (!selectedIds.length) {
        alert("Select at least one target to remediate.");
        return;
      }

      const btn = document.getElementById("detail-remediate-btn");
      const statusEl = document.getElementById("detail-remediate-status");
      if (btn) btn.disabled = true;
      if (statusEl) {
        statusEl.classList.remove("hidden");
        statusEl.className = "text-sm rounded-lg border border-violet-800 bg-violet-950/40 p-3 text-violet-100";
        statusEl.textContent = "Starting remediation...";
      }

      const resp = await fetch(apiUrl(`/api/scans/${jobId}/results/${resultId}/remediation`), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rule_id: item.rule_id,
          control_id: item.control_id || "",
          vcf_control_id: rem.vcf_control_id || "",
          target_result_ids: selectedIds,
          variables_content: document.getElementById("detail-remediate-variables")?.value || null,
        }),
      });
      if (!resp.ok) throw new Error(await resp.text());
      const job = await resp.json();
      activeRemediationJobId = job.id;
      pollRemediationJob(job.id);
    }

    function pollRemediationJob(remediationJobId) {
      if (remediationPollTimer) clearInterval(remediationPollTimer);
      remediationPollTimer = setInterval(async () => {
        try {
          const resp = await fetch(apiUrl(`/api/scans/remediation/${remediationJobId}`));
          if (!resp.ok) throw new Error(await resp.text());
          const job = await resp.json();
          renderRemediationStatus(job);
          if (["completed", "failed", "partial"].includes(job.status)) {
            clearInterval(remediationPollTimer);
            remediationPollTimer = null;
            activeRemediationJobId = null;
            const btn = document.getElementById("detail-remediate-btn");
            if (btn) btn.disabled = false;
          }
        } catch (err) {
          const statusEl = document.getElementById("detail-remediate-status");
          if (statusEl) {
            statusEl.classList.remove("hidden");
            statusEl.className = "text-sm rounded-lg border border-red-800 bg-red-950/40 p-3 text-red-200";
            statusEl.textContent = err.message;
          }
        }
      }, 2000);
    }

    function renderRemediationStatus(job) {
      const statusEl = document.getElementById("detail-remediate-status");
      if (!statusEl) return;
      statusEl.classList.remove("hidden");
      const done = ["completed", "failed", "partial"].includes(job.status);
      statusEl.className = done
        ? "text-sm rounded-lg border border-slate-700 bg-slate-900/70 p-3 text-slate-200"
        : "text-sm rounded-lg border border-violet-800 bg-violet-950/40 p-3 text-violet-100";

      const lines = [
        job.progress_message || `Status: ${job.status}`,
        `${job.progress_current || 0} / ${job.progress_total || 0} targets processed`,
      ];
      (job.targets || []).forEach((target) => {
        lines.push(`• ${target.target_name}: ${target.status}${target.message ? ` — ${target.message}` : ""}`);
      });
      if (job.error_message) lines.push(job.error_message);
      statusEl.textContent = lines.join("\n");
    }

    function renderSyncBanner(status) {
      const banner = document.getElementById("remediation-sync-banner");
      if (!banner || !status) return;
      if (status.synced) {
        banner.classList.add("hidden");
        return;
      }
      banner.classList.remove("hidden");
      banner.innerHTML = `
        <strong>Remediation scripts not loaded locally.</strong>
        Per-control PowerCLI snippets come from the mounted profile repo at
        <code class="text-amber-100">${escapeHtml(status.powercli_dir || "powercli/")}</code>.
        ${escapeHtml(status.setup_hint || "Run setup-stig-profiles.sh")}, then
        <code class="text-amber-100">docker compose restart web worker</code>.
      `;
    }

    async function load() {
      try {
        const resp = await fetch(apiUrl(`/api/scans/${jobId}/results/${resultId}/checklist`));
        if (!resp.ok) throw new Error(await resp.text());
        const data = await resp.json();
        checklistMeta = data;
        items = data.items || [];
        filtered = items.slice();
        loading?.classList.add("hidden");
        app?.classList.remove("hidden");
        renderCounts(data);
        renderSyncBanner(data.remediation_status);

        const jsonLink = document.getElementById("checklist-json-link");
        const cklLink = document.getElementById("checklist-ckl-link");
        if (jsonLink && data.has_json) {
          jsonLink.href = `/api/scans/${jobId}/results/${resultId}/download/json`;
          jsonLink.classList.remove("hidden");
        }
        if (cklLink && data.has_ckl) {
          cklLink.href = `/api/scans/${jobId}/results/${resultId}/download/ckl`;
          cklLink.classList.remove("hidden");
        }

        document.querySelectorAll(".checklist-filter").forEach((btn) => {
          btn.addEventListener("click", () => {
            activeFilter = btn.dataset.filter || "all";
            document.querySelectorAll(".checklist-filter").forEach((b) => {
              b.classList.remove("bg-emerald-900/50", "text-emerald-300");
              b.classList.add("border", "border-slate-700");
            });
            btn.classList.add("bg-emerald-900/50", "text-emerald-300");
            btn.classList.remove("border");
            applyFilters();
          });
        });

        searchEl?.addEventListener("input", applyFilters);

        document.getElementById("detail-remediate-btn")?.addEventListener("click", async () => {
          const item = filtered[selectedIndex];
          if (!item) return;
          try {
            await startRemediation(item);
          } catch (err) {
            alert(`Remediation failed to start: ${err.message}`);
            const btn = document.getElementById("detail-remediate-btn");
            if (btn) btn.disabled = false;
          }
        });

        document.getElementById("detail-remediate-variables-reset")?.addEventListener("click", () => {
          const textarea = document.getElementById("detail-remediate-variables");
          if (textarea && variablesPreviewDefault) {
            textarea.value = variablesPreviewDefault;
          }
        });

        applyFilters();
      } catch (err) {
        if (loading) {
          loading.textContent = `Could not load checklist: ${err.message}`;
          loading.className = "rounded-xl border border-red-800 p-8 text-center text-red-300";
        }
      }
    }

    load();
  };
})();
