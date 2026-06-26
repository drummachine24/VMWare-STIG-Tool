(function () {
  function statusClass(status) {
    if (status === "completed") return "bg-emerald-900 text-emerald-300";
    if (status === "failed") return "bg-red-900 text-red-300";
    if (status === "cancelled") return "bg-slate-700 text-slate-300";
    if (status === "running") return "bg-amber-900 text-amber-300";
    return "bg-slate-800 text-slate-300";
  }

  function escapeHtml(text) {
    const d = document.createElement("div");
    d.textContent = text ?? "";
    return d.innerHTML;
  }

  function formatResultCounts(r) {
    if (r.count_nf != null || r.count_open != null) {
      return `${r.count_nf || 0} NF / ${r.count_open || 0} Open / ${r.count_nr || 0} NR / ${r.count_na || 0} NA`;
    }
    return `${r.passed || 0} pass / ${r.failed || 0} fail / ${r.skipped || 0} skip`;
  }

  function renderResult(jobId, r) {
    const jsonLink = r.json_path
      ? `<a href="${apiUrl(`/api/scans/${jobId}/results/${r.id}/download/json`)}" class="text-sky-400 hover:underline">JSON</a>`
      : "";
    const cklLink = r.ckl_path
      ? `<a href="${apiUrl(`/api/scans/${jobId}/results/${r.id}/download/ckl`)}" class="text-emerald-400 hover:underline">CKL</a>`
      : "";
    const summary = r.summary
      ? `<pre class="mt-2 text-xs text-slate-300 whitespace-pre-wrap overflow-x-auto rounded-lg bg-slate-950 border border-slate-800 p-3">${escapeHtml(r.summary)}</pre>`
      : "";

    return `
      <div class="rounded-xl border border-slate-800 bg-slate-900/40 p-4" data-result-id="${r.id}">
        <div class="flex flex-wrap items-start justify-between gap-3 mb-2">
          <div>
            <div class="font-medium">${escapeHtml(r.target_name)}</div>
            <div class="text-xs text-slate-500">${escapeHtml(r.target_type)} · ${escapeHtml(r.status)} · ${formatResultCounts(r)}</div>
          </div>
          <div class="space-x-2 text-sm">
            <a href="${pageUrl(`/scans/${jobId}/results/${r.id}`)}" class="text-violet-400 hover:underline">View checklist</a>
            ${jsonLink} ${cklLink}
          </div>
        </div>
        ${summary}
      </div>`;
  }

  window.initScanProgress = function (options) {
    const jobId = options.jobId;
    const active = options.active;
    const statusEl = document.getElementById("scan-status-badge");
    const messageEl = document.getElementById("scan-progress-message");
    const barEl = document.getElementById("scan-progress-bar");
    const labelEl = document.getElementById("scan-progress-label");
    const resultsEl = document.getElementById("scan-results-list");
    const panelEl = document.getElementById("scan-progress-panel");
    const cancelBtn = document.getElementById("scan-cancel-btn");
    const errorEl = document.getElementById("scan-error-message");

    if (!active) return;

    let timer = null;
    let cancelling = false;

    async function poll() {
      try {
        const resp = await fetch(apiUrl(`/api/scans/${jobId}/progress`));
        if (!resp.ok) return;
        const data = await resp.json();

        if (statusEl) {
          statusEl.textContent = data.status;
          statusEl.className = `px-2 py-0.5 rounded text-xs ${statusClass(data.status)}`;
        }
        if (messageEl) messageEl.textContent = data.progress_message || "Working...";
        if (labelEl) {
          const cur = data.progress_current || 0;
          const tot = data.progress_total || 0;
          labelEl.textContent = tot ? `Step ${cur} of ${tot}` : "";
        }
        if (barEl) {
          const pct = data.progress_total
            ? Math.min(100, Math.round((data.progress_current / data.progress_total) * 100))
            : data.status === "running"
              ? 5
              : 0;
          barEl.style.width = `${pct}%`;
        }
        if (errorEl && data.error_message) {
          errorEl.textContent = data.error_message;
          errorEl.classList.remove("hidden");
        }
        if (resultsEl && data.results) {
          if (data.results.length === 0) {
            resultsEl.innerHTML =
              '<div class="rounded-xl border border-slate-800 p-6 text-center text-slate-500">Waiting for first result...</div>';
          } else {
            resultsEl.innerHTML = data.results.map((r) => renderResult(jobId, r)).join("");
          }
        }

        if (["completed", "failed", "cancelled"].includes(data.status)) {
          if (panelEl) panelEl.classList.add("hidden");
          if (cancelBtn) cancelBtn.classList.add("hidden");
          if (timer) clearInterval(timer);
        }
      } catch (_) {
        /* retry on next interval */
      }
    }

    if (cancelBtn) {
      cancelBtn.addEventListener("click", async () => {
        if (cancelling) return;
        if (!confirm("Cancel this scan? The current target may finish before the job stops.")) return;
        cancelling = true;
        cancelBtn.disabled = true;
        cancelBtn.textContent = "Cancelling...";
        try {
          await fetch(apiUrl(`/api/scans/${jobId}/cancel`), { method: "POST" });
          poll();
        } finally {
          cancelling = false;
        }
      });
    }

    poll();
    timer = setInterval(poll, 3000);
  };
})();
