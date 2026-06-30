(function () {
  const palette = {
    open: "#f87171",
    nr: "#fbbf24",
    na: "#94a3b8",
    nf: "#34d399",
  };

  function shortTitle(title) {
    const prefix = "VMware Cloud Foundation 9.x ";
    if (title.startsWith(prefix)) {
      return title.slice(prefix.length);
    }
    return title.length > 42 ? `${title.slice(0, 39)}…` : title;
  }

  function initDashboardCharts(payload) {
    if (!payload || !window.Chart) return;

    const totals = payload.totals || {};
    const totalControls = (totals.open || 0) + (totals.nr || 0) + (totals.na || 0) + (totals.nf || 0);
    const reviewed = (totals.open || 0) + (totals.nr || 0) + (totals.nf || 0);
    const compliancePct = reviewed > 0 ? Math.round(((totals.nf || 0) / reviewed) * 100) : 0;

    const gaugeEl = document.getElementById("dashboard-compliance-gauge");
    const gaugeValueEl = document.getElementById("dashboard-compliance-value");
    if (gaugeEl && gaugeValueEl) {
      gaugeValueEl.textContent = `${compliancePct}%`;
      new Chart(gaugeEl, {
        type: "doughnut",
        data: {
          labels: ["Not a finding", "Remaining"],
          datasets: [
            {
              data: [compliancePct, Math.max(0, 100 - compliancePct)],
              backgroundColor: [palette.nf, "#1e293b"],
              borderWidth: 0,
              circumference: 180,
              rotation: 270,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: "72%",
          plugins: {
            legend: { display: false },
            tooltip: { enabled: false },
          },
        },
      });
    }

    const statusEl = document.getElementById("dashboard-status-chart");
    if (statusEl && totalControls > 0) {
      new Chart(statusEl, {
        type: "doughnut",
        data: {
          labels: ["Open", "Not reviewed", "Not applicable", "Not a finding"],
          datasets: [
            {
              data: [totals.open || 0, totals.nr || 0, totals.na || 0, totals.nf || 0],
              backgroundColor: [palette.open, palette.nr, palette.na, palette.nf],
              borderColor: "#0f172a",
              borderWidth: 2,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: "bottom",
              labels: { color: "#cbd5e1", boxWidth: 12, padding: 14 },
            },
          },
        },
      });
    }

    const checklistEl = document.getElementById("dashboard-checklist-chart");
    const checklists = payload.checklists || [];
    if (checklistEl && checklists.length > 0) {
      new Chart(checklistEl, {
        type: "bar",
        data: {
          labels: checklists.map((row) => shortTitle(row.title)),
          datasets: [
            {
              label: "Open",
              data: checklists.map((row) => row.counts.open || 0),
              backgroundColor: palette.open,
              stack: "status",
            },
            {
              label: "Not reviewed",
              data: checklists.map((row) => row.counts.nr || 0),
              backgroundColor: palette.nr,
              stack: "status",
            },
            {
              label: "Not applicable",
              data: checklists.map((row) => row.counts.na || 0),
              backgroundColor: palette.na,
              stack: "status",
            },
            {
              label: "Not a finding",
              data: checklists.map((row) => row.counts.nf || 0),
              backgroundColor: palette.nf,
              stack: "status",
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: "y",
          scales: {
            x: {
              stacked: true,
              ticks: { color: "#94a3b8" },
              grid: { color: "#1e293b" },
            },
            y: {
              stacked: true,
              ticks: { color: "#cbd5e1", autoSkip: false },
              grid: { display: false },
            },
          },
          plugins: {
            legend: {
              position: "bottom",
              labels: { color: "#cbd5e1", boxWidth: 12, padding: 14 },
            },
            tooltip: {
              callbacks: {
                title(items) {
                  const idx = items[0]?.dataIndex ?? 0;
                  return checklists[idx]?.title || items[0]?.label || "";
                },
              },
            },
          },
        },
      });
    }
  }

  window.initDashboardCharts = initDashboardCharts;
})();
