(function () {
  const TYPE_LABELS = {
    vcenter: "vCenter",
    cluster: "Cluster",
    host: "ESXi Host",
    vm: "Virtual Machine",
  };

  function collectSelections(root) {
    const data = {
      scan_vcenter_product: false,
      scan_vcenter_appliance: false,
      esxi_hosts: [],
      vms: [],
    };

    root.querySelectorAll('input[data-target="vcenter_product"]:checked').forEach(() => {
      data.scan_vcenter_product = true;
    });
    root.querySelectorAll('input[data-target="vcenter_appliance"]:checked').forEach(() => {
      data.scan_vcenter_appliance = true;
    });
    root.querySelectorAll('input[data-target="host"]:checked').forEach((el) => {
      if (el.dataset.name) data.esxi_hosts.push(el.dataset.name);
    });
    root.querySelectorAll('input[data-target="vm"]:checked').forEach((el) => {
      if (el.dataset.name) data.vms.push(el.dataset.name);
    });
    return data;
  }

  function syncLegacyCheckboxes(form, data) {
    const esxi = form.querySelector('input[name="scan_esxi"]');
    const vms = form.querySelector('input[name="scan_vms"]');
    const product = form.querySelector('input[name="scan_vcenter_product"]');
    const appliance = form.querySelector('input[name="scan_vcenter_appliance"]');
    if (esxi) esxi.checked = data.esxi_hosts.length > 0;
    if (vms) vms.checked = data.vms.length > 0;
    if (product) product.checked = data.scan_vcenter_product;
    if (appliance) appliance.checked = data.scan_vcenter_appliance;
  }

  function formPayload(form, hiddenValue) {
    const val = (name) => {
      const el = form.querySelector(`[name="${name}"]`);
      if (!el) return "";
      if (el.type === "checkbox") return el.checked;
      return el.value;
    };
    return {
      vcenter_id: parseInt(val("vcenter_id"), 10),
      selected_targets_json: hiddenValue || "",
      scan_esxi: val("scan_esxi") === true,
      scan_vms: val("scan_vms") === true,
      scan_vcenter_product: val("scan_vcenter_product") === true,
      scan_vcenter_appliance: val("scan_vcenter_appliance") === true,
      esxi_scope: val("esxi_scope") || "all_hosts",
      esxi_cluster: val("esxi_cluster") || "",
      esxi_host: val("esxi_host") || "",
    };
  }

  function escapeHtml(text) {
    const d = document.createElement("div");
    d.textContent = text ?? "";
    return d.innerHTML;
  }

  function escapeAttr(text) {
    return String(text).replace(/"/g, "&quot;");
  }

  function renderStigPreview(preview, els) {
    const { summary, steps, guides, guidesWrap } = els;
    if (!summary || !steps) return;

    if (preview.empty) {
      summary.textContent = "No scan targets selected — check items in the inventory tree above.";
      summary.className = "text-sm text-amber-300";
      steps.innerHTML = "";
      if (guidesWrap) guidesWrap.classList.add("hidden");
      return;
    }

    summary.textContent = `${preview.step_count} audit step${preview.step_count === 1 ? "" : "s"} will run. Each step produces a separate result and CKL file.`;
    summary.className = "text-sm text-slate-300";

    steps.innerHTML = preview.steps
      .map((step, i) => {
        const est = step.estimated
          ? '<span class="text-amber-400/80 text-xs ml-1">(count at scan time)</span>'
          : "";
        const guideList = step.guides.map((g) => `<li class="text-slate-500">${escapeHtml(g)}</li>`).join("");
        return `
          <div class="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2 text-sm">
            <div class="flex flex-wrap items-baseline gap-x-2 gap-y-1">
              <span class="text-slate-500 font-mono text-xs">${i + 1}.</span>
              <span class="font-medium text-slate-200">${escapeHtml(step.target)}</span>${est}
              <span class="text-slate-500 text-xs">· ${escapeHtml(step.type)} · ${escapeHtml(step.transport)}</span>
            </div>
            <div class="text-xs text-slate-600 mt-1 font-mono">${escapeHtml(step.profile)}</div>
            <ul class="mt-1 ml-4 list-disc text-xs">${guideList}</ul>
          </div>`;
      })
      .join("");

    if (guides && guidesWrap) {
      if (preview.guides.length) {
        guidesWrap.classList.remove("hidden");
        guides.innerHTML = preview.guides
          .map((g) => {
            const count =
              g.audit_count > 1
                ? `<span class="text-slate-500 ml-1">× ${g.audit_count} audits</span>`
                : "";
            return `<li class="text-slate-300">${escapeHtml(g.title)}${count}</li>`;
          })
          .join("");
      } else {
        guidesWrap.classList.add("hidden");
      }
    }
  }

  function renderNode(node, depth) {
    const wrap = document.createElement("div");
    wrap.className = "inventory-node";
    wrap.style.marginLeft = depth ? `${depth * 1.25}rem` : "0";

    const row = document.createElement("div");
    row.className = "flex items-center gap-2 py-1 text-sm";

    if (node.type === "vcenter") {
      row.innerHTML = `
        <span class="font-medium text-emerald-300">${escapeHtml(node.name)}</span>
        <span class="text-slate-500 text-xs">(${TYPE_LABELS.vcenter})</span>
      `;
      wrap.appendChild(row);

      const extras = document.createElement("div");
      extras.className = "ml-4 space-y-1 mb-2";
      extras.innerHTML = `
        <label class="flex items-center gap-2 text-sm">
          <input type="checkbox" data-target="vcenter_product" class="inv-check rounded" checked>
          <span>Scan vCenter product controls</span>
        </label>
        <label class="flex items-center gap-2 text-sm">
          <input type="checkbox" data-target="vcenter_appliance" class="inv-check rounded">
          <span>Scan vCenter appliance (VCSA via SSH)</span>
        </label>
      `;
      wrap.appendChild(extras);
    } else if (node.type === "cluster") {
      row.innerHTML = `
        <span class="text-slate-300">${escapeHtml(node.name)}</span>
        <span class="text-slate-500 text-xs">(${TYPE_LABELS.cluster})</span>
      `;
      wrap.appendChild(row);
    } else if (node.type === "host") {
      row.innerHTML = `
        <input type="checkbox" data-target="host" data-name="${escapeAttr(node.name)}" class="inv-check rounded" checked>
        <span class="text-slate-200">${escapeHtml(node.name)}</span>
        <span class="text-slate-500 text-xs">(${TYPE_LABELS.host})</span>
      `;
      wrap.appendChild(row);
    } else if (node.type === "vm") {
      row.innerHTML = `
        <input type="checkbox" data-target="vm" data-name="${escapeAttr(node.name)}" class="inv-check rounded" checked>
        <span class="text-slate-300">${escapeHtml(node.name)}</span>
        <span class="text-slate-500 text-xs">(${TYPE_LABELS.vm})</span>
      `;
      wrap.appendChild(row);
    }

    (node.children || []).forEach((child) => {
      wrap.appendChild(renderNode(child, depth + 1));
    });
    return wrap;
  }

  function setAllChecks(root, checked) {
    root.querySelectorAll(".inv-check").forEach((el) => {
      el.checked = checked;
    });
  }

  window.initInventoryTree = function (options) {
    const select = document.getElementById(options.vcenterSelectId);
    const panel = document.getElementById(options.panelId);
    const status = document.getElementById(options.statusId);
    const hidden = document.getElementById(options.hiddenInputId);
    const form = document.getElementById(options.formId);
    const selectAllBtn = document.getElementById(options.selectAllId);
    const deselectAllBtn = document.getElementById(options.deselectAllId);
    const previewEls = {
      summary: document.getElementById(options.previewSummaryId),
      steps: document.getElementById(options.previewStepsId),
      guides: document.getElementById(options.previewGuidesId),
      guidesWrap: document.getElementById(options.previewGuidesWrapId),
    };

    if (!select || !panel || !form) return;

    let loadToken = 0;
    let previewToken = 0;
    let previewTimer = null;

    async function refreshStigPreview() {
      const token = ++previewToken;
      const hiddenValue = hidden ? hidden.value : "";
      try {
        const resp = await fetch(apiUrl("/api/scans/stig-preview"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(formPayload(form, hiddenValue)),
        });
        if (token !== previewToken) return;
        if (!resp.ok) return;
        const preview = await resp.json();
        renderStigPreview(preview, previewEls);
      } catch (_) {
        /* ignore transient errors */
      }
    }

    function schedulePreview() {
      if (previewTimer) clearTimeout(previewTimer);
      previewTimer = setTimeout(refreshStigPreview, 150);
    }

    function updateHidden() {
      const data = collectSelections(panel);
      if (hidden) hidden.value = JSON.stringify(data);
      syncLegacyCheckboxes(form, data);
      schedulePreview();
    }

    async function loadInventory(vcenterId) {
      const token = ++loadToken;
      panel.innerHTML = "";
      if (status) {
        status.textContent = "Loading inventory from vCenter (this may take a minute)...";
        status.className = "text-sm text-amber-300 mb-3";
      }

      try {
        const resp = await fetch(apiUrl(`/api/vcenters/${vcenterId}/inventory`));
        if (token !== loadToken) return;
        if (!resp.ok) {
          const err = await resp.text();
          throw new Error(err || resp.statusText);
        }
        const tree = await resp.json();
        if (tree.demo) {
          if (status) {
            status.textContent =
              "Demo inventory (DRY_RUN mode) — not your real vCenter. Set DRY_RUN=false in .env to load live data.";
            status.className = "text-sm text-amber-300 mb-3";
          }
        }
        panel.appendChild(renderNode(tree, 0));
        panel.querySelectorAll(".inv-check").forEach((el) => {
          el.addEventListener("change", updateHidden);
        });
        updateHidden();
        if (status && !tree.demo) {
          status.textContent = "Select the hosts and VMs to include in this scan.";
          status.className = "text-sm text-slate-400 mb-3";
        }
      } catch (err) {
        if (token !== loadToken) return;
        if (hidden) hidden.value = "";
        if (status) {
          status.textContent = `Could not load inventory: ${err.message}. You can still use the checkboxes below.`;
          status.className = "text-sm text-red-300 mb-3";
        }
        schedulePreview();
      }
    }

    select.addEventListener("change", () => {
      loadInventory(select.value);
    });

    if (selectAllBtn) {
      selectAllBtn.addEventListener("click", (e) => {
        e.preventDefault();
        setAllChecks(panel, true);
        updateHidden();
      });
    }
    if (deselectAllBtn) {
      deselectAllBtn.addEventListener("click", (e) => {
        e.preventDefault();
        setAllChecks(panel, false);
        updateHidden();
      });
    }

    form.querySelectorAll(
      'input[name="scan_esxi"], input[name="scan_vms"], input[name="scan_vcenter_product"], input[name="scan_vcenter_appliance"], input[name="esxi_scope"], input[name="esxi_cluster"], input[name="esxi_host"]'
    ).forEach((el) => {
      el.addEventListener("change", schedulePreview);
      el.addEventListener("input", schedulePreview);
    });

    form.addEventListener("submit", () => updateHidden());
    loadInventory(select.value);
  };
})();
