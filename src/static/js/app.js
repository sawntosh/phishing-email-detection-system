/* PhishGuard UI behaviour. Progressive enhancement only: every page works without this file. */
(function () {
  "use strict";
  var doc = document, root = doc.documentElement, body = doc.body;
  function $(sel, ctx) { return (ctx || doc).querySelector(sel); }
  function $$(sel, ctx) { return Array.prototype.slice.call((ctx || doc).querySelectorAll(sel)); }

  /* ---------- theme ---------- */
  function currentTheme() { return root.getAttribute("data-theme") === "light" ? "light" : "dark"; }
  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    try { localStorage.setItem("pg-theme", theme); } catch (e) { /* ignore */ }
    $$("[data-theme-toggle]").forEach(function (btn) {
      btn.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
      btn.setAttribute("aria-label", theme === "dark" ? "Switch to light theme" : "Switch to dark theme");
      btn.setAttribute("title", btn.getAttribute("aria-label"));
    });
  }
  applyTheme(currentTheme());
  doc.addEventListener("click", function (e) {
    var t = e.target.closest("[data-theme-toggle]");
    if (t) { applyTheme(currentTheme() === "dark" ? "light" : "dark"); }
  });

  /* ---------- sidebar (off-canvas on small screens) ---------- */
  function setSidebar(open) {
    body.classList.toggle("sidebar-open", open);
    $$("[data-sidebar-toggle]").forEach(function (b) { b.setAttribute("aria-expanded", open ? "true" : "false"); });
    if (open) { var first = $(".sidebar .nav a"); if (first) { first.focus(); } }
  }
  doc.addEventListener("click", function (e) {
    if (e.target.closest("[data-sidebar-toggle]")) { setSidebar(!body.classList.contains("sidebar-open")); }
    else if (e.target.closest("[data-sidebar-close]") || (e.target.closest(".sidebar .nav a") && body.classList.contains("sidebar-open"))) { setSidebar(false); }
  });
  doc.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      if (body.classList.contains("sidebar-open")) { setSidebar(false); var tg = $("[data-sidebar-toggle]"); if (tg) { tg.focus(); } }
      $$("details.dropdown[open]").forEach(function (d) { d.removeAttribute("open"); });
    }
  });
  doc.addEventListener("click", function (e) {
    $$("details.dropdown[open]").forEach(function (d) { if (!d.contains(e.target)) { d.removeAttribute("open"); } });
  });

  /* ---------- toasts ---------- */
  function dismissToast(toast) {
    toast.classList.add("is-leaving");
    setTimeout(function () { if (toast.parentNode) { toast.parentNode.removeChild(toast); } }, 220);
  }
  $$(".toast").forEach(function (toast) {
    var timer = setTimeout(function () { dismissToast(toast); }, toast.classList.contains("tone-danger") ? 12000 : 7000);
    toast.addEventListener("mouseenter", function () { clearTimeout(timer); });
  });
  doc.addEventListener("click", function (e) {
    var b = e.target.closest("[data-toast-close]");
    if (b) { dismissToast(b.closest(".toast")); }
  });

  /* ---------- confirmation dialog for destructive / sensitive actions ---------- */
  var dialog = $("#confirm-dialog");
  var pending = null;
  function askConfirm(message, title, okLabel, onOk) {
    if (!dialog || typeof dialog.showModal !== "function") { if (window.confirm(message)) { onOk(); } return; }
    $("[data-dialog-title]", dialog).textContent = title || "Please confirm";
    $("[data-dialog-message]", dialog).textContent = message;
    $("[data-dialog-ok]", dialog).textContent = okLabel || "Confirm";
    pending = onOk; dialog.showModal();
  }
  if (dialog) {
    dialog.addEventListener("click", function (e) {
      if (e.target.closest("[data-dialog-ok]")) { var fn = pending; pending = null; dialog.close(); if (fn) { fn(); } }
      else if (e.target.closest("[data-dialog-cancel]") || e.target === dialog) { pending = null; dialog.close(); }
    });
    dialog.addEventListener("cancel", function () { pending = null; });
  }
  doc.addEventListener("submit", function (e) {
    var form = e.target, submitter = e.submitter || null;
    var source = (submitter && submitter.hasAttribute("data-confirm")) ? submitter : (form.hasAttribute("data-confirm") ? form : null);
    if (!source || form.__confirmed) { return; }
    e.preventDefault();
    askConfirm(source.getAttribute("data-confirm"), source.getAttribute("data-confirm-title"), source.getAttribute("data-confirm-ok"), function () {
      form.__confirmed = true;
      if (form.requestSubmit) { form.requestSubmit(submitter || undefined); } else { form.submit(); }
    });
  });

  /* ---------- tabs ---------- */
  $$("[data-tabs]").forEach(function (tabs) {
    var tabEls = $$("[role=tab], .tabs__tab", tabs), panels = $$(".tabs__panel", tabs);
    if (!tabEls.length) { return; }
    function select(i, focus) {
      tabEls.forEach(function (t, n) {
        var on = n === i; t.setAttribute("aria-selected", on ? "true" : "false"); t.tabIndex = on ? 0 : -1;
        if (panels[n]) { panels[n].hidden = !on; }
      });
      if (focus) { tabEls[i].focus(); }
      if (tabEls[i].id && history.replaceState) { history.replaceState(null, "", "#" + tabEls[i].id.replace("tab-", "")); }
    }
    tabEls.forEach(function (t, n) {
      t.setAttribute("role", "tab");
      if (panels[n]) { panels[n].setAttribute("role", "tabpanel"); if (!panels[n].id) { panels[n].id = "panel-" + n; } t.setAttribute("aria-controls", panels[n].id); }
      t.addEventListener("click", function () { select(n, false); });
      t.addEventListener("keydown", function (e) {
        var k = e.key, to = null;
        if (k === "ArrowRight") { to = (n + 1) % tabEls.length; } else if (k === "ArrowLeft") { to = (n - 1 + tabEls.length) % tabEls.length; }
        else if (k === "Home") { to = 0; } else if (k === "End") { to = tabEls.length - 1; }
        if (to !== null) { e.preventDefault(); select(to, true); }
      });
    });
    var start = 0, hash = (location.hash || "").replace("#", "");
    tabEls.forEach(function (t, n) { if (hash && t.id === "tab-" + hash) { start = n; } });
    select(start, false);
  });

  /* ---------- transitions that start once the page is painted ---------- */
  /* Numbers are never animated: the true value is always in the page. Only bars and rings ease in. */
  requestAnimationFrame(function () {
    requestAnimationFrame(function () {
      $$(".ring, .progress").forEach(function (el) { el.classList.add("is-ready"); });
    });
  });

  /* ---------- client-side table filter (audit log, users) ---------- */
  $$("[data-filter-input]").forEach(function (input) {
    var table = $(input.getAttribute("data-filter-input")); if (!table) { return; }
    var rows = $$("tbody tr", table), counter = $(input.getAttribute("data-filter-count") || "#none");
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase(), shown = 0;
      rows.forEach(function (row) { var hit = !q || row.textContent.toLowerCase().indexOf(q) !== -1; row.hidden = !hit; if (hit) { shown++; } });
      if (counter) { counter.textContent = shown + " of " + rows.length + " shown"; }
    });
  });

  /* ---------- copy to clipboard ---------- */
  doc.addEventListener("click", function (e) {
    var b = e.target.closest("[data-copy]"); if (!b || !navigator.clipboard) { return; }
    navigator.clipboard.writeText(b.getAttribute("data-copy")).then(function () {
      var label = b.getAttribute("data-label") || b.textContent; b.textContent = "Copied"; setTimeout(function () { b.textContent = label; }, 1400);
    });
  });
})();
