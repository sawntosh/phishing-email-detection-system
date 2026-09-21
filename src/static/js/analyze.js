/* Analyze Email page: drag & drop, client-side validation, examples, upload progress, analysis overlay.
   Progressive enhancement: if anything here fails, the plain HTML forms still submit normally. */
(function () {
  "use strict";
  var MAX_BYTES = 5 * 1024 * 1024, ALLOWED = [".eml", ".txt"];
  var doc = document;
  function $(s) { return doc.querySelector(s); }

  var pasteForm = $("#paste-form"), fileForm = $("#file-form"), textarea = $("#message_text"), input = $("#email_file");
  if (!pasteForm || !fileForm) { return; }
  var dropzone = $("#dropzone"), chip = $("#filechip"), fileSubmit = $("#file-submit"), errBox = $("#form-error");
  var overlay = $("#analysis-overlay"), bar = $("#upload-progress"), sub = $("#overlay-sub"), steps = [].slice.call(doc.querySelectorAll("#steps [data-step]"));
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function showError(msg) { errBox.hidden = false; errBox.querySelector("[data-error-text]").textContent = msg; errBox.scrollIntoView({ block: "nearest" }); }
  function clearError() { errBox.hidden = true; }
  function human(n) { return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB"; }

  /* ---- example emails (static demo text supplied with the page) ---- */
  [].forEach.call(doc.querySelectorAll("[data-example]"), function (btn) {
    btn.addEventListener("click", function () {
      var tpl = $("#example-" + btn.getAttribute("data-example"));
      if (tpl) { textarea.value = tpl.content.textContent.replace(/^\n/, ""); updateCount(); textarea.focus(); clearError(); }
    });
  });
  function updateCount() { var c = $("#char-count"); if (c) { c.textContent = textarea.value.length.toLocaleString(); } }
  textarea.addEventListener("input", updateCount); updateCount();

  /* ---- file selection + validation ---- */
  function validateFile(file) {
    if (!file) { return "Choose an email file first."; }
    var name = file.name.toLowerCase(), ext = name.indexOf(".") > -1 ? name.slice(name.lastIndexOf(".")) : "";
    if (ext === ".msg") { return "Outlook .msg files are not supported yet. Export the message as .eml and upload that."; }
    if (ALLOWED.indexOf(ext) === -1) { return "Unsupported file type" + (ext ? " (" + ext + ")" : "") + ". Upload an .eml or .txt file."; }
    if (file.size === 0) { return "That file is empty."; }
    if (file.size > MAX_BYTES) { return "That file is " + human(file.size) + ". The limit is 5 MB."; }
    return null;
  }
  function refreshFile() {
    var file = input.files && input.files[0];
    if (!file) { chip.hidden = true; fileSubmit.disabled = true; return; }
    var problem = validateFile(file);
    if (problem) { showError(problem); input.value = ""; chip.hidden = true; fileSubmit.disabled = true; return; }
    clearError();
    $("#filename").textContent = file.name; $("#filesize").textContent = human(file.size);
    chip.hidden = false; fileSubmit.disabled = false;
  }
  input.addEventListener("change", refreshFile);
  $("#clear-file").addEventListener("click", function () { input.value = ""; refreshFile(); });

  ["dragenter", "dragover"].forEach(function (ev) {
    dropzone.addEventListener(ev, function (e) { e.preventDefault(); dropzone.classList.add("is-over"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    dropzone.addEventListener(ev, function (e) { e.preventDefault(); dropzone.classList.remove("is-over"); });
  });
  dropzone.addEventListener("drop", function (e) {
    var files = e.dataTransfer && e.dataTransfer.files;
    if (!files || !files.length) { return; }
    if (files.length > 1) { showError("Please drop one file at a time."); return; }
    try { input.files = files; } catch (err) { showError("Your browser could not accept the dropped file. Use the browse option instead."); return; }
    refreshFile();
  });
  dropzone.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });

  /* ---- analysis overlay ---- */
  var timers = [];
  function setStep(n) {
    steps.forEach(function (li, i) { li.classList.toggle("is-done", i < n); li.classList.toggle("is-active", i === n); });
  }
  function openOverlay() {
    overlay.classList.add("is-open"); doc.body.style.overflow = "hidden"; setStep(0); setProgress(0);
  }
  function closeOverlay() {
    overlay.classList.remove("is-open"); doc.body.style.overflow = ""; timers.forEach(clearTimeout); timers = [];
    [].forEach.call(doc.querySelectorAll("[data-submit]"), function (b) { b.removeAttribute("aria-busy"); });
    refreshFile();
  }
  function setProgress(p) {
    bar.setAttribute("aria-valuenow", String(Math.round(p))); bar.firstElementChild.style.setProperty("--w", p + "%");
  }
  function advanceStagesWhileWaiting() {
    // The server answers in a fraction of a second; the stages illustrate the order in which the checks run.
    var i = 1;
    (function next() { if (i < steps.length) { setStep(i); i += 1; timers.push(setTimeout(next, reduce ? 0 : 380)); } })();
  }
  function finishAll(then) { setStep(steps.length); sub.textContent = "Analysis complete"; timers.push(setTimeout(then, reduce ? 0 : 260)); }

  /* ---- submit via XHR for real upload progress; fall back to a normal submit on any problem ---- */
  function submitWithProgress(form) {
    var xhr = new XMLHttpRequest();
    xhr.open("POST", form.action);
    xhr.upload.onprogress = function (e) {
      if (e.lengthComputable) { setProgress((e.loaded / e.total) * 100); sub.textContent = e.loaded < e.total ? "Uploading… " + human(e.loaded) + " of " + human(e.total) : "Upload complete"; }
    };
    xhr.upload.onload = function () { setProgress(100); sub.textContent = "Running the analysis engine"; advanceStagesWhileWaiting(); };
    xhr.onerror = function () { closeOverlay(); showError("The connection was interrupted before the email could be analysed. Please try again."); };
    xhr.ontimeout = xhr.onerror; xhr.timeout = 120000;
    xhr.onload = function () {
      var landed = xhr.responseURL || "";
      if (/\/result\/\d+/.test(landed)) { finishAll(function () { window.location.href = landed; }); return; }
      // Rejected by a validation or Zero-Trust gate (or too large): show the page the server rendered, with its message.
      closeOverlay(); doc.open(); doc.write(xhr.responseText); doc.close();
    };
    xhr.send(new FormData(form));
  }
  function handleSubmit(form, e, problem) {
    clearError();
    if (problem) { e.preventDefault(); showError(problem); return; }
    if (!window.XMLHttpRequest || !window.FormData) { return; }  // legacy browser: normal submit
    e.preventDefault();
    try { openOverlay(); form.querySelector("[data-submit]").setAttribute("aria-busy", "true"); submitWithProgress(form); }
    catch (err) { closeOverlay(); form.submit(); }
  }
  pasteForm.addEventListener("submit", function (e) {
    var text = textarea.value.trim();
    handleSubmit(pasteForm, e, text ? null : "Paste the email text first, or upload a file below.");
  });
  fileForm.addEventListener("submit", function (e) {
    handleSubmit(fileForm, e, validateFile(input.files && input.files[0]));
  });
  doc.addEventListener("keydown", function (e) { if (e.key === "Escape" && overlay.classList.contains("is-open")) { e.preventDefault(); } });
})();
