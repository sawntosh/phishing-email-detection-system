/* Runs in <head> before first paint so the chosen theme never flashes. */
(function () {
  var root = document.documentElement, theme = null;
  try { theme = localStorage.getItem("pg-theme"); } catch (e) { /* storage blocked: fall through */ }
  if (theme !== "light" && theme !== "dark") {
    theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  root.setAttribute("data-theme", theme);
  root.classList.add("js");
})();
