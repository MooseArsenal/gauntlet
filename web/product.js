/* Product page: theme toggle only. */
(() => {
  "use strict";
  let t = "light"; try { t = localStorage.getItem("gauntlet-theme") || "light"; } catch (e) { /* noop */ }
  document.documentElement.setAttribute("data-theme", t);
  document.getElementById("btnTheme").addEventListener("click", () => {
    const n = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", n);
    try { localStorage.setItem("gauntlet-theme", n); } catch (e) { /* noop */ }
  });
})();
