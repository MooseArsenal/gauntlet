/* White-label (L2): apply the organisation's branding to any page. The page's
 * own sub-label (Console, Run day, Members…) stays; the name, accent and logo
 * change. The safety line in the banner strip is never rebranded. */
(() => {
  "use strict";
  function token() { try { return localStorage.getItem("gauntlet-token") || ""; } catch (e) { return ""; } }
  async function apply() {
    let b;
    try {
      const t = token();
      const res = await fetch("/api/branding", { headers: t ? { Authorization: `Bearer ${t}` } : {} });
      if (!res.ok) return;
      b = await res.json();
    } catch (e) { return; }
    if (!b || !b.custom) return;
    document.querySelectorAll(".brand b").forEach((el) => { el.textContent = b.name; });
    if (b.accent) {
      document.documentElement.style.setProperty("--accent2", b.accent);
      document.documentElement.style.setProperty("--crit", b.accent);
    }
    if (b.logo) {
      document.querySelectorAll(".brand .mark").forEach((el) => {
        el.innerHTML = ""; const img = document.createElement("img"); img.src = b.logo; img.alt = b.name; img.className = "brand-logo"; el.appendChild(img); el.style.display = "inline-flex";
      });
    }
    if (b.tagline) document.querySelectorAll(".strip span:first-child").forEach((el) => { el.textContent = el.textContent.replace(/^Exercise control/i, b.tagline); });
    if (document.title.startsWith("Gauntlet")) document.title = document.title.replace(/^Gauntlet/, b.name);
    // partner mode: show where you are acting
    let partner = ""; try { partner = localStorage.getItem("gauntlet-partner-token") || ""; } catch (e) { /* noop */ }
    if (partner && !document.getElementById("partnerBar")) {
      const bar = document.createElement("div"); bar.id = "partnerBar"; bar.className = "partner-bar";
      bar.innerHTML = `<span>Acting for <b>${b.name}</b> via your partner account.</span><button class="btn ghost small" id="btnPartnerReturn">Return to partner console</button>`;
      document.body.insertBefore(bar, document.body.firstChild.nextSibling);
      document.getElementById("btnPartnerReturn").addEventListener("click", () => {
        try { localStorage.setItem("gauntlet-token", partner); localStorage.removeItem("gauntlet-partner-token"); localStorage.removeItem("gauntlet-refresh"); } catch (e) { /* noop */ }
        location.href = "/partner.html";
      });
    }
  }
  window.GauntletBrand = { apply };
  document.addEventListener("DOMContentLoaded", apply);
})();
