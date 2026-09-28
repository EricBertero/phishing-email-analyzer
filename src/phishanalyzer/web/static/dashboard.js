// Dashboard behaviour: chart tooltips and the theme toggle. No inline scripts (CSP).
(function () {
  "use strict";

  // --- theme toggle (a per-browser convenience; the OS setting is the default) ---
  const root = document.documentElement;
  function stored() {
    try { return localStorage.getItem("theme"); } catch (e) { return null; }
  }
  const saved = stored();
  if (saved === "light" || saved === "dark") root.setAttribute("data-theme", saved);
  const toggle = document.getElementById("theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", function () {
      const dark = root.getAttribute("data-theme") === "dark" ||
        (!root.hasAttribute("data-theme") && window.matchMedia("(prefers-color-scheme: dark)").matches);
      const next = dark ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("theme", next); } catch (e) { /* private mode */ }
    });
  }

  // --- chart tooltip: one readout per day column, on hover and keyboard focus -----
  const wrap = document.querySelector(".chart-wrap");
  if (!wrap) return;
  const tip = wrap.querySelector(".tooltip");
  const groups = JSON.parse(wrap.getAttribute("data-groups") || "[]");

  function show(col) {
    // Built with textContent only: nothing here is ever parsed as HTML.
    tip.replaceChildren();
    const day = document.createElement("div");
    day.className = "t-day";
    day.textContent = col.getAttribute("data-day") + " · " + col.getAttribute("data-total") + " scanned";
    tip.appendChild(day);
    groups.slice().reverse().forEach(function (g) {
      const row = document.createElement("div");
      row.className = "t-row";
      const key = document.createElement("span");
      key.className = "key fill-" + g[0];
      const value = document.createElement("strong");
      value.textContent = col.getAttribute("data-" + g[0]) || "0";
      const label = document.createElement("span");
      label.textContent = g[1];
      row.append(key, value, label);
      tip.appendChild(row);
    });
    tip.hidden = false;
    const box = wrap.getBoundingClientRect();
    const rect = col.getBoundingClientRect();
    let left = rect.left - box.left + rect.width / 2 - tip.offsetWidth / 2;
    left = Math.max(0, Math.min(left, box.width - tip.offsetWidth));
    tip.style.left = left + "px";
    tip.style.top = "0px";
  }
  function hide() { tip.hidden = true; }

  wrap.querySelectorAll(".col").forEach(function (col) {
    col.addEventListener("pointerenter", function () { show(col); });
    col.addEventListener("focus", function () { show(col); });
    col.addEventListener("pointerleave", hide);
    col.addEventListener("blur", hide);
  });
})();
