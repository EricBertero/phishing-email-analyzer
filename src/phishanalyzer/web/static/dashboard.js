// Dashboard behaviour: chart tooltips. No inline scripts (CSP). The theme follows the system
// setting in CSS alone, as the brand asks, so there is nothing to toggle here.
(function () {
  "use strict";

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
