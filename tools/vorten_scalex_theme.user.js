// ==UserScript==
// @name         Vorten D8 theme for ScaleX LAN Manager
// @namespace    https://gitlab.vorten.ru/infra
// @version      1.1
// @description  Adds a "Vorten D8" entry to the ScaleX interface-style picker (Оформление) and recolors the web UI with it: graphite surfaces, red accent, monospace font, square corners. Client-side only, the server is untouched.
// @match        https://192.168.0.118:8443/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

// Palette source: infra/proxmox-theme (colors.map, vorten-extra.css) and infra/authentik (vorten.css).
// Works by fetching every same-origin stylesheet, swapping the ScaleX baseline colors for Vorten ones
// and inlining the result. Hard-coded rgba(232,255,101,...) lime tints in styles.css make a plain
// :root variable override insufficient, hence the rewrite.
// The choice lives in localStorage "vorten.theme" ("off" = disabled, anything else = on, the default).
// To use it on another ScaleX host, add another @match line.
(() => {
  "use strict";

  const KEY = "vorten.theme";
  const STYLE_KEY = "scalex.appearance.style";  // ScaleX's own style picker value
  const OPTION_VALUE = "vorten";

  const readEnabled = () => {
    try { return localStorage.getItem(KEY) !== "off"; } catch { return true; }
  };
  const store = (key, value) => {
    try { localStorage.setItem(key, value); } catch { /* storage is optional */ }
  };
  const enabled = readEnabled();

  const COLOR_MAP = [
    [/rgba\(\s*232\s*,\s*255\s*,\s*101/gi, "rgba(255,77,77"],  // accent tints
    [/#e8ff65/gi, "#ff4d4d"],  // accent
    [/#12140c/gi, "#140a0a"],  // text on accent
    [/#242a0a/gi, "#2a1010"],  // accent-dark
    [/#dce9a4/gi, "#ffb0b0"],  // light accent text
    [/#202622/gi, "#141415"],  // body gradient highlight
    [/#111315/gi, "#0b0b0c"],  // bg
    [/#1a1d20/gi, "#141415"],  // panel
    [/#22262a/gi, "#1c1c1e"],  // panel-2
    [/#31363b/gi, "#2c2c2e"],  // line
    [/#15181a/gi, "#141415"],  // printer cards
    [/#111416/gi, "#0b0b0c"],  // inputs
    [/#25292c/gi, "#26262a"],  // disabled primary button
    [/#f4f1ea/gi, "#ececec"],  // text
    [/#999f9f/gi, "#8e8e93"],  // muted
  ];

  const EXTRA_CSS = `
:root {
  --vt-font: "Space Mono", "JetBrains Mono", ui-monospace, "Cascadia Mono", Consolas, monospace;
  --bg: #0b0b0c; --panel: #141415; --panel-2: #1c1c1e; --line: #2c2c2e;
  --text: #ececec; --muted: #8e8e93; --accent: #ff4d4d; --accent-dark: #2a1010;
}
body, button, input, select, textarea { font-family: var(--vt-font) !important; }
button, .button-link, input, select, textarea, dialog, [class*="card"], [class*="panel"] { border-radius: 2px !important; }`;

  const recolor = css => COLOR_MAP.reduce((out, [from, to]) => out.replace(from, to), css);

  async function applyTheme() {
    const links = [...document.querySelectorAll('link[rel="stylesheet"]')]
      .filter(link => new URL(link.href, location.href).origin === location.origin);
    await Promise.all(links.map(async link => {
      try {
        const css = await (await fetch(link.href)).text();
        const style = document.createElement("style");
        style.dataset.vorten = link.getAttribute("href");
        style.textContent = recolor(css);
        link.replaceWith(style);
      } catch { /* leave the original stylesheet in place */ }
    }));
    const extra = document.createElement("style");
    extra.dataset.vorten = "extra";
    extra.textContent = EXTRA_CSS;
    document.head.appendChild(extra);
  }

  // "Vorten D8" entry in the Оформление dialog. appearance.js only knows baseline/industrial, so the
  // capture-phase listener keeps the "vorten" value away from it. Switching either way reloads the
  // page: that is the simplest way to put the original stylesheets back or take them out.
  function addPickerOption() {
    const select = document.querySelector("#appearance-style");
    if (!select) return;
    const option = new Option("Vorten D8", OPTION_VALUE);
    select.appendChild(option);
    if (enabled) select.value = OPTION_VALUE;
    select.addEventListener("change", event => {
      if (select.value === OPTION_VALUE) {
        event.stopImmediatePropagation();
        store(KEY, "on");
        store(STYLE_KEY, "baseline");
      } else {
        store(KEY, "off");  // appearance.js (next listener) saves the chosen style itself
      }
      setTimeout(() => location.reload(), 50);
    }, true);
  }

  let veil = null;
  if (enabled) {
    // Vorten maps onto the "baseline" style only; set before appearance-init.js reads it.
    store(STYLE_KEY, "baseline");
    // Avoid a flash of lime while the stylesheets are being rewritten.
    veil = document.createElement("style");
    veil.textContent = "html{background:#0b0b0c!important}body{visibility:hidden}";
    document.documentElement.appendChild(veil);
  }

  const run = () => {
    addPickerOption();
    if (!enabled) return;
    const done = () => veil.remove();
    applyTheme().then(done, done);
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run, { once: true });
  else run();
})();
