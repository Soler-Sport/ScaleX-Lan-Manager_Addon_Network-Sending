// ==UserScript==
// @name         Vorten D8 theme for ScaleX LAN Manager
// @namespace    https://gitlab.vorten.ru/infra
// @version      1.0
// @description  Recolors the ScaleX LAN Manager web UI (baseline style) with the Vorten D8 palette: graphite surfaces, red accent, monospace font, square corners. Client-side only, the server is untouched.
// @match        https://192.168.0.118:8443/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

// Palette source: infra/proxmox-theme (colors.map, vorten-extra.css) and infra/authentik (vorten.css).
// Works by fetching every same-origin stylesheet, swapping the ScaleX baseline colors for Vorten ones
// and inlining the result. Hard-coded rgba(232,255,101,...) lime tints in styles.css make a plain
// :root variable override insufficient, hence the rewrite.
// To use it on another ScaleX host, add another @match line.
(() => {
  "use strict";

  // Forced before appearance-init.js runs: the Vorten palette maps onto the "baseline" style only.
  try { localStorage.setItem("scalex.appearance.style", "baseline"); } catch { /* storage is optional */ }

  // Avoid a flash of lime while the stylesheets are being rewritten.
  const veil = document.createElement("style");
  veil.textContent = "html{background:#0b0b0c!important}body{visibility:hidden}";
  document.documentElement.appendChild(veil);

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

  async function apply() {
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

  const done = () => veil.remove();
  const run = () => apply().then(done, done);
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run, { once: true });
  else run();
})();
