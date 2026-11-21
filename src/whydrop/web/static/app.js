// Shell: top bar, hash router, theme/language, the live connection (spec §8, UI design doc §3).
import { api, dur, h, isPublic, lang, loadLang, prefsGet, prefsSet, t, token } from "./lib.js";

const routes = [
  { re: /^#?\/?$/, page: () => import("./pages/now.js"), nav: "now" },
  { re: /^#\/drops(\?.*)?$/, page: () => import("./pages/drops.js"), nav: "drops" },
  { re: /^#\/drop\/(\d+)$/, page: () => import("./pages/drop.js"), nav: "drops" },
  { re: /^#\/nat$/, page: () => import("./pages/nat.js"), nav: "nat" },
  { re: /^#\/protocol$/, page: () => import("./pages/protocol.js"), nav: "protocol" },
  { re: /^#\/network$/, page: () => import("./pages/network.js"), nav: "network" },
];
const NAV = [["now", "#/"], ["drops", "#/drops"], ["nat", "#/nat"], ["protocol", "#/protocol"], ["network", "#/network"]];

export const live = { listeners: new Set(), status: null, connected: false };
let current = null;

function applyTheme(mode) {
  if (mode === "light" || mode === "dark") document.documentElement.dataset.theme = mode;
  else delete document.documentElement.dataset.theme;
}

function topBar(active) {
  const theme = prefsGet("whydrop.theme") || "system";
  const next = { system: "light", light: "dark", dark: "system" };
  const st = live.status;
  const rec = st && st.since_ms ? t("top.recording", { dur: dur((Date.now() - st.since_ms) / 1000) })
    : st && st.since_s != null ? t("top.recording", { dur: dur(-st.since_s) }) : t("top.not_recording");
  return h("header", {},
    h("div", { class: "top" },
      h("div", { class: "brand" }, "whydrop", st?.agent && !isPublic ? h("small", {}, st.agent) : null),
      h("nav", { class: "nav", "aria-label": "Main" },
        NAV.map(([k, href]) => h("a", { href, "aria-current": k === active ? "page" : null }, t(`nav.${k}`)))),
      h("div", { class: "top-right" },
        h("span", { class: "rec" + (st ? "" : " off"), "aria-live": "polite" }, rec),
        h("button", { class: "switch", type: "button", onclick: async () => { await loadLang(lang === "ko" ? "en" : "ko"); render(); } },
          t("top.lang")),
        h("button", { class: "switch", type: "button", onclick: () => { const m = next[theme]; prefsSet("whydrop.theme", m); applyTheme(m); render(); } },
          t(`top.theme.${theme}`)))));
}

let wsBanner = null;
function setBanner(text) {
  wsBanner?.remove();
  wsBanner = text ? h("div", { class: "banner", role: "status" }, text) : null;
  if (wsBanner) document.getElementById("app").prepend(wsBanner);
}

function connect(attempt = 0) {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const protos = token() ? ["whydrop", token()] : ["whydrop"];
  const ws = new WebSocket(`${proto}//${location.host}/ws${isPublic ? "?public=1" : ""}`, protos);
  ws.onopen = () => {
    if (attempt > 0) { setBanner(t("banner.ws_back")); setTimeout(() => setBanner(null), 2000); }
    live.connected = true;
    attempt = 0;
  };
  ws.onmessage = (e) => { const msg = JSON.parse(e.data); for (const fn of live.listeners) fn(msg); };
  ws.onclose = () => {
    if (live.connected) setBanner(t("banner.ws_lost"));
    live.connected = false;
    setTimeout(() => connect(attempt + 1), Math.min(30000, 1000 * 2 ** attempt));
  };
}

export async function refreshStatus() {
  try { live.status = await api("/api/status"); } catch { live.status = null; }
  return live.status;
}

async function render() {
  const hash = location.hash || "#/";
  const route = routes.find(r => r.re.test(hash)) || routes[0];
  const m = hash.match(route.re);
  current?.leave?.();
  const app = document.getElementById("app");
  const head = document.getElementById("head");
  head.replaceChildren(topBar(route.nav));
  const mod = await route.page();
  const main = h("main", { id: "main", tabindex: "-1" });
  app.replaceChildren(main);
  if (isPublic) app.append(h("div", { class: "publicbadge" }, t("badge.public")));
  current = mod;
  await mod.mount(main, { id: m?.[1] && Number(m[1]), refresh: render });
  document.title = `whydrop · ${t(`nav.${route.nav}`)}`;
}

(async () => {
  applyTheme(prefsGet("whydrop.theme") || "system");
  await loadLang(lang);
  await refreshStatus();
  window.addEventListener("hashchange", render);
  await render();
  connect();
  setInterval(async () => { await refreshStatus(); document.getElementById("head").replaceChildren(topBar(
    (routes.find(r => r.re.test(location.hash || "#/")) || routes[0]).nav)); }, 15000);
})();
