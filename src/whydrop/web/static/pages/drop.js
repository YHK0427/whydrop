// Drop detail (#/drop/<id>): cause, next step, evidence, copy/export (UI design doc §5.2).
import { lanes, series } from "../components/lanes.js";
import { pathDiagram } from "../components/path.js";
import { strip } from "../components/strip.js";
import { api, dur, errorPanel, h, isPublic, parseIncident, segWord, startMs, t, toast, token, when } from "../lib.js";

const ORDER = ["host_net", "wifi", "lan", "line", "dns"];
const REPO_ISSUES = "https://github.com/YHK0427/whydrop/issues/new";
let cleanup = [];

function frozenPath(d, link) {
  const down = new Set(d.raw.map(s => (s.startsWith("dns") ? "dns" : s === "link" ? "wifi" : s)));
  const first = ORDER.findIndex(s => down.has(s));
  return ORDER.map((k, i) => ({ key: k, label: k === "wifi" && link === "wired" ? t("seg.link") : t(`seg.${k}`),
    ui: down.has(k) ? "down" : first >= 0 && i > first ? "not_checked" : "ok" }));
}

async function download(path, name) {
  const headers = token() ? { Authorization: `Bearer ${token()}` } : {};
  const r = await fetch(path, { headers });
  if (!r.ok) { toast(t("error.load", { what: name, code: r.status })); return; }
  const url = URL.createObjectURL(await r.blob());
  const a = h("a", { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

function card(d, headline) {   // the "card PNG": public-view words only, drawn on a canvas
  const c = document.createElement("canvas");
  c.width = 1200; c.height = 630;
  const x = c.getContext("2d"), css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  x.fillStyle = css("--surface"); x.fillRect(0, 0, 1200, 630);
  x.fillStyle = css("--ink"); x.font = "700 52px 'Pretendard Variable', system-ui";
  const words = headline.split(" "); let line = "", y = 140;
  for (const w of words) { if (x.measureText(line + w).width > 1040) { x.fillText(line, 80, y); line = ""; y += 66; } line += w + " "; }
  x.fillText(line, 80, y);
  x.font = "400 30px 'Pretendard Variable', system-ui"; x.fillStyle = css("--ink-2");
  x.fillText(d.next.slice(0, 80), 80, y + 80);
  x.fillStyle = css("--ink-3"); x.font = "400 24px 'Pretendard Variable', system-ui";
  x.fillText(`whydrop · ${t("drop.rule", { rule: d.rule })}`, 80, 570);
  c.toBlob((b) => { const url = URL.createObjectURL(b); const a = h("a", { href: url, download: `whydrop-drop-${d.id}.png` });
    document.body.append(a); a.click(); a.remove(); }, "image/png");
}

export async function mount(main, { id, refresh }) {
  cleanup.forEach(f => f()); cleanup = [];
  let raw, st, ann;
  try {
    [raw, st] = await Promise.all([api(`/api/incidents/${id}`), api("/api/status")]);
  } catch (e) { main.replaceChildren(errorPanel(e, refresh)); return; }
  const d = parseIncident(raw);
  const from = d.start - 60000, to = (d.end || Date.now()) + 60000;
  const [samples, events, ringRows] = await Promise.all([
    api(`/api/samples?from=${from}&to=${to}&step=1`), api(`/api/events?from=${from}&to=${to}`),
    api(`/api/incidents/${id}/strip`).catch(() => [])]);
  ann = await api(`/api/annotations?from=${from}&to=${to}`).catch(() => []);

  const durS = d.end ? (d.end - d.start) / 1000 : (Date.now() - d.start) / 1000;
  const headline = d.segs.length ? t("drop.headline", { seg: d.segs[0], dur: dur(durS), cause: d.label })
    : t("drop.headline_point", { cause: d.label });
  const label = ann.find(a => a.label === "reproduced" || a.label === "injected" || a.label === "user-test");

  const actions = h("div", { class: "row" },
    h("button", { class: "btn", type: "button", onclick: async () => {
      try { await navigator.clipboard.writeText(await api(`/api/incidents/${id}/summary?lang=${document.documentElement.lang}`)); toast(t("drop.copied")); }
      catch (e) { toast(t("error.load", { what: "summary", code: e.code || "?" })); }
    } }, t("drop.copy")),
    h("button", { class: "btn", type: "button", onclick: () => download(`/api/export/bugreport/${id}`, `whydrop-bugreport-${id}.json`) },
      t("drop.export_json")),
    h("button", { class: "btn", type: "button", onclick: () => card(d, headline) }, t("drop.card")),
    h("a", { class: "btn", target: "_blank", rel: "noopener noreferrer",
      href: `${REPO_ISSUES}?${new URLSearchParams({ title: `Wrong diagnosis: rule ${d.rule}`,
        body: `Rule ${d.rule}, ${Math.round(durS)} s.\n\nWhat really happened:\n\n(Attach the bug report JSON from "${t("drop.export_json")}".)` })}` },
      t("drop.wrong")));

  const evRows = Object.entries(d.evidence).filter(([k]) => !["label", "next_step", "protocol", "events"].includes(k));
  const lanesEl = lanes(series(samples.rows, 1, st?.mode || "basic"), { stepS: 1, mode: st?.mode || "basic", baseline: "ready",
    events: events.filter(e => e.kind === "rst") });
  cleanup.push(() => lanesEl.cleanup());

  main.replaceChildren(
    h("section", { class: "panel" },
      h("p", {}, h("a", { href: "#/drops" }, t("drop.back"))),
      label ? h("p", { class: "labelbanner" }, t(`label.${label.label}`)) : null,
      h("h1", { class: "headline" }, headline),
      h("p", { class: "when" }, `${when(d.start)}`, " ", h("span", { class: "faint" }, t("drop.rule", { rule: d.rule })), " ",
        h("span", { class: "faint" }, d.final ? t("drop.final") : t("drop.settling"))),
      actions,
      pathDiagram(frozenPath(d, st?.link), { frozen: true, vertical: window.matchMedia("(max-width: 640px)").matches })),
    h("section", { class: "panel" }, h("h2", {}, t("drop.next")), h("p", { class: "protocol" }, d.next || "–")),
    h("section", { class: "panel" }, h("h2", {}, t("drop.timeline")), h("h3", {}, t("drop.strip")), strip(ringRows), lanesEl),
    d.protocol ? h("section", { class: "panel" }, h("h2", {}, t("drop.protocol")), h("p", { class: "protocol" }, d.protocol)) : null,
    h("section", { class: "panel split" },
      h("div", {}, h("h2", {}, t("drop.evidence")), evRows.length ? h("dl", { class: "kv" },
        evRows.flatMap(([k, v]) => [h("dt", {}, t(`ev.${k}`) === `ev.${k}` ? k : t(`ev.${k}`)),
          h("dd", {}, Array.isArray(v) ? v.join(", ") || "–" : String(v))])) : h("p", { class: "faint" }, "–")),
      h("div", {}, h("h2", {}, t("drop.history")),
        h("p", {}, d.changed ? t("drop.changed", { rule: d.provisional || "?" }) : t("drop.unchanged")),
        h("h2", {}, t("drop.annotations")), ann.length ? h("ul", { class: "drops" }, ann.map(a => h("li", {},
          h("span", { class: "what" }, t(`label.${a.label}`)), " ", h("span", { class: "faint" }, when(startMs(a)))))) : h("p", { class: "faint" }, "–"))));
}

export function leave() { cleanup.forEach(f => f()); cleanup = []; }
