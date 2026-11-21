// Now (#/): is it working right now, when did it last drop, and why — without scrolling (UI design doc §5.1).
import { live, refreshStatus } from "../app.js";
import { lanes, series } from "../components/lanes.js";
import { hops, pathDiagram } from "../components/path.js";
import { api, cause, dur, endMs, errorPanel, h, isPublic, parseIncident, prefsGet, prefsSet, startMs, t, toast, when } from "../lib.js";

const RANGES = [["1h", 3600], ["6h", 21600], ["24h", 86400], ["7d", 604800]];
let cleanup = [];

function statusSentence(st, open, rough) {
  if (!st) return t("status.not_recording", { since: "–" });
  const segs = st.segments || {};
  if (Object.values(segs).every(s => s === "checking")) return t("status.checking");
  if (open) {
    const secs = Math.max(0, Math.round((Date.now() - open.start) / 1000));
    return t("status.down", { seg: open.segs[0] || t("seg.line"), secs });
  }
  if (rough) {
    const d = rough.detail_json ? JSON.parse(rough.detail_json) : (rough.detail || {});
    return t("status.rough", { pct: Math.max(1, Math.round((d.loss || 0) * 100)) });
  }
  return t("status.ok");
}

function lastDrop(drops, st) {
  const done = drops.filter(d => !d.open);
  if (!done.length) {
    const since = st?.since_ms ? (Date.now() - st.since_ms) / 1000 : st?.since_s != null ? -st.since_s : 0;
    return h("div", {},
      h("p", { class: "lastdrop" }, t("last.none", { dur: dur(since) })),
      h("p", { class: "faint" }, t("test.hint")));
  }
  const d = done[0];
  return h("div", { class: "row" },
    h("p", { class: "lastdrop" }, t("last.drop", { when: when(d.start), dur: dur((d.end - d.start) / 1000),
      where: d.segs.join(", ") || d.label, cause: d.segs.length ? d.label : "" })),
    h("a", { class: "btn", href: `#/drop/${d.id}` }, t("last.open")));
}

function banners(findings, st) {
  const out = [];
  const kinds = new Set(findings.filter(f => f.end_ms == null && f.end_s == null).map(f => f.kind));
  if (kinds.has("secret_mismatch")) out.push(h("p", { class: "banner bad" }, t("banner.secret_mismatch")));
  else if (kinds.has("precision_degraded")) out.push(h("p", { class: "banner" }, t("banner.precision_degraded")));
  if (kinds.has("vpn_egress") || st?.vpn) out.push(h("p", { class: "banner" }, t("banner.vpn")));
  return out;
}

export async function mount(main, { refresh }) {
  cleanup.forEach(f => f()); cleanup = [];
  const range = Number(prefsGet("whydrop.range") || 3600);
  const to = Date.now(), from = to - range * 1000;
  let st, incs, conds, findings, samples, events;
  try {
    [st, incs, conds, findings] = await Promise.all([refreshStatus(), api(`/api/incidents?from=${to - 30 * 86400000}&to=${to}`),
      api(`/api/conditions?from=${from}&to=${to}`), api("/api/findings")]);
    [samples, events] = await Promise.all([api(`/api/samples?from=${from}&to=${to}`), api(`/api/events?from=${from}&to=${to}&kind=rst`)]);
  } catch (e) {
    main.replaceChildren(errorPanel(e, refresh));
    return;
  }
  const drops = incs.map(parseIncident).sort((a, b) => b.start - a.start);
  const open = drops.find(d => d.open && d.segs.length);
  const roughNow = conds.find(c => (c.end_ms ?? c.end_s) == null && c.kind === "loss");
  const roughSegs = new Set(conds.filter(c => (c.end_ms ?? c.end_s) == null)
    .map(c => (c.kind === "loss" ? "line" : c.kind === "wifi_lan_loss" || c.kind === "weak_signal" ? (st?.link === "wired" ? "link" : "wifi") : null)));
  const vertical = window.matchMedia("(max-width: 640px)").matches;

  const sentence = h("h1", { class: "status", "aria-live": "polite" }, statusSentence(st, open, roughNow));
  const picked = (seg) => { location.hash = `#/drops?segment=${seg}`; };
  const head = h("section", { class: "panel" }, ...banners(findings, st), sentence, lastDrop(drops, st),
    pathDiagram(hops(st, roughSegs), { onPick: picked, vertical }));

  const rangeRow = h("div", { class: "ranges", role: "group", "aria-label": t("range.1h") },
    RANGES.map(([k, s]) => h("button", { type: "button", "aria-pressed": String(s === range),
      onclick: () => { prefsSet("whydrop.range", String(s)); refresh(); } }, t(`range.${k}`))));
  const testBtn = isPublic ? null : h("button", { class: "btn primary", type: "button", onclick: async (ev) => {
    ev.target.disabled = true;
    try {
      await api("/api/annotations", { method: "POST", json: { start_ms: Date.now(), end_ms: Date.now() + 120000, label: "user-test" } });
      toast(t("test.started"));
    } catch (e) { toast(t("error.load", { what: "annotation", code: e.code || "?" })); }
    setTimeout(() => { ev.target.disabled = false; }, 120000);
  } }, t("test.button"));
  const data = series(samples.rows, samples.step_s, st?.mode || "basic");
  const lanesEl = lanes(data, { stepS: samples.step_s, mode: st?.mode || "basic", baseline: st?.baseline, events });
  cleanup.push(() => lanesEl.cleanup());
  const charts = h("section", { class: "panel" + (vertical ? " charts-collapsed" : "") }, h("div", { class: "row" }, rangeRow, testBtn), lanesEl);
  if (vertical) {
    const show = h("button", { class: "btn", type: "button", onclick: () => { charts.classList.remove("charts-collapsed"); show.remove(); } },
      t("lane.show_charts"));
    charts.prepend(show);
  }

  const inRange = drops.filter(d => d.start >= from);
  const recent = h("div", {}, h("h2", {}, t("recent.title")), inRange.length
    ? h("ul", { class: "drops" }, inRange.slice(0, 8).map(d => h("li", {}, h("a", { href: `#/drop/${d.id}` },
        h("span", { class: "what" }, `${when(d.start)}, ${d.open ? "…" : dur((d.end - d.start) / 1000)}, ${d.segs.join(", ") || ""}`),
        h("div", { class: "muted" }, d.label)))))
    : h("p", { class: "empty" }, t("recent.none")));
  const roughList = conds.filter(c => c.kind === "loss" || c.kind === "latency" || c.kind === "wifi_lan_loss");
  const rough = h("div", {}, h("h2", {}, t("rough.title")), roughList.length
    ? h("ul", { class: "drops" }, roughList.slice(0, 8).map(c => {
        const d = c.detail_json ? JSON.parse(c.detail_json) : (c.detail || {});
        const s = startMs(c), e = endMs(c);
        return h("li", {}, h("div", { class: "what" }, `${when(s)}${e ? ", " + dur((e - s) / 1000) : ""}`),
          h("div", { class: "muted" }, cause(d.label || c.kind)));
      }))
    : h("p", { class: "empty" }, t("rough.none")));
  main.replaceChildren(head, charts, h("section", { class: "panel split" }, recent, rough));

  let timer = null;
  const onMsg = (msg) => {
    if (!["incident", "segment", "condition", "finding"].includes(msg.type)) return;
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const s2 = await refreshStatus();
      const list = (await api(`/api/incidents?from=${Date.now() - 30 * 86400000}`)).map(parseIncident);
      const o2 = list.find(d => d.open && d.segs.length);
      sentence.textContent = statusSentence(s2, o2, null);
      const node = pathDiagram(hops(s2, roughSegs), { onPick: picked, vertical });
      head.querySelector(".path")?.replaceWith(node);
    }, 800);
  };
  live.listeners.add(onMsg);
  const tick = setInterval(() => { if (open) sentence.textContent = statusSentence(live.status, open, roughNow); }, 1000);
  cleanup.push(() => { live.listeners.delete(onMsg); clearInterval(tick); clearTimeout(timer); });
}

export function leave() { cleanup.forEach(f => f()); cleanup = []; }
