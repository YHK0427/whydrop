// Now (#/): is it working right now, when did it last drop, and why — without scrolling (UI design doc §5.1).
import { live, refreshStatus } from "../app.js";
import { lanes, series } from "../components/lanes.js";
import { hops, pathDiagram } from "../components/path.js";
import { api, cause, dur, endMs, errorPanel, h, isPublic, parseIncident, prefsGet, prefsSet, startMs, t, toast, when } from "../lib.js";

const isRemote = () => !["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);
const RANGES = [["1h", 3600], ["6h", 21600], ["24h", 86400], ["7d", 604800]];

function lossWhere(d) {   // line / path (to the reflector) / home; rows before 0.1.0 carry only the label
  return d.where || (/reflector/.test(d.label || "") ? "path" : /home network/.test(d.label || "") ? "home" : "line");
}

function statusSentence(st, open, rough) {
  if (!st) return t("status.not_recording", { since: "–" });
  const segs = st.segments || {};
  if (Object.values(segs).every(s => s === "checking")) return t("status.checking");
  if (open) {
    const secs = Math.max(0, Math.round((Date.now() - open.start) / 1000));
    return t(open.slow ? "status.slow" : "status.down", { seg: open.segs[0] || t("seg.line"), secs });
  }
  if (rough) {
    const d = rough.detail_json ? JSON.parse(rough.detail_json) : (rough.detail || {});
    return t(`status.rough${{ path: "_path", home: "_home" }[lossWhere(d)] || ""}`, { pct: Math.max(1, Math.round((d.loss || 0) * 100)) });
  }
  return t("status.ok");
}

function lastDrop(drops, st) {
  const done = drops.filter(d => !d.open);
  if (!done.length) {
    const since = st?.since_ms ? (Date.now() - st.since_ms) / 1000 : st?.since_s != null ? -st.since_s : 0;
    return h("div", {},
      h("p", { class: "lastdrop" }, t("last.none", { dur: dur(since) })),
      isPublic ? null : h("p", { class: "faint" }, t(isRemote() ? "test.hint_remote" : "test.hint")));   // the public view has no test button
  }
  const d = done[0];
  return h("div", { class: "row" },
    h("p", { class: "lastdrop" }, d.point ? t("last.event", { when: when(d.start), cause: d.label }) : t("last.drop", { when: when(d.start), dur: dur((d.end - d.start) / 1000),
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
  const cleanup = [];   // this mount's own: a later mount of the same page never shares it
  const range = Number(prefsGet("whydrop.range") || 3600);
  const to = Date.now(), from = to - range * 1000;
  let st, incs, conds, findings, samples, events, anns;
  try {
    [st, incs, conds, findings] = await Promise.all([refreshStatus(), api(`/api/incidents?from=${to - 30 * 86400000}&to=${to}`),
      api(`/api/conditions?from=${from}&to=${to}`), api("/api/findings")]);
    [samples, events, anns] = await Promise.all([api(`/api/chart?from=${from}&to=${to}`), api(`/api/events?from=${from}&to=${to}&kind=rst`),
      api(`/api/annotations?from=${from}&to=${to}`).catch(() => [])]);
  } catch (e) {
    main.replaceChildren(errorPanel(e, refresh));
    return;
  }
  let drops = incs.map(parseIncident).sort((a, b) => b.start - a.start);
  let open = drops.find(d => d.open && d.segs.length);
  let roughNow = conds.find(c => (c.end_ms ?? c.end_s) == null && c.kind === "loss");
  const roughSegs = new Set(conds.filter(c => (c.end_ms ?? c.end_s) == null)
    .map(c => (c.kind === "loss" ? { line: "line", path: null, home: st?.link === "wired" ? "link" : "wifi" }[lossWhere(c.detail_json ? JSON.parse(c.detail_json) : (c.detail || {}))] : c.kind === "wifi_lan_loss" || c.kind === "weak_signal" ? (st?.link === "wired" ? "link" : "wifi") : null)));
  const vertical = window.matchMedia("(max-width: 640px)").matches;

  const sentence = h("h1", { class: "status", "aria-live": "polite" }, statusSentence(st, open, roughNow));
  const picked = (seg) => { location.hash = `#/drops?segment=${seg}`; };
  let lastNode = lastDrop(drops, st);
  const head = h("section", { class: "panel" }, ...banners(findings, st), sentence, lastNode,
    pathDiagram(hops(st, roughSegs), { onPick: picked, vertical }));
  const FOCUSABLE = 'a[href], button, [tabindex="0"]';
  const swapIn = (old, fresh) => {   // replace a block; if it held the focus, put it back on the same control
    const a = document.activeElement, had = old.contains(a), href = had && a.getAttribute("href");
    const idx = had ? [...old.querySelectorAll(FOCUSABLE)].indexOf(a) : -1;
    old.replaceWith(fresh);
    if (had) ((href && fresh.querySelector(`[href="${href}"]`)) || fresh.querySelectorAll(FOCUSABLE)[idx])?.focus();
    return fresh;
  };
  let lastHops = JSON.stringify(hops(st, roughSegs));   // the path as drawn
  const swapLast = (s) => { lastNode = swapIn(lastNode, lastDrop(drops, s)); };

  const rangeRow = h("div", { class: "ranges", role: "group", "aria-label": t("range.1h") },
    RANGES.map(([k, s]) => h("button", { type: "button", "aria-pressed": String(s === range),
      onclick: () => { prefsSet("whydrop.range", String(s)); refresh(); } }, t(`range.${k}`))));
  const testBtn = isPublic ? null : h("button", { class: "btn primary", type: "button", onclick: async (ev) => {
    ev.target.disabled = true;
    try {
      await api("/api/annotations", { method: "POST", json: { start_ms: Date.now(), end_ms: Date.now() + 120000, label: "user-test" } });
      toast(t("test.started"));
    } catch (e) { toast(t("error.load", { what: t("what.annotation"), code: e.code || "?" })); }
    setTimeout(() => { ev.target.disabled = false; }, 120000);
  } }, t("test.button"));
  const data = series(samples, st?.mode || "basic");
  const lanesEl = lanes(data, { stepS: samples.step_s, mode: st?.mode || "basic", baseline: st?.baseline, events });
  let lanesNow = lanesEl;
  cleanup.push(() => lanesNow.cleanup());
  const charts = h("section", { class: "panel" + (vertical ? " charts-collapsed" : "") }, h("div", { class: "row" }, rangeRow, testBtn), lanesEl);
  if (vertical) {
    const show = h("button", { class: "btn", type: "button", onclick: () => { charts.classList.remove("charts-collapsed"); show.remove(); } },
      t("lane.show_charts"));
    charts.prepend(show);
  }

  const scene = (s, e) => {   // a drop or patch inside an annotated scene says so: injected and reproduced aren't natural
    const a = (anns || []).find(x => startMs(x) <= (e ?? Date.now()) && (endMs(x) ?? startMs(x)) >= s);
    return a ? h("span", { class: "scenetag" }, t(`label.${a.label}`)) : null;
  };
  const lists = () => {   // rebuilt whenever a drop or patch arrives, so neither list waits for a reload
    const inRange = drops.filter(d => d.start >= Date.now() - range * 1000);
    const recent = h("div", {}, h("h2", {}, t("recent.title")), inRange.length
      ? h("ul", { class: "drops" }, inRange.slice(0, 8).map(d => h("li", {}, h("a", { href: `#/drop/${d.id}` },
          h("span", { class: "what" }, [when(d.start), d.point ? null : d.open ? "…" : dur((d.end - d.start) / 1000), d.segs.join(", ") || null]
            .filter(Boolean).join(", ")), scene(d.start, d.end),   // a point event has no duration
          h("div", { class: "muted" }, d.label)))))
      : h("p", { class: "empty" }, t("recent.none")));
    const roughList = conds.filter(c => c.kind === "loss" || c.kind === "latency" || c.kind === "wifi_lan_loss");
    const rough = h("div", {}, h("h2", {}, t("rough.title")), roughList.length
      ? h("ul", { class: "drops" }, roughList.slice(0, 8).map(c => {
          const d = c.detail_json ? JSON.parse(c.detail_json) : (c.detail || {});
          const s = startMs(c), e = endMs(c);
          return h("li", {}, h("div", { class: "what" }, `${when(s)}${e ? ", " + dur((e - s) / 1000) : ""}`, scene(s, e)),
            h("div", { class: "muted" }, cause(d.label || c.kind)));
        }))
      : h("p", { class: "empty" }, t("rough.none")));
    return h("section", { class: "panel split" }, recent, rough);
  };
  let listsNode = lists();
  main.replaceChildren(head, charts, listsNode);

  let timer = null, lastSig = JSON.stringify([incs, conds, anns]);   // what the page was built from
  const onMsg = (msg) => {
    if (!["incident", "segment", "condition", "finding", "resync"].includes(msg.type)) return;
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const s2 = await refreshStatus();
      const now = Date.now();
      const [list, c2] = await Promise.all([api(`/api/incidents?from=${now - 30 * 86400000}`), api(`/api/conditions?from=${now - range * 1000}`)]);
      anns = await api(`/api/annotations?from=${now - range * 1000}&to=${now}`).catch(() => anns);
      const sig = JSON.stringify([list, c2, anns]);
      const changed = sig !== lastSig;
      lastSig = sig;
      drops = list.map(parseIncident).sort((a, b) => b.start - a.start);
      conds = c2;
      open = drops.find(d => d.open && d.segs.length);
      roughNow = c2.find(c => (c.end_ms ?? c.end_s) == null && c.kind === "loss");
      sentence.textContent = statusSentence(s2, open, roughNow);
      const hl = hops(s2, roughSegs), hsig = JSON.stringify(hl), old = head.querySelector(".path");
      if (hsig !== lastHops && old) {   // redraw only a changed path: a redraw moves the keyboard focus
        lastHops = hsig;
        swapIn(old, pathDiagram(hl, { onPick: picked, vertical }));
      }
      if (changed) {   // rebuilding unchanged lists would only move the keyboard focus
        swapLast(s2);
        listsNode = swapIn(listsNode, lists());
      }
    }, 800);
  };
  live.listeners.add(onMsg);
  const tick = setInterval(() => {
    if (open) sentence.textContent = statusSentence(live.status, open, roughNow);
    if (!drops.some(d => !d.open)) swapLast(live.status || st);   // "Recording for N s" keeps counting
  }, 1000);
  const redraw = range <= 21600 ? setInterval(async () => {   // new data in place: focus, scroll and toggles stay
    if (document.visibilityState !== "visible") return;
    const t2 = Date.now();
    try {
      const [c, ev] = await Promise.all([api(`/api/chart?from=${t2 - range * 1000}&to=${t2}`),
        api(`/api/events?from=${t2 - range * 1000}&to=${t2}&kind=rst`)]);
      const fresh = lanes(series(c, live.status?.mode || "basic"), { stepS: c.step_s, mode: live.status?.mode || "basic",
        baseline: live.status?.baseline, events: ev });
      lanesNow.cleanup();
      lanesNow.replaceWith(fresh);
      lanesNow = fresh;
    } catch { /* keep the old charts; the next tick tries again */ }
  }, 60000) : null;
  cleanup.push(() => { live.listeners.delete(onMsg); clearInterval(tick); clearTimeout(timer); clearInterval(redraw); });
  return () => cleanup.forEach(f => f());
}
