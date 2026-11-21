// The path diagram: this device → Wi-Fi/cable → router → internet line → DNS, drawn as a cable that visibly
// breaks at the hop that failed (UI design doc §4, §5.1). Nodes are buttons that filter the page.
import { h, svg, t } from "../lib.js";

const STATE = { up: "ok", down: "down", unobservable: "cant_see", unknown: "not_checked", checking: "checking" };

export function hops(status, rough = new Set()) {
  const seg = status?.segments || {};
  const linkSeg = status?.link === "wired" ? "link" : "wifi";
  const why = {};
  const list = [
    { key: "host_net", label: t("seg.host_net"), state: seg.host_net },
    { key: linkSeg, label: linkSeg === "wifi" && status?.signal_dbm != null
        ? `${t("seg.wifi")} ${String(status.signal_dbm).replace("-", "\u2212")} dBm` : t(`seg.${linkSeg}`),
      state: seg[linkSeg] },
    { key: "lan", label: t("seg.lan"), state: seg.lan },
    { key: "line", label: t("seg.line"), state: seg.line },
    { key: "dns", label: t("seg.dns"), state: seg.dns },
  ];
  if (seg[linkSeg] === "down") why.lan = t("why.wifi_down");
  if (seg.lan === "unobservable") why.lan = t("why.unobservable");
  for (const x of list) {
    let s = STATE[x.state] || "not_checked";
    if (s === "not_checked" && seg[linkSeg] === "down" && x.key !== "host_net" && x.key !== linkSeg) s = "not_checked";
    if (s === "ok" && rough.has(x.key)) s = "unstable";
    x.ui = s;
    x.why = why[x.key];
  }
  return list;
}

export function pathDiagram(list, { onPick, vertical = false, frozen = false } = {}) {
  const n = list.length, gap = vertical ? 64 : 200, r = 11;
  const W = vertical ? 300 : gap * (n - 1) + 120, H = vertical ? gap * (n - 1) + 40 : 86;
  const pos = (i) => vertical ? [24, 20 + i * gap] : [60 + i * gap, 22];
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "group", "aria-label": frozen ? t("drop.frozen") : t("nav.now") });
  for (let i = 0; i < n - 1; i++) {
    const [x1, y1] = pos(i), [x2, y2] = pos(i + 1);
    const next = list[i + 1].ui;
    const cls = next === "down" ? "cable broken" : (next === "not_checked" || next === "cant_see") ? "cable unknown" : "cable";
    root.append(svg("line", { class: cls, x1: vertical ? x1 : x1 + r, y1: vertical ? y1 + r : y1, x2: vertical ? x2 : x2 - r,
      y2: vertical ? y2 - r : y2 }));
    if (next === "down") {   // the break itself: a gap with two frayed ends
      const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
      root.append(svg("path", { class: "cable broken", d: vertical ? `M${mx - 9} ${my - 6} L${mx + 9} ${my + 6} M${mx + 9} ${my - 6} L${mx - 9} ${my + 6}`
        : `M${mx - 6} ${my - 9} L${mx + 6} ${my + 9} M${mx + 6} ${my - 9} L${mx - 6} ${my + 9}` }));
    }
  }
  list.forEach((x, i) => {
    const [cx, cy] = pos(i);
    const mark = { ok: "✓", unstable: "!", down: "✕", not_checked: "–", cant_see: "?", checking: "…" }[x.ui];
    const g = svg("g", { class: `node ${x.ui === "ok" ? "" : x.ui === "unstable" ? "warn" : x.ui === "down" ? "down" : "unknown"}`,
      tabindex: onPick ? "0" : null, role: onPick ? "button" : null,
      "aria-label": `${x.label}: ${t(`state.${x.ui}`)}${x.why ? ". " + x.why : ""}` },
      svg("circle", { cx, cy, r }),
      svg("text", { x: vertical ? cx + 24 : cx, y: vertical ? cy + 5 : cy + 34, "text-anchor": vertical ? "start" : "middle" }, x.label),
      svg("text", { class: "state", x: vertical ? cx + 24 : cx, y: vertical ? cy + 24 : cy + 54, "text-anchor": vertical ? "start" : "middle" },
        `${mark} ${t(`state.${x.ui}`)}`));
    if (onPick) {
      g.addEventListener("click", () => onPick(x.key));
      g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onPick(x.key); } });
    }
    root.append(g);
  });
  const why = list.map(x => x.why).filter(Boolean);
  return h("div", { class: "path" }, root, why.length ? h("p", { class: "why" }, why[0]) : null);
}
