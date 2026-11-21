// NAT timeouts (#/nat): the keepalive to set, the survival chart, and a run button (UI design doc §5.3).
import { api, errorPanel, h, isPublic, svg, t, toast } from "../lib.js";

function bracket(rows) {
  const dead = rows.filter(r => r.alive === 0 || r.alive === false).map(r => r.delay_s);
  const hi = dead.length ? Math.min(...dead) : null;
  const ok = rows.filter(r => (r.alive === 1 || r.alive === true) && (hi == null || r.delay_s < hi)).map(r => r.delay_s);
  return [ok.length ? Math.max(...ok) : null, hi];
}

function chart(byProto) {   // step lines of survival vs delay, log x axis, direct labels (light aqua < 3:1)
  const W = 640, H = 200, L = 60, R = 70, T = 16, B = 34;
  const all = Object.values(byProto).flat().map(r => r.delay_s);
  if (!all.length) return null;
  const lx = (v) => L + (Math.log10(v) - 1) / (Math.log10(Math.max(...all, 600)) - 1) * (W - L - R);
  const ly = (alive) => (alive ? T + 20 : H - B - 10);
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": t("nat.title") });
  root.append(svg("line", { x1: L, y1: H - B, x2: W - R, y2: H - B, stroke: "var(--rule)" }));
  for (const tick of [10, 30, 60, 300, 600, 1800, 3600]) {
    if (tick > Math.max(...all) * 1.5) break;
    root.append(svg("text", { x: lx(tick), y: H - 12, "text-anchor": "middle", fill: "var(--ink-3)", "font-size": 12 }, `${tick} s`));
  }
  root.append(svg("text", { x: 8, y: ly(1) + 4, fill: "var(--ink-3)", "font-size": 12 }, t("nat.alive")),
    svg("text", { x: 8, y: ly(0) + 4, fill: "var(--ink-3)", "font-size": 12 }, t("nat.forgotten")));
  for (const [proto, rows] of Object.entries(byProto)) {
    const color = proto === "udp" ? "var(--udp)" : "var(--tcp)";
    const pts = rows.slice().sort((a, b) => a.delay_s - b.delay_s);
    let d = "";
    pts.forEach((r, i) => { if (r.alive == null) return; const x = lx(r.delay_s), y = ly(r.alive); d += d ? ` H${x} V${y}` : `M${x} ${y}`; });
    if (d) root.append(svg("path", { d, fill: "none", stroke: color, "stroke-width": 2.5 }));
    for (const r of pts) root.append(svg("circle", { cx: lx(r.delay_s), cy: r.alive == null ? (ly(1) + ly(0)) / 2 : ly(r.alive), r: 5,
      fill: r.alive == null ? "var(--surface)" : color, stroke: color, "stroke-width": 2 }));
    const last = pts[pts.length - 1];
    if (last) root.append(svg("text", { x: lx(last.delay_s) + 10, y: (last.alive == null ? (ly(1) + ly(0)) / 2 : ly(last.alive)) + 4,
      fill: "var(--ink)", "font-size": 13, "font-weight": 600 }, proto.toUpperCase()));
  }
  return root;
}

export async function mount(main, { refresh }) {
  let nat;
  try { nat = await api("/api/nat"); } catch (e) { main.replaceChildren(errorPanel(e, refresh)); return; }
  const rows = nat.results || [];
  const by = { udp: rows.filter(r => r.proto === "udp"), tcp: rows.filter(r => r.proto === "tcp") };
  const hero = [];
  for (const [proto, list] of Object.entries(by)) {
    if (!list.length) continue;
    const [lo, hi] = bracket(list);
    if (lo != null && hi != null) {
      const first = !hero.some(x => x.classList.contains("status"));   // the shortest keepalive is the hero
      hero.push(h("p", { class: first ? "status" : "lastdrop" }, t("nat.keepalive", { s: Math.max(5, Math.floor(lo * 0.8 / 5) * 5) })),
        h("p", { class: first ? "lastdrop" : "faint" }, t("nat.range", { proto: proto.toUpperCase(), lo, hi })));
    } else if (lo != null) {
      hero.push(h("p", { class: "lastdrop" }, t("nat.open", { proto: proto.toUpperCase(), lo })));
    }
  }
  const running = nat.running;
  const btn = isPublic ? null : h("button", { class: "btn primary", type: "button", disabled: running ? true : null, onclick: async () => {
    try { await api("/api/nat/run", { method: "POST" }); refresh(); }
    catch (e) { toast(e.code === 409 ? t("nat.already") : e.code === 400 ? t("nat.needs_precision") : t("error.load", { what: "nat", code: e.code })); }
  } }, t("nat.run"));
  const progress = running ? h("p", { class: "muted", "aria-live": "polite" }, t("nat.running", {
    proto: (running.last?.proto || "udp").toUpperCase(), delay: running.last?.delay_s ?? "…", done: running.done, total: running.total })) : null;
  const tableRows = rows.map(r => h("tr", {}, h("td", {}, r.proto.toUpperCase()), h("td", {}, `${r.delay_s} s`),
    h("td", {}, r.alive == null ? t("nat.inconclusive") : r.alive ? t("nat.alive") : t("nat.forgotten"))));
  main.replaceChildren(h("section", { class: "panel" }, h("h1", { class: "headline" }, t("nat.title")),
    ...(hero.length ? hero : [h("p", { class: "empty" }, t("nat.none"))]), h("div", { class: "row" }, btn, progress)),
    rows.length ? h("section", { class: "panel" }, h("div", { class: "natchart" }, chart(by)),
      h("table", { class: "data" }, h("tbody", {}, tableRows))) : null);
  if (running) setTimeout(() => location.hash === "#/nat" && refresh(), 5000);
}
