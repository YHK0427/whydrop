// Time-aligned lanes on one x axis with a shared crosshair (UI design doc §6): packet loss (mirrored up/down bars),
// latency (line + usual band), TCP connection (state band). Every lane has a table view with the same data.
import uPlot from "../vendor/uplot/uPlot.esm.js";
import { clock, h, t, tsMs } from "../lib.js";

const LINE_PROBES = new Set(["line_hb", "stun", "tcp_connect"]);
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();

export function series(rows, stepS, mode) {
  const by = new Map();
  for (const r of rows) {
    const ts = Math.floor(tsMs(r) / 1000 / stepS) * stepS;
    if (!by.has(ts)) by.set(ts, { up: 0, down: 0, lost: 0, rttSum: 0, rttN: 0, cSent: 0, cOk: 0 });
    const b = by.get(ts);
    if (r.probe === "udp_stream") { b.up += r.lost_up || 0; b.down += r.lost_down || 0; b.lost += r.lost || 0; }
    if (mode === "basic" && LINE_PROBES.has(r.probe)) b.lost += r.lost || 0;
    if (LINE_PROBES.has(r.probe) && r.rtt_avg != null) { b.rttSum += r.rtt_avg * (r.ok || 1); b.rttN += r.ok || 1; }
    if (r.probe === "canary") { b.cSent += r.sent || 0; b.cOk += r.ok || 0; }
  }
  const xs = [...by.keys()].sort((a, b) => a - b);
  const get = (f) => xs.map(x => f(by.get(x)));
  return {
    x: xs,
    up: get(b => b.up || null), down: get(b => (b.down ? -b.down : null)),
    unknown: get(b => (mode === "basic" ? b.lost : Math.max(0, b.lost - b.up - b.down)) || null),
    rtt: smooth(get(b => (b.rttN ? +(b.rttSum / b.rttN).toFixed(1) : null)), stepS < 10 ? Math.round(10 / stepS) : 1),
    tcp: get(b => (b.cSent ? (b.cOk === b.cSent ? 2 : b.cOk ? 1 : 0) : null)),   // 2 ok, 1 retransmitting, 0 stall
  };
}

function smooth(arr, w) {   // rolling median; gaps stay gaps
  if (w <= 1) return arr;
  return arr.map((v, i) => {
    if (v == null) return null;
    const win = arr.slice(Math.max(0, i - w + 1), i + 1).filter(x => x != null).sort((a, b) => a - b);
    return win[Math.floor(win.length / 2)];
  });
}

function pct(arr, q) {
  const v = arr.filter(x => x != null).sort((a, b) => a - b);
  return v.length ? v[Math.min(v.length - 1, Math.floor(v.length * q))] : null;
}

function table(cols, rows) {
  return h("div", { class: "tablewrap" }, h("table", { class: "data" },
    h("thead", {}, h("tr", {}, cols.map(c => h("th", { scope: "col" }, c)))),
    h("tbody", {}, rows.map(r => h("tr", {}, r.map(c => h("td", {}, c ?? "–")))))));
}

function lane(title, sub, legend, makeChart, tableView) {
  const box = h("div", { class: "chart" });
  let showTable = false;
  const btn = h("button", { class: "tablebtn", type: "button", "aria-pressed": "false" }, t("lane.table"));
  const wrap = h("section", { class: "lane", "aria-label": title },
    h("div", { class: "lane-head" }, h("h3", {}, title), legend, h("span", { class: "faint" }, sub), btn), box);
  btn.addEventListener("click", () => {
    showTable = !showTable;
    btn.textContent = showTable ? t("lane.chart") : t("lane.table");
    btn.setAttribute("aria-pressed", String(showTable));
    box.replaceChildren(showTable ? tableView() : "");
    if (!showTable) makeChart(box);
  });
  queueMicrotask(() => makeChart(box));
  return wrap;
}

export function lanes(data, { stepS, mode, baseline, events = [] }) {
  const sync = uPlot.sync("whydrop");
  const width = (box) => Math.max(200, Math.min(1200, (box || root).clientWidth - 2));   // the content box, not main's padding
  const cursor = { sync: { key: sync.key }, points: { show: false } };
  const axisX = { stroke: css("--ink-3"), grid: { stroke: css("--rule") }, ticks: { stroke: css("--rule") } };
  const axisY = (label) => ({ stroke: css("--ink-3"), grid: { stroke: css("--rule") }, ticks: { show: false }, label, size: 46 });
  const bars = uPlot.paths.bars({ size: [0.9, 12] });
  const charts = [];
  const root = h("div", { class: "lanes" });
  const mk = (opts, d) => (box) => { const u = new uPlot({ width: width(box), height: opts.height, cursor, legend: { show: false },
    scales: { x: { time: true } }, ...opts }, d, box); charts.push(u); };
  const stepWord = stepS === 1 ? t("unit.s", { n: 1 }) : stepS < 60 ? t("unit.s", { n: stepS }) : t("unit.min", { n: stepS / 60 });

  const precision = mode === "precision";
  const lossLegend = h("span", { class: "legend" }, precision
    ? [h("span", {}, h("i", { class: "sw up" }), t("lane.loss.legend_up")), h("span", {}, h("i", { class: "sw down" }), t("lane.loss.legend_down"))]
    : [h("span", {}, h("i", { class: "sw lost" }), t("lane.loss.legend_basic"))]);
  const loss = lane(t("lane.loss"), t("lane.loss.per", { step: stepWord }), lossLegend,
    mk({ height: 140, axes: [axisX, axisY("")],
      scales: { x: { time: true }, y: { range: () => {
        const hi = Math.max(1, ...data.up.map(v => v || 0), ...data.unknown.map(v => v || 0));
        const lo = precision ? Math.min(-1, ...data.down.map(v => v || 0)) : 0;
        const m = Math.max(hi, -lo);
        return [precision ? -m : 0, m];
      } } },
      series: [{}, { stroke: css("--up"), fill: css("--up"), paths: bars, points: { show: false } },
      { stroke: css("--down"), fill: css("--down"), paths: bars, points: { show: false } },
      { stroke: css("--ink-3"), fill: css("--ink-3"), paths: bars, points: { show: false } }] },
       [data.x, data.up, data.down, data.unknown]),
    () => table([t("drops.col.when"), "▲", "▼", "?"], data.x.map((x, i) => [clock(x * 1000), data.up[i], data.down[i] && -data.down[i], data.unknown[i]])));

  const p10 = pct(data.rtt, 0.1), p50 = pct(data.rtt, 0.5);
  const latency = lane(t("lane.latency"), baseline === "ready" ? t("lane.latency.sub") : t("lane.latency.learning"), null,
    mk({ height: 120, axes: [axisX, axisY("ms")], series: [{}, { stroke: css("--ink"), width: 2, points: { show: false }, spanGaps: false }],
      hooks: { drawClear: [(u) => {   // the usual band, never a second axis
        if (p10 == null) return;
        const { ctx, bbox } = u, y1 = u.valToPos(p50, "y", true), y0 = u.valToPos(p10, "y", true);
        ctx.save(); ctx.fillStyle = css("--rule"); ctx.fillRect(bbox.left, y1, bbox.width, y0 - y1); ctx.restore();
      }] } }, [data.x, data.rtt]),
    () => table([t("drops.col.when"), "ms"], data.x.map((x, i) => [clock(x * 1000), data.rtt[i]])));

  let tcp;
  if (precision) {
    const resets = events.filter(e => e.kind === "rst").map(e => Math.floor(tsMs(e) / 1000));
    tcp = lane(t("lane.tcp"), "", h("span", { class: "legend" },
      h("span", {}, h("i", { class: "sw ok" }), t("state.ok")), h("span", {}, h("i", { class: "sw stall" }), t("lane.tcp.stall")),
      h("span", {}, h("i", { class: "sw rst" }), "RST")),
      mk({ height: 90, axes: [axisX, { show: false }], scales: { x: { time: true }, y: { range: [0, 2] } },
        series: [{}, { stroke: css("--ink-3"), points: { show: false }, paths: uPlot.paths.stepped({ align: 1 }) }],
        hooks: { draw: [(u) => {
          const { ctx } = u;
          ctx.save();
          data.x.forEach((x, i) => {
            const v = data.tcp[i]; if (v == null) return;
            const x0 = u.valToPos(x, "x", true), x1 = u.valToPos(x + stepS, "x", true);
            ctx.fillStyle = css(v === 2 ? "--good" : v === 1 ? "--warn" : "--serious");
            ctx.fillRect(x0, u.bbox.top + 8, Math.max(1, x1 - x0), u.bbox.height - 16);
          });
          ctx.fillStyle = css("--critical"); ctx.font = "bold 13px sans-serif";
          resets.forEach(s => ctx.fillText("✕", u.valToPos(s, "x", true) - 4, u.bbox.top + 14));
          ctx.restore();
        }] } }, [data.x, data.tcp]),
      () => table([t("drops.col.when"), t("lane.tcp")], data.x.map((x, i) => [clock(x * 1000),
        data.tcp[i] == null ? null : [t("lane.tcp.stall"), t("lane.tcp.retrans"), t("state.ok")][data.tcp[i]]])));
  } else {
    tcp = h("section", { class: "lane" }, h("div", { class: "lane-head" }, h("h3", {}, t("lane.tcp"))),
      h("p", { class: "faint" }, t("lane.tcp.basic")));
  }
  root.append(loss, latency, tcp);
  const onResize = () => charts.forEach(u => u.setSize({ width: width(u.root.parentElement), height: u.height }));
  window.addEventListener("resize", onResize);
  root.cleanup = () => { window.removeEventListener("resize", onResize); charts.forEach(u => u.destroy()); };
  return root;
}
