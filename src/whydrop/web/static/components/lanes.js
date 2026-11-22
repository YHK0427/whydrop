// Time-aligned lanes on one x axis with a shared crosshair (UI design doc §6): packet loss (mirrored up/down bars),
// latency (line + usual band), TCP connection (state band). Every lane has a table view with the same data.
import uPlot from "../vendor/uplot/uPlot.esm.js";
import { clock, h, lang, t, tsMs } from "../lib.js";


const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();

export function series(c, mode) {
  // /api/chart is already bucketed and columnar; the lanes only pick the loss source and smooth the latency
  const stepS = c.step_s;
  return {
    x: c.x_rel ? c.x_rel.map(v => Date.now() / 1000 + v) : c.x, up: c.up, down: c.down,   // public view: relative s
    unknown: mode === "basic" ? c.basic_lost : c.stream_unknown,
    rtt: smooth(c.rtt, stepS < 10 ? Math.round(10 / stepS) : 1),
    tcp: c.tcp,
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
    box._chart?.destroy();
    box._chart = null;
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
  const timeFmt = (splits) => {   // the UI language's clock (24 h in Korean), not uPlot's built-in English am/pm
    const span = splits.length > 1 ? splits[splits.length - 1] - splits[0] : 0;
    const f = new Intl.DateTimeFormat(lang, span > 1.5 * 86400 ? { month: "numeric", day: "numeric", hour: "2-digit", hour12: false }
      : span <= 900 ? { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }   // a drop's ±60 s window
      : { hour: "2-digit", minute: "2-digit", hour12: false });
    return splits.map(s => f.format(s * 1000));
  };
  const axisX = { stroke: css("--ink-3"), grid: { stroke: css("--rule") }, ticks: { stroke: css("--rule") }, values: (u, splits) => timeFmt(splits) };
  const axisY = (label) => ({ stroke: css("--ink-3"), grid: { stroke: css("--rule") }, ticks: { show: false }, label, size: 46 });
  const bars = uPlot.paths.bars({ size: [0.9, 12] });
  const charts = [];
  const root = h("div", { class: "lanes" });
  const mk = (opts, d) => (box) => { const u = new uPlot({ width: width(box), height: opts.height, cursor, legend: { show: false },
    scales: { x: { time: true } }, ...opts }, d, box); box._chart = u; charts.push(u); };
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
  const onResize = () => charts.forEach(u => u.root.isConnected && u.setSize({ width: width(u.root.parentElement), height: u.height }));
  window.addEventListener("resize", onResize);
  root.cleanup = () => { window.removeEventListener("resize", onResize); charts.forEach(u => { try { u.destroy(); } catch {} }); };
  return root;
}
