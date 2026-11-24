// Report for the ISP (#/isp): only what happened beyond the router, each event set against the router at that moment.
// Printable: "Save as PDF" prints the page alone (the print stylesheet hides the dashboard around it).
import { api, dur, errorPanel, h, lang, t, toast } from "../lib.js";

const pct = (x) => Math.round(x * 1000) / 10;
const day = (ms) => new Intl.DateTimeFormat(lang, { year: "numeric", month: "long", day: "numeric" }).format(ms);
const stamp = (ms) => `${new Intl.DateTimeFormat(lang, { month: "short", day: "numeric" }).format(ms)} ${new Date(ms).toLocaleTimeString("en-GB", { hour12: false })}`;
const zone = () => new Intl.DateTimeFormat(lang, { timeZoneName: "short" }).formatToParts(new Date()).find(p => p.type === "timeZoneName")?.value || "";

function bar(share, cls) {   // a 0–1 share as a filled bar; width set through CSSOM (the CSP allows no inline style attribute)
  const fill = h("span", { class: "fill" });
  fill.style.width = `${Math.max(0, Math.min(1, share)) * 100}%`;
  return h("span", { class: `isp-bar ${cls}`, "aria-hidden": "true" }, fill);
}

function lead(d) {
  const parts = ["drops", "slow", "lossy", "ip", "dns"].filter(k => d.counts[k]).map(k =>
    t(`isp.part.${k}`, { n: d.counts[k], dur: dur(d.secs[k] || 0), pct: pct(d.worst) }));
  if (!parts.length) return t("isp.clean");
  const gw = d.events.filter(e => e.router).reduce((a, e) => ({ ok: a.ok + e.router.ok, sent: a.sent + e.router.sent }), { ok: 0, sent: 0 });
  const joined = parts.length > 1 ? parts.slice(0, -1).join(", ") + t("isp.and") + parts.at(-1) : parts[0];
  return t(gw.sent ? "isp.lead" : "isp.lead_nogw", { parts: joined, ok: gw.ok, sent: gw.sent });
}

function calendar(d) {
  return h("figure", { class: "isp-cal" },
    h("ol", {}, d.days.map(x => {
      const cell = h("li", { class: x.events ? "ev" : null, title: day(x.start_ms) },
        h("span", { class: "recd" }), h("b", {}, new Date(x.start_ms).getDate()));
      cell.querySelector(".recd").style.height = `${Math.round(x.recorded * 100)}%`;
      return cell;
    })),
    h("figcaption", {}, h("span", { class: "key recd" }), t("isp.cal.rec"), h("span", { class: "key ev" }), t("isp.cal.event")));
}

function row(e) {
  const r = e.router;
  const beyond = e.kind === "lossy" ? [bar(e.loss, "bad"), t("isp.beyond.loss", { pct: pct(e.loss) })]
    : e.beyond ? [bar(1 - e.beyond.ans / e.beyond.sent, "bad"), t("isp.beyond.ans", e.beyond)]
    : [t(`isp.kind.${e.kind}`)];
  return h("tr", {},
    h("td", { class: "when" }, stamp(e.start_ms)),
    h("td", { class: "len" }, dur(e.dur_s)),
    h("td", { class: "side" }, r ? [bar(r.ok / r.sent, "good"), t("isp.router", r)] : h("span", { class: "faint" }, t("isp.na"))),
    h("td", { class: "side" }, h("strong", {}, t(`isp.kind.${e.kind}`)), h("br"), beyond, e.unsure ? [h("br"), h("span", { class: "faint" }, t("isp.unsure"))] : null));
}

export async function mount(main, { refresh }) {
  let d, version = "";
  try {
    d = await api("/api/isp-report?format=json");
    version = (await api("/api/status").catch(() => ({}))).version || "";
  } catch (e) { main.replaceChildren(errorPanel(e, refresh)); return; }
  const text = h("button", { type: "button", class: "btn", onclick: async () => {
    let body;
    try { body = await api(`/api/isp-report?lang=${document.documentElement.lang}`); }
    catch (e) { toast(t("error.load", { what: t("isp.title"), code: e.code || "?" })); return; }
    const a = h("a", { href: URL.createObjectURL(new Blob([body], { type: "text/plain" })), download: "whydrop-isp-report.txt" });
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  } }, t("isp.text"));
  main.replaceChildren(h("article", { class: "isp" },
    h("header", { class: "isp-head" },
      h("h1", {}, t("isp.title")),
      h("div", { class: "row noprint" }, h("button", { type: "button", class: "btn primary", onclick: () => print() }, t("isp.print")), text)),
    h("p", { class: "isp-period" }, t("isp.period", { from: day(d.from_ms), to: day(d.to_ms), h: d.recorded_h, zone: zone() })),
    h("p", { class: "isp-lead" }, lead(d)),
    calendar(d),
    d.events.length ? h("table", { class: "isp-table" },
      h("thead", {}, h("tr", {}, ["when", "len", "router", "beyond"].map(c => h("th", { scope: "col" }, t(`isp.col.${c}`))))),
      h("tbody", {}, d.events.map(row))) : null,
    d.home || d.tests ? h("p", { class: "isp-note" }, t("isp.excluded", { home: d.home, tests: d.tests })) : null,
    h("p", { class: "isp-note" }, t("isp.method")),
    h("p", { class: "isp-note faint" }, t("isp.made", { v: version }))));
}
