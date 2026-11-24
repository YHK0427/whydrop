// Drop detail (#/drop/<id>): cause, next step, evidence, copy/export (UI design doc §5.2).
import { lanes, series } from "../components/lanes.js";
import { pathDiagram } from "../components/path.js";
import { strip } from "../components/strip.js";
import { api, dur, errorPanel, h, parseIncident, segWord, startMs, STATIC, t, toast, token, when } from "../lib.js";

const ORDER = ["host_net", "wifi", "lan", "line", "dns"];
const REPO_ISSUES = "https://github.com/YHK0427/whydrop/issues/new";

async function copyText(text) {
  try { if (navigator.clipboard) { await navigator.clipboard.writeText(text); return true; } } catch { /* fall through */ }
  const ta = h("textarea", { readonly: true, class: "sr" }, text);
  document.body.append(ta); ta.select();
  let ok = false;
  try { ok = document.execCommand("copy"); } catch { ok = false; }
  ta.remove();
  return ok;
}

function showText(main, text) {
  const box = h("textarea", { readonly: true, rows: 6, class: "copybox", "aria-label": t("drop.copy") }, text);
  main.querySelector(".copybox")?.remove();
  main.querySelector(".row")?.after(box);
  box.focus(); box.select();
}

const word = (v) => { const k = `evv.${v}`, w = t(k); return w === k ? String(v) : w; };   // "upload" → "업로드"; codes stay

// The measurements behind a verdict, worded from i18n ("fact.*", "ruled.*"); older drops have none.
export function whyLine(kind, x) {
  const na = t("why.na"), v = (y) => (y == null ? na : y);
  const vals = Object.fromEntries(Object.entries(x).map(([k, y]) => [k, v(y)]));
  if (x.segs) vals.segs = x.segs.map(segWord).filter((w, i, a) => a.indexOf(w) === i).join(", ") || na;
  if (x.classes) vals.classes = x.classes.map(segWord).join(", ");
  if (kind === "fact" && x.k === "tcp") vals.rst = t(x.rst ? "why.rst" : "why.norst");
  return t(`${kind}.${x.k}`, vals);
}
const whyPanel = (d) => (d.facts.length ? [h("section", { class: "panel why" }, h("h2", {}, t("why.title")),
  h("div", { class: "split" },
    h("div", {}, h("h3", {}, t("why.seen")), h("ul", { class: "why-list" }, d.facts.map((x) => h("li", { class: "seen" }, whyLine("fact", x))))),
    d.ruled.length ? h("div", {}, h("h3", {}, t("why.ruled")), h("ul", { class: "why-list" }, d.ruled.map((x) => h("li", { class: "ruled" }, whyLine("ruled", x))))) : null))]
  : []);   // an array: replaceChildren(null) would print "null"

function frozenPath(d, link) {
  const down = new Set(d.home ? ["wifi"] : d.raw.map(s => (s.startsWith("dns") ? "dns" : s === "link" ? "wifi" : s)));
  const first = d.slow ? -1 : ORDER.findIndex(s => down.has(s));   // a slow hop doesn't hide the ones after it
  return ORDER.map((k, i) => ({ key: k, label: k === "wifi" && link === "wired" ? t("seg.link") : t(`seg.${k}`),
    ui: down.has(k) ? (d.slow ? "unstable" : "down") : first >= 0 && i > first ? "not_checked" : "ok" }));
}

async function download(path, name) {
  const headers = token() ? { Authorization: `Bearer ${token()}` } : {};
  const r = await fetch(path, { headers });
  if (!r.ok) { toast(t("error.load", { what: t("what.bugreport"), code: r.status })); return; }
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
  const cleanup = [];   // this mount's own: a later mount of the same page never shares it
  let raw, st, ann;
  try {
    [raw, st] = await Promise.all([api(`/api/incidents/${id}`), api("/api/status")]);
  } catch (e) { main.replaceChildren(errorPanel(e, refresh)); return; }
  const d = parseIncident(raw);
  const from = d.start - 60000, to = (d.end || Date.now()) + 60000;
  let samples, events, ringRows;
  try {
    [samples, events, ringRows, ann] = await Promise.all([
      api(`/api/chart?from=${from}&to=${to}&step=1&incident=${id}`), api(`/api/events?from=${from}&to=${to}&incident=${id}`),
      api(`/api/incidents/${id}/strip`).catch(() => []), api(`/api/annotations?from=${from}&to=${to}&incident=${id}`).catch(() => [])]);
  } catch (e) { main.replaceChildren(errorPanel(e, refresh)); return; }

  const durS = d.end ? (d.end - d.start) / 1000 : (Date.now() - d.start) / 1000;
  const causeText = d.facts.length ? d.label.replace(/\s*\((likely|추정)\)$/, "") : d.label;   // the measurements below say how it was decided
  const headline = d.segs.length ? t(d.slow ? "drop.headline_slow" : "drop.headline", { seg: d.segs[0], dur: dur(durS), cause: causeText })
    : t("drop.headline_point", { cause: causeText });
  const label = ann.find(a => a.label === "reproduced" || a.label === "injected" || a.label === "user-test");

  const actions = h("div", { class: "row" },
    h("button", { class: "btn", type: "button", onclick: async () => {
      let text;
      try { text = await api(`/api/incidents/${id}/summary?lang=${document.documentElement.lang}`); }
      catch (e) { toast(t("error.load", { what: t("what.summary"), code: e.code || "?" })); return; }
      if (await copyText(text)) toast(t("drop.copied"));
      else showText(main, text);   // http://<LAN IP> is not a secure context: no clipboard API there
    } }, t("drop.copy")),
    STATIC ? null : h("button", { class: "btn", type: "button", onclick: () => download(`/api/export/bugreport/${id}`, `whydrop-bugreport-${id}.json`) },
      t("drop.export_json")),
    h("button", { class: "btn", type: "button", onclick: () => card(d, headline) }, t("drop.card")),
    h("a", { class: "btn", target: "_blank", rel: "noopener noreferrer",
      href: `${REPO_ISSUES}?${new URLSearchParams({ title: `Wrong diagnosis: rule ${d.rule}`,
        body: `Rule ${d.rule}, ${Math.round(durS)} s.\n\nWhat really happened:\n\n(Attach the bug report JSON from "${t("drop.export_json")}".)` })}` },
      t("drop.wrong")));

  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);   // cause_X repeats the incident's own X
  const evRows = Object.entries(d.evidence).filter(([k, v]) => !["label", "next_step", "protocol", "protocol_ko", "events", "cause_where", "facts", "ruled_out"].includes(k)
    && !(k.startsWith("cause_") && same(d.evidence[k.slice(6)], v)));
  const lanesEl = lanes(series(samples, st?.mode || "basic"), { stepS: samples.step_s, mode: st?.mode || "basic", baseline: "ready",
    events: events.filter(e => e.kind === "rst") });
  cleanup.push(() => lanesEl.cleanup());

  main.replaceChildren(
    h("section", { class: "panel" },
      h("p", {}, h("a", { href: "#/drops" }, t("drop.back"))),
      label ? h("p", { class: "labelbanner" }, t(`label.${label.label}`)) : null,
      h("h1", { class: "headline" }, headline),
      h("p", { class: "when" }, `${when(d.start)}`, " ", h("span", { class: "faint" }, t("drop.rule", { rule: d.rule })), " ",
        h("span", { class: "faint" }, d.final ? t("drop.final") : t("drop.settling")),
        d.facts.length ? [" ", h("a", { href: "#why", onclick: (e) => { e.preventDefault(); main.querySelector(".why")?.scrollIntoView({ behavior: "smooth" }); } },
          t("why.count", { n: d.facts.length }))] : null),
      actions,
      pathDiagram(frozenPath(d, st?.link), { frozen: true, vertical: window.matchMedia("(max-width: 640px)").matches })),
    ...whyPanel(d),
    h("section", { class: "panel" }, h("h2", {}, t("drop.next")), h("p", { class: "protocol" }, d.next || "–")),
    h("section", { class: "panel" }, h("h2", {}, t("drop.timeline")), h("h3", {}, t("drop.strip")), strip(ringRows), lanesEl),
    ...(d.protocol ? [h("section", { class: "panel" }, h("h2", {}, t("drop.protocol")), h("p", { class: "protocol" }, d.protocol))] : []),
    h("section", { class: "panel split" },
      h("div", {}, h("h2", {}, t("drop.evidence")), evRows.length ? h("dl", { class: "kv" },
        evRows.flatMap(([k, v]) => [h("dt", {}, t(`ev.${k}`) === `ev.${k}` ? k : t(`ev.${k}`)),
          h("dd", {}, Array.isArray(v) ? v.map(word).join(", ") || "–" : word(v))])) : h("p", { class: "faint" }, "–")),
      h("div", {}, h("h2", {}, t("drop.history")),
        h("p", {}, d.changed ? t("drop.changed", { rule: d.provisional || "?" }) : t("drop.unchanged")),
        h("h2", {}, t("drop.annotations")), ann.length ? h("ul", { class: "drops" }, ann.map(a => h("li", {},
          h("span", { class: "what" }, t(`label.${a.label}`)), " ", h("span", { class: "faint" }, when(startMs(a)))))) : h("p", { class: "faint" }, "–"))));
  return () => cleanup.forEach(f => f());
}
