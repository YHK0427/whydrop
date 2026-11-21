// My network (#/network): what is being watched, what was excluded and why, findings, availability, heatmap
// (UI design doc §5.5).
import { api, dur, errorPanel, h, parseIncident, t } from "../lib.js";

function heatmap(drops) {
  const grid = Array.from({ length: 7 }, () => Array(24).fill(0));
  for (const d of drops) { const x = new Date(d.start); grid[(x.getDay() + 6) % 7][x.getHours()] += 1; }
  const max = Math.max(1, ...grid.flat());
  const days = Array.from({ length: 7 }, (_, i) => new Date(2024, 0, 1 + i).toLocaleDateString(document.documentElement.lang, { weekday: "short" }));
  const el = h("div", { class: "heat", role: "table", "aria-label": t("net.heatmap") }, h("span"),
    ...Array.from({ length: 24 }, (_, i) => h("span", {}, i % 6 === 0 ? String(i) : "")));
  grid.forEach((row, di) => {
    el.append(h("span", {}, days[di]));
    row.forEach((n, hi) => {
      const cell = h("i", { title: `${days[di]} ${hi}:00 — ${n}` });
      if (n) cell.style.background = `color-mix(in srgb, var(--up) ${Math.round(20 + 80 * n / max)}%, var(--surface))`;
      el.append(cell);
    });
  });
  return el;
}

export async function mount(main, { refresh }) {
  let st, sc, findings, incs;
  try {
    [st, sc, findings, incs] = await Promise.all([api("/api/status"), api("/api/selfcheck"), api("/api/findings"),
      api(`/api/incidents?from=${Date.now() - 90 * 86400000}`)]);
  } catch (e) { main.replaceChildren(errorPanel(e, refresh)); return; }
  const check = sc[0] ? (sc[0].result_json ? JSON.parse(sc[0].result_json) : sc[0]) : {};
  const excluded = check.excluded && typeof check.excluded === "object" ? Object.entries(check.excluded) : [];
  const m = st.month || {};
  const open = findings.filter(f => (f.end_ms ?? f.end_s) == null);
  main.replaceChildren(
    h("section", { class: "panel" }, h("h1", { class: "headline" }, t("net.title")),
      h("dl", { class: "kv" },
        h("dt", {}, t("net.mode")), h("dd", {}, t(`net.mode.${st.mode || "basic"}`)),
        h("dt", {}, t("net.availability")), h("dd", {}, t("net.availability.value", { pct: m.availability ?? "–" }), " ",
          h("span", { class: "faint" }, t(m.drops === 1 ? "net.availability.sub_one" : "net.availability.sub",
            { drops: m.drops ?? 0, dur: dur(m.down_s || 0) }))))),
    h("section", { class: "panel" }, h("h2", {}, t("net.excluded")), excluded.length
      ? h("ul", { class: "drops" }, excluded.map(([pair, why]) => h("li", {}, h("span", { class: "what" }, pair), ": ", why)))
      : h("p", { class: "faint" }, typeof check.excluded === "number" ? String(check.excluded) : t("net.none_excluded"))),
    h("section", { class: "panel" }, h("h2", {}, t("net.findings")), open.length
      ? h("ul", { class: "drops" }, open.map(f => h("li", {}, f.kind))) : h("p", { class: "faint" }, t("net.none_findings"))),
    h("section", { class: "panel" }, h("h2", {}, t("net.heatmap")), heatmap(incs.map(parseIncident))));
}
