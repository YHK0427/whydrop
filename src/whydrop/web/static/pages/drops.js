// Drops (#/drops): every drop with filters by cause and segment (UI design doc §3).
import { api, dur, errorPanel, h, parseIncident, t, when } from "../lib.js";

export async function mount(main, { refresh }) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const segment = q.get("segment");
  let rows;
  try { rows = (await api(`/api/incidents?from=${Date.now() - 90 * 86400000}`)).map(parseIncident); }
  catch (e) { main.replaceChildren(errorPanel(e, refresh)); return; }
  rows.sort((a, b) => b.start - a.start);
  const causes = [...new Set(rows.map(r => r.label).filter(Boolean))];
  const select = h("select", { "aria-label": t("drops.col.cause") }, h("option", { value: "" }, t("drops.filter.all")),
    causes.map(c => h("option", { value: c }, c)));
  const body = h("tbody");
  const draw = () => {
    const shown = rows.filter(r => (!select.value || r.label === select.value) && (!segment || r.raw.includes(segment)
      || (segment === "dns" && r.raw.some(s => s.startsWith("dns")))));
    body.replaceChildren(...shown.map(r => h("tr", {},
      h("td", {}, h("a", { href: `#/drop/${r.id}` }, when(r.start))),
      h("td", {}, r.point ? "–" : r.open ? "…" : dur((r.end - r.start) / 1000)),
      h("td", {}, r.segs.join(", ") || "–"),
      h("td", {}, r.label))));
    empty.hidden = shown.length > 0;
  };
  const empty = h("p", { class: "empty" }, t("drops.none"));
  select.addEventListener("change", draw);
  main.replaceChildren(h("section", { class: "panel" }, h("h1", { class: "headline" }, t("drops.title")),
    h("div", { class: "row" }, select, segment ? h("span", { class: "faint" }, `${t("drops.col.where")}: ${segment}`) : null),
    h("table", { class: "data drops-table" }, h("thead", {}, h("tr", {}, ["when", "length", "where", "cause"].map(c =>
      h("th", { scope: "col" }, t(`drops.col.${c}`))))), body), empty));
  draw();
}
