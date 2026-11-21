// Packet strip: one 8 px square per packet, 10 per second (UI design doc §6). Received packets are neutral so the
// losses are what you see; up = --up, down = --down, unknown = hatched, late = hollow.
import { h, t } from "../lib.js";

export function strip(rows) {
  if (!rows.length) return h("p", { class: "faint" }, t("drop.strip.none"));
  const cls = (r) => r.dir === "ok" ? "" : r.dir === "late" ? "late" : r.dir === "up" ? "up" : r.dir === "down" ? "down"
    : r.dir === "local" ? "local" : "unknown";
  const el = h("div", { class: "strip", role: "img", "aria-label": t("drop.strip") });
  for (const r of rows) {
    el.append(h("i", { class: cls(r), title: `seq ${r.seq}: ${r.dir}` }));
  }
  return h("div", {},
    h("span", { class: "legend" },
      h("span", {}, h("i", { class: "sw up" }), t("drop.strip.legend_up")),
      h("span", {}, h("i", { class: "sw down" }), t("drop.strip.legend_down")),
      h("span", {}, t("drop.strip.legend_unknown")), h("span", {}, t("drop.strip.legend_late"))),
    el);
}
