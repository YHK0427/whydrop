// Protocol (#/protocol): recent WD/WT packets as hex with each field named as in docs/protocol (UI design doc §5.4).
import { live } from "../app.js";
import { STATIC, api, clock, errorPanel, h, lang, t, tsMs } from "../lib.js";

// WD (44 B): !2sBBIIQIIII + hmac8 — field names as in docs/protocol
const WD = [["magic", 2], ["version", 1], ["type", 1], ["session_id", 4], ["seq", 4], ["t_send_ns", 8], ["recv_count", 4],
  ["epoch", 4], ["rx_bitmap", 4], ["arg", 4], ["hmac", 8]];
let paused = false;

function hexdump(hex) {
  const bytes = hex.match(/../g) || [];
  const out = h("div", { class: "hex" });
  let i = 0;
  for (const [name, n] of WD) {
    if (i >= bytes.length) break;
    out.append(h("span", { class: "f", title: name }, bytes.slice(i, i + n).join(" ")), " ", h("span", { class: "faint" }, name), "\n");
    i += n;
  }
  return out;
}

export async function mount(main, { refresh }) {
  if (STATIC) {   // the demo is a snapshot of incidents: no packet capture in it, so no table and nothing to pause
    const doc = `https://github.com/YHK0427/whydrop/blob/main/docs/protocol${lang === "ko" ? ".ko" : ""}.md`;
    main.replaceChildren(h("section", { class: "panel" }, h("h1", { class: "headline" }, t("proto.title")),
      h("p", {}, t("proto.static"), " ", h("a", { href: doc, target: "_blank", rel: "noopener noreferrer" }, t("proto.doc")))));
    return () => {};
  }
  const cleanup = [];   // this mount's own: a later mount of the same page never shares it
  let packets;
  try { packets = await api("/api/packets"); } catch (e) { main.replaceChildren(errorPanel(e, refresh)); return; }   // not "no packets yet"
  const body = h("tbody"), detail = h("div");
  const draw = () => {
    body.replaceChildren(...packets.slice(-200).reverse().map(p => {
      const tr = h("tr", { tabindex: "0" }, h("td", {}, clock(tsMs(p))), h("td", {}, p.dir), h("td", {}, p.type), h("td", {}, p.seq),
        h("td", {}, `${p.size} B`));
      const open = () => detail.replaceChildren(h("h3", {}, `${p.type} seq ${p.seq}`), hexdump(p.hex || ""));
      tr.addEventListener("click", open);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
      return tr;
    }));
    empty.hidden = packets.length > 0;
  };
  const empty = h("p", { class: "empty" }, t("proto.none"));
  const pause = h("button", { class: "btn", type: "button", "aria-pressed": "false", onclick: () => {
    paused = !paused; pause.textContent = paused ? t("proto.resume") : t("proto.pause"); pause.setAttribute("aria-pressed", String(paused));
  } }, t("proto.pause"));
  main.replaceChildren(h("section", { class: "panel" }, h("h1", { class: "headline" }, t("proto.title")), pause, empty,
    h("table", { class: "data" }, h("thead", {}, h("tr", {}, ["time", "dir", "type", "seq", "size"].map(c => h("th", { scope: "col" }, t(`proto.col.${c}`))))), body)),
    h("section", { class: "panel" }, detail));
  draw();
  const poll = setInterval(async () => {
    if (paused || body.contains(document.activeElement)) return;   // never yank the row someone is on
    packets = await api("/api/packets").catch(() => packets); draw();
  }, 2000);
  cleanup.push(() => clearInterval(poll));
  return () => cleanup.forEach(f => f());
}
