// Shared helpers: i18n with Korean particles, API access with the token, time formatting, DOM building.
const store = (() => { try { return window.sessionStorage; } catch { return null; } })();
const prefs = (() => { try { return window.localStorage; } catch { return null; } })();

export const params = new URLSearchParams(location.search);
export const isPublic = params.get("public") === "1";

// ---------- token: moved from ?token= into sessionStorage, then stripped from the URL (spec §8) ----------
(() => {
  const t = params.get("token");
  if (t) {
    store?.setItem("whydrop.token", t);
    params.delete("token");
    const q = params.toString();
    history.replaceState(null, "", location.pathname + (q ? "?" + q : "") + location.hash);
  }
})();
export const token = () => store?.getItem("whydrop.token") || null;

// ---------- i18n ----------
let dict = {};
export let lang = prefs?.getItem("whydrop.lang") || ((navigator.language || "en").startsWith("ko") ? "ko" : "en");

export async function loadLang(l) {
  lang = l;
  prefs?.setItem("whydrop.lang", l);
  document.documentElement.lang = l;
  dict = await (await fetch(`i18n/${l}.json`)).json();
  causes = l === "ko" ? await (await fetch("i18n/causes.ko.json")).json() : {};
}

let causes = {};
export const cause = (text) => causes[text] ?? text;   // server texts are English; the UI translates them

function josa(word, pair) {           // 이가 / 을를 / 은는 / 과와 by the final consonant
  const c = String(word).trim().slice(-1).charCodeAt(0);
  const has = c >= 0xac00 && c <= 0xd7a3 ? (c - 0xac00) % 28 !== 0 : /[0-9lmnLMN]$/.test(String(word));
  return word + (has ? pair[0] : pair[1]);
}

export function t(key, vars = {}) {
  const s = dict[key] ?? key;
  return s.replace(/\{(\w+)(?::(\S\S))?\}/g, (_, k, j) => {
    const v = vars[k] ?? "";
    return j ? josa(v, j) : v;
  });
}

// ---------- API ----------
export class ApiError extends Error { constructor(path, code) { super(`${path} ${code}`); this.path = path; this.code = code; } }

export async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (token()) headers.Authorization = `Bearer ${token()}`;
  if (opts.method && opts.method !== "GET") headers["X-Whydrop"] = "1";
  if (opts.json !== undefined) { headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(opts.json); }
  const sep = path.includes("?") ? "&" : "?";
  const url = isPublic && !path.includes("public=") ? `${path}${sep}public=1` : path;
  const r = await fetch(url, { ...opts, headers });
  if (!r.ok) throw new ApiError(path, r.status);
  const ct = r.headers.get("content-type") || "";
  return ct.includes("json") ? r.json() : r.text();
}

// ---------- time ----------
const tz = () => Intl.DateTimeFormat().resolvedOptions().timeZone;
const tzShort = () => new Intl.DateTimeFormat(lang, { timeZoneName: "short" }).formatToParts(new Date())
  .find(p => p.type === "timeZoneName")?.value || "";

export function when(ms, nowMs = Date.now()) {
  if (isPublic) return dur(Math.max(0, (nowMs - ms) / 1000)) + (lang === "ko" ? " 전" : " ago");
  const d = new Date(ms), now = new Date(nowMs);
  const tm = d.toLocaleTimeString(lang, { hour: "2-digit", minute: "2-digit", hour12: false });
  const day = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((day(now) - day(d)) / 86400000);
  const s = diff === 0 ? t("time.today", { t: tm }) : diff === 1 ? t("time.yesterday", { t: tm })
    : t("time.date", { d: d.toLocaleDateString(lang, { month: "short", day: "numeric" }), t: tm });
  return `${s} (${tzShort()})`;
}

export function clock(ms) {
  return new Date(ms).toLocaleTimeString(lang, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

export function dur(sec) {
  sec = Math.round(sec);
  if (sec < 120) return t("unit.s", { n: sec });
  if (sec < 7200) return t("unit.min", { n: Math.round(sec / 60) });
  if (sec < 172800) return t("unit.h", { n: Math.round(sec / 3600) });
  return t("unit.d", { n: Math.round(sec / 86400) });
}

// public rows carry seconds relative to now; private rows carry epoch ms
export const startMs = (r) => r.start_ms ?? (r.start_s != null ? Date.now() + r.start_s * 1000 : null);
export const endMs = (r) => r.end_ms ?? (r.end_s != null ? Date.now() + r.end_s * 1000 : null);
export const tsMs = (r) => r.ts_ms ?? (r.t_s != null ? Date.now() + r.t_s * 1000 : null);

// ---------- incidents in UI words ----------
export function segWord(s) {
  if (s.startsWith("dns")) return t("seg.dns");
  return t(`seg.${s}`);
}
export function parseIncident(r) {
  const tags = r.tags_json ? JSON.parse(r.tags_json) : { segments: r.segments || [], tags: r.tags || [], point: r.point };
  const ev = r.evidence_json ? JSON.parse(r.evidence_json) : (r.evidence || {});
  const start = startMs(r), end = endMs(r);
  const segs = [...new Set((tags.segments || []).map(segWord))];
  return { id: r.id, start, end, open: end == null, segs, raw: tags.segments || [], point: tags.point, tags: tags.tags || [],
           chain: tags.chain || [], label: cause(ev.label || ""), next: cause(ev.next_step || ""), protocol: ev.protocol || "",
           rule: r.cause_final || r.primary_cause || r.cause, final: r.cause_final != null || r.final,
           changed: !!r.cause_changed, provisional: ev.provisional, evidence: ev };
}

// ---------- DOM ----------
export function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) el.append(k instanceof Node ? k : String(k));
  return el;
}
export const svg = (tag, attrs = {}, ...kids) => {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) if (v != null) el.setAttribute(k, v);
  for (const k of kids.flat()) if (k != null) el.append(k instanceof Node ? k : String(k));
  return el;
};

export function toast(msg) {
  const el = h("div", { class: "toast", role: "status" }, msg);
  document.body.append(el);
  setTimeout(() => el.remove(), 2200);
}

export function errorPanel(err, retry) {
  if (err instanceof ApiError && err.code === 401) return h("p", { class: "banner bad" }, t("error.token"));
  return h("div", { class: "banner bad" },
    h("p", {}, t("error.load", { what: err.path || "data", code: err.code || "?" })),
    h("button", { class: "btn", onclick: retry }, t("error.retry")),
    h("p", { class: "faint" }, err.path || ""));
}

export const prefsGet = (k) => prefs?.getItem(k);
export const prefsSet = (k, v) => prefs?.setItem(k, v);
export { tz };
