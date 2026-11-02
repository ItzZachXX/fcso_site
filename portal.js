// Deputy portal (standalone, no server).
// The roster and documents live in content.js, encrypted with AES-256-GCM.
// The deputy code unlocks the deputy copy; the command code unlocks the full copy.
// A wrong code can't decrypt anything, and the codes themselves are never stored in the site's files.

const RANKS = [
  ["Sheriff", "High Command"], ["Chief Deputy", "High Command"], ["Major", "High Command"],
  ["Commander", "Department Command Staff"], ["Captain", "Department Command Staff"], ["Lieutenant", "Department Command Staff"],
  ["Sergeant", "Supervisory Board"],
  ["Corporal", "Patrol Staff"], ["Master Deputy", "Patrol Staff"], ["Deputy First Class", "Patrol Staff"], ["Deputy", "Patrol Staff"], ["Probationary Deputy", "Patrol Staff"],
  ["Cadet", "Cadets"],
].map(([name, tier]) => ({ name, tier }));
const DIVISIONS = ["Special Operations Division", "Traffic Services Division", "Criminal Investigations Unit", "Internal Affairs Division", "Field Training Division", "Public Relations Division"];
const CATEGORIES = ["General", "Standard Operating Procedures", "Training", "Division"];
const STATUSES = ["Active", "Leave of Absence", "Reduced Activity", "Suspended", "Probationary"];
const meta = { ranks: RANKS, divisions: DIVISIONS, categories: CATEGORIES, statuses: STATUSES };

const SESSION_KEY = "fcso_portal";
const DRAFT_KEY = "fcso_draft";

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const uid = () => [...crypto.getRandomValues(new Uint8Array(6))].map((b) => b.toString(16).padStart(2, "0")).join("");

let session = null; // { role, name, code }
let state = null; // admin: { roster, docs, announcements, codes }   deputy: { roster, docs }
let pendingCodes = null; // new codes waiting to be published
let dirty = false;
let currentDoc = null;
const isAdmin = () => session?.role === "admin";

// ---------- crypto ----------
const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function keyFor(code, salt, iterations) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(code), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function seal(obj, code) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const iterations = 250000;
  const key = await keyFor(code, salt, iterations);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(obj)));
  return { salt: toB64(salt), iv: toB64(iv), iterations, ct: toB64(ct) };
}
async function unseal(box, code) {
  const key = await keyFor(code, fromB64(box.salt), box.iterations);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(box.iv) }, key, fromB64(box.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

async function unlock(code) {
  const data = window.FCSO_DATA;
  if (!data) throw new Error("The portal content file (content.js) is missing. Ask command to upload it.");
  try {
    return { role: "admin", data: await unseal(data.admin, code) };
  } catch {}
  try {
    return { role: "deputy", data: await unseal(data.deputy, code) };
  } catch {}
  const groups = await unlockGroups(code);
  if (groups.length) return { role: "division", data: { roster: [], docs: [] }, groups };
  throw new Error("That code isn't valid.");
}

// Division documents with a code are published in groups, one per code. Returns the indexes and docs a code opens.
async function unlockGroups(code) {
  const opened = [];
  for (const [i, g] of (window.FCSO_DATA?.divisionDocs || []).entries()) {
    try {
      opened.push({ index: i, docs: (await unseal(g.box, code)).docs });
    } catch {}
  }
  return opened;
}

const lockedGroups = () =>
  (window.FCSO_DATA?.divisionDocs || []).map((g, index) => ({ ...g, index })).filter((g) => !session.unlocked.has(g.index));

function addUnlocked(groups) {
  for (const g of groups) {
    if (session.unlocked.has(g.index)) continue;
    session.unlocked.add(g.index);
    for (const d of g.docs) state.docs.push({ ...d, unlockedByCode: true });
  }
}

// ---------- ui helpers ----------
function toast(message, error = false) {
  const t = $("#toast");
  t.textContent = message;
  t.classList.toggle("error", error);
  t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("show"), 3200);
}
const fmtDate = (ts) => new Date(ts).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
const fmtDateTime = (ts) => new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });

// ---------- session ----------
function signOut(message) {
  session = null;
  state = null;
  dirty = false;
  try { sessionStorage.removeItem(SESSION_KEY); } catch {}
  document.body.classList.remove("locked");
  $("#app").hidden = true;
  $("#session").hidden = true;
  $("#draft-bar").hidden = true;
  $("#login").hidden = false;
  $("#login-error").textContent = message || "";
  history.replaceState(null, "", location.pathname);
}
$("#signout").addEventListener("click", () => {
  if (dirty && !confirm("You have unpublished changes. They stay saved in this browser, but nobody else will see them until you publish. Sign out anyway?")) return;
  signOut();
});

async function signIn(name, code, docCodes = []) {
  const { role, data, groups } = await unlock(code);
  session = { role, name, code, docCodes: [], unlocked: new Set() };
  state = data;
  state.roster ||= [];
  state.docs ||= [];
  if (role === "admin") {
    state.announcements ||= window.FCSO_PUBLIC?.announcements || [];
    state.codes ||= { admin: code, deputy: null };
    await loadDraft();
  } else {
    if (groups) addUnlocked(groups);
    // Re-open division documents unlocked earlier in this tab.
    for (const c of docCodes) {
      const g = await unlockGroups(c);
      if (g.length) { addUnlocked(g); session.docCodes.push(c); }
    }
  }
  rememberSession();
  startApp();
}

function rememberSession() {
  try { sessionStorage.setItem(SESSION_KEY, JSON.stringify({ name: session.name, code: session.code, docCodes: session.docCodes })); } catch {}
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = $("#login-name").value.trim();
  const code = $("#login-code").value.trim();
  const err = $("#login-error");
  if (!name) return (err.textContent = "Enter your name or callsign.");
  if (!code) return (err.textContent = "Enter your access code.");
  const btn = $("#login-btn");
  btn.disabled = true;
  btn.textContent = "Unlocking...";
  err.textContent = "";
  try {
    await signIn(name, code);
    $("#login-code").value = "";
  } catch (ex) {
    err.textContent = ex.message;
  } finally {
    btn.disabled = false;
    btn.textContent = "Sign in";
  }
});

function startApp() {
  $("#login").hidden = true;
  $("#app").hidden = false;
  $("#session").hidden = false;
  $("#who").textContent = session.name;
  const tag = $("#access");
  tag.textContent = { admin: "Command access", deputy: "Deputy access", division: "Document access" }[session.role];
  tag.classList.toggle("admin", isAdmin());
  $$("[data-admin]").forEach((el) => (el.hidden = !isAdmin()));
  $('#tabs a[data-tab="roster"]').hidden = session.role === "division";
  document.body.classList.toggle("locked", !isAdmin());
  $("#docs-sub").textContent = isAdmin()
    ? "Every document, including division documents. You can create and edit them."
    : session.role === "division"
      ? "The division documents your code unlocks. Documents are read-only."
      : "Department procedures, training material, and references. Locked division documents open with their own code. Documents are read-only.";
  fillSelects();
  updateDraftUi();
  route();
}

window.addEventListener("hashchange", route);
function route() {
  if (!session) return;
  let [tab, arg] = location.hash.replace("#", "").split("/");
  const tabs = isAdmin() ? ["roster", "docs", "announcements", "access", "publish"] : session.role === "division" ? ["docs"] : ["roster", "docs"];
  if (!tabs.includes(tab)) tab = tabs[0];
  $$(".view").forEach((v) => (v.hidden = v.id !== `view-${tab}`));
  $$("#tabs a").forEach((a) => (a.dataset.tab === tab ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  ({ roster: renderRoster, docs: () => showDocs(arg), announcements: renderAnnouncements, access: () => {}, publish: updateDraftUi })[tab]();
}

// ---------- drafts (command only; saved encrypted in this browser) ----------
// The draft key is derived once per sign-in, so each save is near-instant (no lost edits on a quick reload).
let draftKey = null;
async function saveDraft() {
  dirty = true;
  updateDraftUi();
  try {
    if (!draftKey || draftKey.code !== session.code) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      draftKey = { code: session.code, salt, iterations: 250000, key: await keyFor(session.code, salt, 250000) };
    }
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, draftKey.key, new TextEncoder().encode(JSON.stringify({ ...state, pendingCodes })));
    const box = { salt: toB64(draftKey.salt), iv: toB64(iv), iterations: draftKey.iterations, ct: toB64(ct) };
    localStorage.setItem(DRAFT_KEY, JSON.stringify({ base: window.FCSO_DATA?.updated || 0, at: Date.now(), box }));
  } catch {}
}

async function loadDraft() {
  let draft;
  try { draft = JSON.parse(localStorage.getItem(DRAFT_KEY)); } catch {}
  if (!draft) return;
  let data;
  try { data = await unseal(draft.box, session.code); } catch { return; } // made with another code
  const published = window.FCSO_DATA?.updated || 0;
  if (draft.base !== published && !confirm(`You have unpublished changes from ${fmtDateTime(draft.at)}, but the live site has been published since then. Load your unpublished changes anyway? (Cancel keeps the live version.)`)) {
    localStorage.removeItem(DRAFT_KEY);
    return;
  }
  pendingCodes = data.pendingCodes || null;
  delete data.pendingCodes;
  state = data;
  dirty = true;
  toast(`Loaded your unpublished changes from ${fmtDateTime(draft.at)}.`);
}

function updateDraftUi() {
  if (!isAdmin()) return;
  $("#draft-bar").hidden = !dirty || location.hash === "#publish";
  $("#publish-state").textContent = dirty ? "You have unpublished changes" : "No unpublished changes";
  $("#publish-detail").textContent = dirty
    ? `Download the new content file and upload it to GitHub to put your changes live.${pendingCodes ? " This includes your new access codes." : ""}`
    : "Everything here matches the live site. You can still download the current file if you need a copy.";
  $("#publish-discard").hidden = !dirty;
}

// ---------- selects ----------
function options(el, values, keepFirst = true) {
  const first = keepFirst ? el.options[0]?.outerHTML || "" : "";
  el.innerHTML = first + values.map((v) => `<option>${esc(v)}</option>`).join("");
}
function fillSelects() {
  options($("#roster-rank"), meta.ranks.map((r) => r.name));
  options($("#roster-division"), meta.divisions);
  options($("#roster-status"), meta.statuses);
  options($("#r-rank"), meta.ranks.map((r) => r.name));
  options($("#r-division"), meta.divisions);
  options($("#r-status"), meta.statuses, false);
  options($("#d-category"), meta.categories, false);
  options($("#d-division"), meta.divisions, false);
}

// ---------- roster ----------
const statusClass = (s) => ({ "Leave of Absence": "leave", "Reduced Activity": "reduced", Suspended: "suspended", Probationary: "probationary" })[s] || "";
const rankOrder = (name) => { const i = RANKS.findIndex((r) => r.name === name); return i === -1 ? 999 : i; };
const sortedRoster = () => [...state.roster].sort((a, b) => rankOrder(a.rank) - rankOrder(b.rank) || a.name.localeCompare(b.name));

function renderRoster() {
  const roster = sortedRoster();
  const q = $("#roster-search").value.trim().toLowerCase();
  const rank = $("#roster-rank").value;
  const division = $("#roster-division").value;
  const status = $("#roster-status").value;
  const list = roster.filter(
    (r) =>
      (!q || r.name.toLowerCase().includes(q) || (r.callsign || "").toLowerCase().includes(q)) &&
      (!rank || r.rank === rank) && (!division || r.division === division) && (!status || r.status === status)
  );
  const cols = isAdmin() ? 7 : 6;
  if (!roster.length) {
    $("#roster-body").innerHTML = `<tr><td colspan="${cols}" class="empty">${isAdmin() ? "The roster is empty. Add your first member with Add member." : "The roster hasn't been filled in yet."}</td></tr>`;
  } else if (!list.length) {
    $("#roster-body").innerHTML = `<tr><td colspan="${cols}" class="empty">No members match those filters.</td></tr>`;
  } else {
    $("#roster-body").innerHTML = list
      .map(
        (r) => `<tr>
          <td class="callsign">${esc(r.callsign) || "-"}</td>
          <td>${esc(r.name)}</td>
          <td>${esc(r.rank) || "-"}</td>
          <td>${esc(r.division) || "-"}</td>
          <td><span class="status ${statusClass(r.status)}">${esc(r.status)}</span></td>
          <td>${r.joined ? esc(fmtDate(r.joined + "T12:00:00")) : "-"}</td>
          ${isAdmin() ? `<td><button class="btn btn-quiet btn-sm" data-edit="${esc(r.id)}">Edit</button></td>` : ""}
        </tr>`
      )
      .join("");
  }
  $("#roster-count").textContent = roster.length ? `Showing ${list.length} of ${roster.length} members.` : "";
}
["#roster-search", "#roster-rank", "#roster-division", "#roster-status"].forEach((s) => $(s).addEventListener("input", renderRoster));

$("#roster-body").addEventListener("click", (e) => {
  const id = e.target.closest("[data-edit]")?.dataset.edit;
  if (id) openRosterEditor(state.roster.find((r) => r.id === id));
});
$("#roster-add").addEventListener("click", () => openRosterEditor(null));

let editingMember = null;
function openRosterEditor(r) {
  editingMember = r;
  $("#roster-dlg-title").textContent = r ? `Edit ${r.name}` : "Add member";
  $("#r-name").value = r?.name || "";
  $("#r-callsign").value = r?.callsign || "";
  $("#r-rank").value = r?.rank || "";
  $("#r-division").value = r?.division || "";
  $("#r-status").value = r?.status || "Active";
  $("#r-joined").value = r?.joined || new Date().toISOString().slice(0, 10);
  $("#r-discord").value = r?.discordId || "";
  $("#r-notes").value = r?.notes || "";
  $("#roster-error").textContent = "";
  $("#roster-delete").hidden = !r;
  $("#roster-dlg").showModal();
  $("#r-name").focus();
}

$("#roster-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const name = $("#r-name").value.trim();
  if (!name) return ($("#roster-error").textContent = "Enter the member's name.");
  const entry = {
    name: name.slice(0, 60),
    callsign: $("#r-callsign").value.trim().slice(0, 20),
    rank: $("#r-rank").value,
    division: $("#r-division").value,
    status: $("#r-status").value,
    joined: $("#r-joined").value,
    discordId: $("#r-discord").value.replace(/\D/g, ""),
    notes: $("#r-notes").value.trim().slice(0, 1000),
    updatedAt: Date.now(),
  };
  if (editingMember) Object.assign(editingMember, entry);
  else state.roster.push({ id: uid(), ...entry });
  $("#roster-dlg").close();
  toast(editingMember ? "Member saved. Publish to put it live." : "Member added. Publish to put it live.");
  saveDraft();
  renderRoster();
});

$("#roster-delete").addEventListener("click", () => {
  if (!editingMember || !confirm(`Remove ${editingMember.name} from the roster?`)) return;
  state.roster = state.roster.filter((r) => r !== editingMember);
  $("#roster-dlg").close();
  toast("Member removed. Publish to put it live.");
  saveDraft();
  renderRoster();
});

// ---------- markdown ----------
// Everything is escaped first, so no HTML from a document can run.
// Supports: # headings, **bold**, *italic*, `code`, [links](https://...), - lists, 1. lists, > quotes, tables, ---.
function inline(s) {
  return s
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[^*])\*([^*\s][^*]*)\*/g, "$1<em>$2</em>")
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
}
function render(md) {
  if (!md) return "";
  const lines = esc(md).replace(/\r/g, "").split("\n");
  const out = [];
  let para = [];
  const flush = () => { if (para.length) out.push(`<p>${para.map(inline).join("<br>")}</p>`); para = []; };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let m;
    if (!line.trim()) { flush(); continue; }
    if ((m = line.match(/^(#{1,4})\s+(.*)$/))) { flush(); const n = Math.min(m[1].length + 1, 4); out.push(`<h${n}>${inline(m[2])}</h${n}>`); continue; }
    if (/^\s*(-{3,}|\*{3,})\s*$/.test(line)) { flush(); out.push("<hr>"); continue; }
    if (/^\s*&gt;\s?/.test(line)) {
      flush(); const q = [];
      while (i < lines.length && /^\s*&gt;\s?/.test(lines[i])) q.push(inline(lines[i++].replace(/^\s*&gt;\s?/, "")));
      i--; out.push(`<blockquote>${q.join("<br>")}</blockquote>`); continue;
    }
    if (/^\s*([-*+]|\d+\.)\s+/.test(line)) {
      flush(); const ordered = /^\s*\d+\./.test(line); const items = [];
      while (i < lines.length && /^\s*([-*+]|\d+\.)\s+/.test(lines[i])) items.push(`<li>${inline(lines[i++].replace(/^\s*([-*+]|\d+\.)\s+/, ""))}</li>`);
      i--; out.push(`<${ordered ? "ol" : "ul"}>${items.join("")}</${ordered ? "ol" : "ul"}>`); continue;
    }
    if (/^\s*\|.*\|\s*$/.test(line) && /^\s*\|?\s*:?-{2,}/.test(lines[i + 1] || "")) {
      flush(); const cells = (l) => l.trim().replace(/^\||\|$/g, "").split("|").map((c) => inline(c.trim()));
      const head = cells(line); i += 2; const rows = [];
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) rows.push(cells(lines[i++]));
      i--; out.push(`<table><thead><tr>${head.map((c) => `<th>${c}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table>`); continue;
    }
    para.push(line);
  }
  flush();
  return out.join("\n");
}

// ---------- documents ----------
function showDocs(id) {
  renderDocList(id);
  if (id) openDoc(id);
  else showReaderEmpty();
}

function showReaderEmpty() {
  currentDoc = null;
  $("#reader").innerHTML = `<div class="empty">${state.docs.length ? "Pick a document from the list to read it." : isAdmin() ? "There are no documents yet. Create the first one with New document." : "No documents have been published yet."}</div>`;
}

function renderDocList(activeId) {
  const q = $("#doc-search").value.trim().toLowerCase();
  const list = [...state.docs].filter((d) => !q || d.title.toLowerCase().includes(q)).sort((a, b) => a.title.localeCompare(b.title));
  const groups = {};
  for (const d of list) {
    const key = d.category === "Division" ? `Division: ${d.division || "Unassigned"}` : d.category;
    (groups[key] ||= []).push(d);
  }
  // Locked division documents (deputies only): shown by division, opened with a document code.
  if (!isAdmin() && !q) {
    for (const g of lockedGroups()) {
      const key = `Division: ${g.divisions.join(", ")}`;
      (groups[key] ||= []).push({ locked: true, id: `locked-${g.index}`, title: `${g.count} locked document${g.count === 1 ? "" : "s"}` });
    }
  }
  const order = (k) => { const i = CATEGORIES.indexOf(k.startsWith("Division") ? "Division" : k); return i === -1 ? 99 : i; };
  const keys = Object.keys(groups).sort((a, b) => order(a) - order(b) || a.localeCompare(b));
  const link = (d) =>
    d.locked
      ? `<a class="locked" href="#docs/${d.id}" ${d.id === activeId ? 'aria-current="true"' : ""}><span>${esc(d.title)}</span><span class="lock-tag">Code needed</span></a>`
      : `<a href="#docs/${esc(d.id)}" ${d.id === activeId ? 'aria-current="true"' : ""}>${esc(d.title)}</a>`;
  $("#doc-groups").innerHTML = keys.length
    ? keys.map((k) => `<div class="doc-group"><h3>${esc(k)}</h3>${groups[k].map(link).join("")}</div>`).join("")
    : `<p class="empty">${q ? "No documents match that search." : "No documents yet."}</p>`;
}

function showUnlock(id) {
  currentDoc = null;
  $("#reader").innerHTML = `
    <form class="unlock" id="unlock-form" novalidate>
      <h2>Division document</h2>
      <p>This document is locked. Enter the document code you were given by your division or command.</p>
      <div class="field"><label for="unlock-code">Document code</label><input id="unlock-code" type="password" autocomplete="off" required></div>
      <p class="form-error" id="unlock-error" role="alert"></p>
      <button class="btn btn-primary" type="submit" id="unlock-btn">Unlock</button>
    </form>`;
  $("#unlock-code").focus();
  $("#unlock-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const code = $("#unlock-code").value.trim();
    if (!code) return ($("#unlock-error").textContent = "Enter the document code.");
    const btn = $("#unlock-btn");
    btn.disabled = true;
    btn.textContent = "Unlocking...";
    const opened = (await unlockGroups(code)).filter((g) => !session.unlocked.has(g.index));
    btn.disabled = false;
    btn.textContent = "Unlock";
    if (!opened.length) return ($("#unlock-error").textContent = "That code doesn't unlock any locked documents.");
    addUnlocked(opened);
    session.docCodes.push(code);
    rememberSession();
    const docs = opened.flatMap((g) => g.docs);
    toast(`Unlocked ${docs.length} document${docs.length === 1 ? "" : "s"}.`);
    location.hash = `docs/${docs[0].id}`;
  });
}
$("#doc-search").addEventListener("input", () => renderDocList(currentDoc?.id));

function watermark() {
  const text = `${session.name}  ${new Date().toLocaleDateString()}  FCSO`;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="320" height="180"><text x="10" y="110" transform="rotate(-24 160 90)" font-family="Arial" font-size="15" font-weight="700" fill="#141b3d">${esc(text)}</text></svg>`;
  return `<div class="watermark" style="background-image:url('data:image/svg+xml;utf8,${encodeURIComponent(svg)}')"></div>`;
}

function openDoc(id) {
  if (!isAdmin() && id.startsWith("locked-")) return showUnlock(id);
  const d = state.docs.find((x) => x.id === id);
  if (!d) {
    currentDoc = null;
    $("#reader").innerHTML = `<div class="empty">That document doesn't exist or you can't view it.</div>`;
    return;
  }
  currentDoc = d;
  $("#reader").innerHTML = `
    ${isAdmin() ? "" : watermark()}
    <div class="reader-meta">
      <span>${esc(d.category)}${d.division ? `: ${esc(d.division)}` : ""}. Updated ${esc(fmtDate(d.updatedAt))}${d.updatedBy ? ` by ${esc(d.updatedBy)}` : ""}.${
        isAdmin() && d.category === "Division" ? (d.code ? ` Document code: <span class="doc-code">${esc(d.code)}</span>` : " Command only (no document code).") : ""
      }</span>
      ${isAdmin() ? `<button class="btn btn-outline btn-sm" id="doc-edit">Edit document</button>` : ""}
    </div>
    <h1 class="doc-title">${esc(d.title)}</h1>
    <div class="prose">${render(d.body) || "<p><em>This document is empty.</em></p>"}</div>`;
  $("#doc-edit")?.addEventListener("click", () => openDocEditor(d));
}

let editingDoc = null;
function openDocEditor(d) {
  editingDoc = d;
  $("#doc-dlg-title").textContent = d ? "Edit document" : "New document";
  $("#d-title").value = d?.title || "";
  $("#d-category").value = d?.category || CATEGORIES[0];
  $("#d-division").value = d?.division || DIVISIONS[0];
  $("#d-body").value = d?.body || "";
  $("#d-code").value = d?.code || "";
  $("#doc-error").textContent = "";
  $("#doc-delete").hidden = !d;
  syncDivisionField();
  updatePreview();
  $("#doc-dlg").showModal();
  $("#d-title").focus();
}
function syncDivisionField() {
  const division = $("#d-category").value === "Division";
  $("#d-division-field").hidden = !division;
  $("#d-code-field").hidden = !division;
}
// Readable random code, e.g. "sod-k7mq-p2xd" (letters that can't be confused with each other).
$("#d-code-gen").addEventListener("click", () => {
  const abc = "abcdefghjkmnpqrstuvwxyz23456789";
  const part = () => [...crypto.getRandomValues(new Uint8Array(4))].map((b) => abc[b % abc.length]).join("");
  const prefix = $("#d-division").value.split(" ").filter((w) => /^[A-Z]/.test(w) && w !== "Division" && w !== "Unit").map((w) => w[0]).join("").toLowerCase() || "div";
  $("#d-code").value = `${prefix}-${part()}-${part()}`;
});
function updatePreview() { $("#d-preview").innerHTML = render($("#d-body").value) || "<p class='hint'>The preview shows here as you type.</p>"; }
$("#d-category").addEventListener("change", syncDivisionField);
$("#d-body").addEventListener("input", updatePreview);
$("#doc-new").addEventListener("click", () => openDocEditor(null));

$("#doc-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const title = $("#d-title").value.trim();
  if (!title) return ($("#doc-error").textContent = "Give the document a title.");
  const category = $("#d-category").value;
  const code = category === "Division" ? $("#d-code").value.trim() : "";
  if (code && code.length < 8) return ($("#doc-error").textContent = "Document codes must be at least 8 characters.");
  const codes = pendingCodes || state.codes;
  if (code && (code === codes.admin || code === codes.deputy)) return ($("#doc-error").textContent = "Use a different code from the deputy and command codes.");
  const fields = {
    title: title.slice(0, 150),
    category,
    division: category === "Division" ? $("#d-division").value : null,
    code: code || null,
    body: $("#d-body").value,
    updatedAt: Date.now(),
    updatedBy: session.name,
  };
  let doc = editingDoc;
  if (doc) Object.assign(doc, fields);
  else state.docs.push((doc = { id: uid(), ...fields }));
  $("#doc-dlg").close();
  toast(editingDoc ? "Document saved. Publish to put it live." : "Document created. Publish to put it live.");
  saveDraft();
  if (location.hash === `#docs/${doc.id}`) showDocs(doc.id);
  else location.hash = `docs/${doc.id}`;
});

$("#doc-delete").addEventListener("click", () => {
  if (!editingDoc || !confirm(`Delete "${editingDoc.title}"? This can't be undone once published.`)) return;
  state.docs = state.docs.filter((d) => d !== editingDoc);
  $("#doc-dlg").close();
  toast("Document deleted. Publish to put it live.");
  saveDraft();
  location.hash = "docs";
  showDocs();
});

// ---------- announcements ----------
function renderAnnouncements() {
  const list = [...state.announcements].reverse();
  $("#ann-list").innerHTML = list.length
    ? list.map((a) => `<div class="ann-item"><div><b>${esc(a.title)}</b><p>${esc(a.body)}</p><span class="hint">Posted ${esc(fmtDateTime(a.at))}${a.by ? ` by ${esc(a.by)}` : ""}</span></div><button class="btn btn-danger btn-sm" data-remove="${esc(a.id)}">Remove</button></div>`).join("")
    : `<p class="empty">No announcements yet. Anything you post shows on the home page once published.</p>`;
}

$("#ann-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const title = $("#ann-title").value.trim();
  const body = $("#ann-body").value.trim();
  if (!title || !body) return ($("#ann-error").textContent = "Add a title and a message.");
  state.announcements.push({ id: uid(), title: title.slice(0, 120), body: body.slice(0, 2000), at: Date.now(), by: session.name });
  $("#ann-title").value = "";
  $("#ann-body").value = "";
  $("#ann-error").textContent = "";
  toast("Announcement added. Publish to put it on the home page.");
  saveDraft();
  renderAnnouncements();
});

$("#ann-list").addEventListener("click", (e) => {
  const id = e.target.closest("[data-remove]")?.dataset.remove;
  if (!id || !confirm("Remove this announcement from the home page?")) return;
  state.announcements = state.announcements.filter((a) => a.id !== id);
  toast("Announcement removed. Publish to take it off the home page.");
  saveDraft();
  renderAnnouncements();
});

// ---------- access codes ----------
$("#codes-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const deputy = $("#code-deputy").value.trim();
  const admin = $("#code-admin").value.trim();
  const err = $("#codes-error");
  if (!deputy && !admin) return (err.textContent = "Enter a new deputy code, a new command code, or both.");
  if ([deputy, admin].some((c) => c && c.length < 8)) return (err.textContent = "Codes must be at least 8 characters.");
  const nextDeputy = deputy || pendingCodes?.deputy || state.codes.deputy;
  const nextAdmin = admin || pendingCodes?.admin || state.codes.admin;
  if (nextDeputy === nextAdmin) return (err.textContent = "The deputy and command codes must be different.");
  pendingCodes = { deputy: nextDeputy, admin: nextAdmin };
  err.textContent = "";
  $("#code-deputy").value = "";
  $("#code-admin").value = "";
  toast("New codes set. Publish to make them take effect.");
  saveDraft();
});

// ---------- publish ----------
async function buildContentFile() {
  const codes = pendingCodes || state.codes;
  if (!codes.deputy) throw new Error("The deputy code is unknown. Set a deputy code on the Access codes tab first.");
  const updated = Date.now();
  const full = { roster: state.roster, docs: state.docs, announcements: state.announcements, codes };
  const deputyView = {
    roster: state.roster.map(({ notes, ...r }) => r), // command notes stay command-only
    docs: state.docs.filter((d) => d.category !== "Division"), // division docs stay command-only
  };
  // Division documents with a code: one encrypted group per code (the code itself is never published).
  const byCode = new Map();
  for (const d of state.docs) {
    if (d.category !== "Division" || !d.code) continue;
    if (d.code === codes.admin || d.code === codes.deputy) throw new Error(`"${d.title}" uses the same code as the deputy or command code. Change its document code first.`);
    if (!byCode.has(d.code)) byCode.set(d.code, []);
    const { code, ...doc } = d;
    byCode.get(d.code).push(doc);
  }
  const divisionDocs = [];
  for (const [code, docs] of byCode) {
    divisionDocs.push({ divisions: [...new Set(docs.map((d) => d.division || "Unassigned"))], count: docs.length, box: await seal({ docs }, code) });
  }
  const data = { updated, admin: await seal(full, codes.admin), deputy: await seal(deputyView, codes.deputy), divisionDocs };
  const pub = { announcements: state.announcements.slice(-5).map(({ id, title, body, at }) => ({ id, title, body, at })) };
  const text =
    "// Fayette County Sheriff's Office portal content. Generated by the portal; don't edit by hand.\n" +
    "// The roster and documents below are encrypted and can only be opened with an access code.\n" +
    `window.FCSO_PUBLIC = ${JSON.stringify(pub)};\n` +
    `window.FCSO_DATA = ${JSON.stringify(data)};\n`;
  return { text, codes, updated };
}

$("#publish-download").addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  btn.disabled = true;
  btn.textContent = "Preparing...";
  try {
    const { text, codes } = await buildContentFile();
    const url = URL.createObjectURL(new Blob([text], { type: "text/javascript" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: "content.js" });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    // The download is the published version from this browser's point of view.
    state.codes = codes;
    if (codes.admin !== session.code) {
      session.code = codes.admin;
      try { sessionStorage.setItem(SESSION_KEY, JSON.stringify({ name: session.name, code: session.code })); } catch {}
    }
    pendingCodes = null;
    dirty = false;
    try { localStorage.removeItem(DRAFT_KEY); } catch {}
    updateDraftUi();
    toast("content.js downloaded. Upload it to GitHub to publish.");
  } catch (ex) {
    toast(ex.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Download content.js";
  }
});

$("#publish-discard").addEventListener("click", async () => {
  if (!confirm("Discard every unpublished change and go back to the live version?")) return;
  try { localStorage.removeItem(DRAFT_KEY); } catch {}
  const code = session.code;
  const name = session.name;
  dirty = false;
  pendingCodes = null;
  try {
    await signIn(name, code);
    toast("Unpublished changes discarded.");
  } catch {
    signOut("Sign in again to continue.");
  }
});

window.addEventListener("beforeunload", (e) => {
  if (dirty) {
    e.preventDefault();
    e.returnValue = "";
  }
});

// ---------- dialogs ----------
$$("dialog [data-close]").forEach((b) => b.addEventListener("click", () => b.closest("dialog").close()));

// ---------- deputy copy deterrents (documents and roster are view-only) ----------
const protectedArea = (t) => document.body.classList.contains("locked") && t.closest?.(".reader, .table-wrap");
["copy", "cut", "contextmenu", "dragstart", "selectstart"].forEach((type) =>
  document.addEventListener(type, (e) => {
    if (protectedArea(e.target)) e.preventDefault();
  })
);
document.addEventListener("keydown", (e) => {
  if (!document.body.classList.contains("locked")) return;
  const k = e.key.toLowerCase();
  if ((e.ctrlKey || e.metaKey) && ["c", "x", "a", "p", "s"].includes(k) && !e.target.matches("input, textarea")) {
    e.preventDefault();
    if (k === "p" || k === "s") toast("Saving and printing documents is turned off.", true);
  }
});

// ---------- start ----------
(async () => {
  let saved;
  try { saved = JSON.parse(sessionStorage.getItem(SESSION_KEY)); } catch {}
  if (saved?.code) {
    try {
      await signIn(saved.name, saved.code, saved.docCodes || []);
      return;
    } catch {
      try { sessionStorage.removeItem(SESSION_KEY); } catch {}
    }
  }
  $("#login").hidden = false;
})();
