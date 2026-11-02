// Deputy portal. Every check that matters happens on the bot's API; this file only shows what the API sends back.
const API = window.FCSO_API || "https://api.fayettecountysheriffs.xyz";
const KEY = "fcso_session";

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

let session = null; // { token, role, name, exp }
let meta = { ranks: [], divisions: [], categories: [], statuses: [] };
let roster = [];
let docs = [];
let currentDoc = null;
const isAdmin = () => session?.role === "admin";

// ---------- API ----------
async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(API + path, {
    method,
    headers: { "Content-Type": "application/json", ...(session ? { Authorization: `Bearer ${session.token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  }).catch(() => null);
  if (!res) throw new Error("The portal can't reach the department server right now. Try again in a minute.");
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && session) {
    signOut("Your session has ended. Sign in again.");
    throw new Error(data.error || "Signed out");
  }
  if (!res.ok) throw new Error(data.error || "Something went wrong. Try again.");
  return data;
}

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
function loadSession() {
  try {
    const s = JSON.parse(localStorage.getItem(KEY));
    if (s && s.exp > Date.now()) return s;
  } catch {}
  return null;
}

function signOut(message) {
  session = null;
  try { localStorage.removeItem(KEY); } catch {}
  document.body.classList.remove("locked");
  $("#app").hidden = true;
  $("#session").hidden = true;
  $("#login").hidden = false;
  $("#login-error").textContent = message || "";
  history.replaceState(null, "", location.pathname);
}

$("#signout").addEventListener("click", () => signOut());

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = $("#login-name").value.trim();
  const code = $("#login-code").value;
  const err = $("#login-error");
  if (!name) return (err.textContent = "Enter your name or callsign.");
  if (!code) return (err.textContent = "Enter your access code.");
  const btn = $("#login-btn");
  btn.disabled = true;
  btn.textContent = "Signing in...";
  err.textContent = "";
  try {
    const s = await api("/api/auth", { method: "POST", body: { name, code } });
    session = s;
    try { localStorage.setItem(KEY, JSON.stringify(s)); } catch {}
    $("#login-code").value = "";
    await startApp();
  } catch (ex) {
    err.textContent = ex.message;
  } finally {
    btn.disabled = false;
    btn.textContent = "Sign in";
  }
});

async function startApp() {
  $("#login").hidden = true;
  $("#app").hidden = false;
  $("#session").hidden = false;
  $("#who").textContent = session.name;
  const tag = $("#access");
  tag.textContent = isAdmin() ? "Command access" : "Deputy access";
  tag.classList.toggle("admin", isAdmin());
  $$("[data-admin]").forEach((el) => (el.hidden = !isAdmin()));
  document.body.classList.toggle("locked", !isAdmin());
  $("#docs-sub").textContent = isAdmin()
    ? "Every document, including division documents. You can create and edit them."
    : "Department procedures, training material, and references. Documents are read-only.";

  try {
    meta = await api("/api/meta");
  } catch (ex) {
    toast(ex.message, true);
    return;
  }
  fillSelects();
  route();
}

window.addEventListener("hashchange", route);

function route() {
  if (!session) return;
  let [tab, arg] = location.hash.replace("#", "").split("/");
  if (!["roster", "docs", "announcements", "access"].includes(tab)) tab = "roster";
  if (!isAdmin() && (tab === "announcements" || tab === "access")) tab = "roster";
  $$(".view").forEach((v) => (v.hidden = v.id !== `view-${tab}`));
  $$("#tabs a").forEach((a) => (a.dataset.tab === tab ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  ({ roster: showRoster, docs: () => showDocs(arg), announcements: showAnnouncements, access: showAccess })[tab]();
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

async function showRoster() {
  $("#roster-body").innerHTML = `<tr><td colspan="7" class="empty">Loading the roster...</td></tr>`;
  try {
    roster = await api("/api/roster");
    renderRoster();
  } catch (ex) {
    $("#roster-body").innerHTML = `<tr><td colspan="7" class="empty">${esc(ex.message)}</td></tr>`;
  }
}

function renderRoster() {
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
    $("#roster-body").innerHTML = `<tr><td colspan="${cols}" class="empty">${isAdmin() ? "The roster is empty. Add members one at a time, or import everyone with the department role from Discord." : "The roster hasn't been filled in yet."}</td></tr>`;
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
  if (id) openRosterEditor(roster.find((r) => r.id === id));
});
$("#roster-add").addEventListener("click", () => openRosterEditor(null));

$("#roster-import").addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  btn.disabled = true;
  btn.textContent = "Importing...";
  try {
    const { added } = await api("/api/roster/import", { method: "POST" });
    toast(added ? `Added ${added} member${added === 1 ? "" : "s"} from Discord.` : "Everyone with the department role is already on the roster.");
    await showRoster();
  } catch (ex) {
    toast(ex.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Import from Discord";
  }
});

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

$("#roster-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {
    name: $("#r-name").value, callsign: $("#r-callsign").value, rank: $("#r-rank").value, division: $("#r-division").value,
    status: $("#r-status").value, joined: $("#r-joined").value, discordId: $("#r-discord").value, notes: $("#r-notes").value,
  };
  try {
    if (editingMember) await api(`/api/roster/${editingMember.id}`, { method: "PUT", body });
    else await api("/api/roster", { method: "POST", body });
    $("#roster-dlg").close();
    toast(editingMember ? "Member saved." : "Member added.");
    showRoster();
  } catch (ex) {
    $("#roster-error").textContent = ex.message;
  }
});

$("#roster-delete").addEventListener("click", async () => {
  if (!editingMember || !confirm(`Remove ${editingMember.name} from the roster?`)) return;
  try {
    await api(`/api/roster/${editingMember.id}`, { method: "DELETE" });
    $("#roster-dlg").close();
    toast("Member removed from the roster.");
    showRoster();
  } catch (ex) {
    $("#roster-error").textContent = ex.message;
  }
});

// ---------- documents ----------
// Markdown -> HTML. Everything is escaped first, so no HTML from a document can run.
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

async function showDocs(id) {
  try {
    docs = await api("/api/docs");
  } catch (ex) {
    $("#doc-groups").innerHTML = `<p class="empty">${esc(ex.message)}</p>`;
    return;
  }
  renderDocList(id);
  if (id) openDoc(id);
  else if (!currentDoc) showReaderEmpty();
}

function showReaderEmpty() {
  currentDoc = null;
  $("#reader").innerHTML = `<div class="empty">${docs.length ? "Pick a document from the list to read it." : isAdmin() ? "There are no documents yet. Create the first one with New document." : "No documents have been published yet."}</div>`;
}

function renderDocList(activeId) {
  const q = $("#doc-search").value.trim().toLowerCase();
  const list = docs.filter((d) => !q || d.title.toLowerCase().includes(q));
  const groups = {};
  for (const d of list) {
    const key = d.category === "Division" ? `Division: ${d.division || "Unassigned"}` : d.category;
    (groups[key] ||= []).push(d);
  }
  const order = (k) => { const i = meta.categories.indexOf(k.startsWith("Division") ? "Division" : k); return i === -1 ? 99 : i; };
  const keys = Object.keys(groups).sort((a, b) => order(a) - order(b) || a.localeCompare(b));
  $("#doc-groups").innerHTML = keys.length
    ? keys.map((k) => `<div class="doc-group"><h3>${esc(k)}</h3>${groups[k].map((d) => `<a href="#docs/${esc(d.id)}" ${d.id === activeId ? 'aria-current="true"' : ""}>${esc(d.title)}</a>`).join("")}</div>`).join("")
    : `<p class="empty">${q ? "No documents match that search." : "No documents yet."}</p>`;
}
$("#doc-search").addEventListener("input", () => renderDocList(currentDoc?.id));

function watermark() {
  const text = `${session.name}  ${new Date().toLocaleDateString()}  FCSO`;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="320" height="180"><text x="10" y="110" transform="rotate(-24 160 90)" font-family="Arial" font-size="15" font-weight="700" fill="#141b3d">${esc(text)}</text></svg>`;
  return `<div class="watermark" style="background-image:url('data:image/svg+xml;utf8,${encodeURIComponent(svg)}')"></div>`;
}

async function openDoc(id) {
  $("#reader").innerHTML = `<div class="empty">Opening document...</div>`;
  try {
    const d = await api(`/api/docs/${encodeURIComponent(id)}`);
    currentDoc = d;
    $("#reader").innerHTML = `
      ${isAdmin() ? "" : watermark()}
      <div class="reader-meta">
        <span>${esc(d.category)}${d.division ? `: ${esc(d.division)}` : ""}. Updated ${esc(fmtDate(d.updatedAt))}${d.updatedBy ? ` by ${esc(d.updatedBy)}` : ""}.</span>
        ${isAdmin() ? `<button class="btn btn-outline btn-sm" id="doc-edit">Edit document</button>` : ""}
      </div>
      <h1 class="doc-title">${esc(d.title)}</h1>
      <div class="prose">${render(d.body) || "<p><em>This document is empty.</em></p>"}</div>`;
    $("#doc-edit")?.addEventListener("click", () => openDocEditor(d));
    renderDocList(id);
  } catch (ex) {
    currentDoc = null;
    $("#reader").innerHTML = `<div class="empty">${esc(ex.message)}</div>`;
  }
}

let editingDoc = null;
function openDocEditor(d) {
  editingDoc = d;
  $("#doc-dlg-title").textContent = d ? "Edit document" : "New document";
  $("#d-title").value = d?.title || "";
  $("#d-category").value = d?.category || meta.categories[0];
  $("#d-division").value = d?.division || meta.divisions[0];
  $("#d-body").value = d?.body || "";
  $("#doc-error").textContent = "";
  $("#doc-delete").hidden = !d;
  syncDivisionField();
  updatePreview();
  $("#doc-dlg").showModal();
  $("#d-title").focus();
}
function syncDivisionField() { $("#d-division-field").hidden = $("#d-category").value !== "Division"; }
function updatePreview() { $("#d-preview").innerHTML = render($("#d-body").value) || "<p class='hint'>The preview shows here as you type.</p>"; }
$("#d-category").addEventListener("change", syncDivisionField);
$("#d-body").addEventListener("input", updatePreview);
$("#doc-new").addEventListener("click", () => openDocEditor(null));

$("#doc-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = { title: $("#d-title").value, category: $("#d-category").value, division: $("#d-division").value, body: $("#d-body").value };
  try {
    const saved = editingDoc
      ? await api(`/api/docs/${editingDoc.id}`, { method: "PUT", body })
      : await api("/api/docs", { method: "POST", body });
    $("#doc-dlg").close();
    toast(editingDoc ? "Document saved." : "Document created.");
    if (location.hash === `#docs/${saved.id}`) showDocs(saved.id);
    else location.hash = `docs/${saved.id}`;
  } catch (ex) {
    $("#doc-error").textContent = ex.message;
  }
});

$("#doc-delete").addEventListener("click", async () => {
  if (!editingDoc || !confirm(`Delete "${editingDoc.title}"? This can't be undone.`)) return;
  try {
    await api(`/api/docs/${editingDoc.id}`, { method: "DELETE" });
    $("#doc-dlg").close();
    toast("Document deleted.");
    currentDoc = null;
    location.hash = "docs";
    showDocs();
  } catch (ex) {
    $("#doc-error").textContent = ex.message;
  }
});

// ---------- announcements ----------
async function showAnnouncements() {
  $("#ann-list").innerHTML = `<p class="empty">Loading...</p>`;
  try {
    const list = await api("/api/announcements");
    $("#ann-list").innerHTML = list.length
      ? list.map((a) => `<div class="ann-item"><div><b>${esc(a.title)}</b><p>${esc(a.body)}</p><span class="hint">Posted ${esc(fmtDateTime(a.at))}${a.by ? ` by ${esc(a.by)}` : ""}</span></div><button class="btn btn-danger btn-sm" data-remove="${esc(a.id)}">Remove</button></div>`).join("")
      : `<p class="empty">No announcements yet. Anything you post shows on the home page.</p>`;
  } catch (ex) {
    $("#ann-list").innerHTML = `<p class="empty">${esc(ex.message)}</p>`;
  }
}

$("#ann-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("/api/announcements", { method: "POST", body: { title: $("#ann-title").value, body: $("#ann-body").value } });
    $("#ann-title").value = "";
    $("#ann-body").value = "";
    $("#ann-error").textContent = "";
    toast("Announcement posted.");
    showAnnouncements();
  } catch (ex) {
    $("#ann-error").textContent = ex.message;
  }
});

$("#ann-list").addEventListener("click", async (e) => {
  const id = e.target.closest("[data-remove]")?.dataset.remove;
  if (!id || !confirm("Remove this announcement from the home page?")) return;
  try {
    await api(`/api/announcements/${id}`, { method: "DELETE" });
    toast("Announcement removed.");
    showAnnouncements();
  } catch (ex) {
    toast(ex.message, true);
  }
});

// ---------- access ----------
async function showAccess() {
  $("#audit-list").innerHTML = `<p class="empty">Loading...</p>`;
  try {
    const list = await api("/api/audit");
    $("#audit-list").innerHTML = list.length
      ? list.map((a) => `<div class="audit-item"><span><b>${esc(a.name || "Unknown")}</b> (${a.role === "admin" ? "command" : "deputy"}) ${esc(a.action.toLowerCase())}${a.detail ? `: ${esc(a.detail)}` : ""}</span><time>${esc(fmtDateTime(a.at))}</time></div>`).join("")
      : `<p class="empty">No activity yet.</p>`;
  } catch (ex) {
    $("#audit-list").innerHTML = `<p class="empty">${esc(ex.message)}</p>`;
  }
}

$("#codes-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const deputy = $("#code-deputy").value.trim();
  const admin = $("#code-admin").value.trim();
  if (!deputy && !admin) return ($("#codes-error").textContent = "Enter a new deputy code, a new command code, or both.");
  if (!confirm("Change the codes? Everyone will be signed out, including you.")) return;
  try {
    await api("/api/settings/codes", { method: "PUT", body: { deputy, admin } });
    signOut("Codes changed. Sign in with the new code.");
  } catch (ex) {
    $("#codes-error").textContent = ex.message;
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
session = loadSession();
if (session) {
  api("/api/me")
    .then(() => startApp())
    .catch((ex) => { if (session) signOut(ex.message); });
} else {
  $("#login").hidden = false;
}
