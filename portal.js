// Deputy portal (standalone: GitHub Pages only, no bot or server).
//
// content.json holds everything, encrypted with AES-256-GCM:
//   admin   - the full copy, opened with the command code
//   deputy  - the deputy copy (no command notes, no password or division-only documents), opened with the deputy code
//   locked  - password-protected documents, one group per password
// Command's edits save automatically by updating content.json in the GitHub repo through the GitHub API.
// The GitHub token lives inside the command copy, so only someone with the command code can save.

// The encryption only works over HTTPS, so always switch to the secure address.
if (location.protocol === "http:" && !/^(localhost|127\.0\.0\.1)$/.test(location.hostname)) {
  location.replace("https://" + location.host + location.pathname + location.search + location.hash);
}

// If anything fails while loading, say so on the sign-in box instead of leaving a blank page.
window.addEventListener("error", () => {
  const box = document.getElementById("login");
  const err = document.getElementById("login-error");
  if (box && document.getElementById("app")?.hidden !== false) box.hidden = false;
  if (err && !err.textContent) err.textContent = "The portal didn't load correctly. Press Ctrl + F5 to reload it. If that doesn't help, the site files may be out of date.";
});

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

const CONTENT_FILE = "content.json";
const SESSION_KEY = "fcso_portal";
const DRAFT_KEY = "fcso_draft";
const SAVE_DELAY = 2500;

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const uid = () => [...crypto.getRandomValues(new Uint8Array(6))].map((b) => b.toString(16).padStart(2, "0")).join("");

let file = null; // the parsed content.json
let fileSha = null; // GitHub's version id for content.json (command only)
let session = null; // { role, name, code, docCodes, unlocked }
let state = null; // admin: { roster, docs, announcements, codes, github }   others: { roster, docs }
let currentDoc = null;
const isAdmin = () => session?.role === "admin";

// ---------- encoding ----------
function toB64(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const textToB64 = (t) => toB64(new TextEncoder().encode(t));
const b64ToText = (b) => new TextDecoder().decode(fromB64(b.replace(/\s/g, "")));

// ---------- crypto ----------
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

// ---------- loading content ----------
async function loadFile() {
  const res = await fetch(`${CONTENT_FILE}?t=${Date.now()}`, { cache: "no-store" }).catch(() => null);
  if (!res || !res.ok) throw new Error("The portal's content file (content.json) couldn't be loaded. Make sure it's uploaded to the site.");
  file = await res.json();
  return file;
}

async function unlock(code) {
  try {
    return { role: "admin", data: await unseal(file.admin, code) };
  } catch {}
  try {
    return { role: "deputy", data: await unseal(file.deputy, code) };
  } catch {}
  const groups = await unlockGroups(code);
  if (groups.length) return { role: "division", data: { roster: [], docs: [] }, groups };
  throw new Error("That code isn't valid.");
}

// Password-protected documents are published in groups, one per password.
async function unlockGroups(code) {
  const opened = [];
  for (const [i, g] of (file?.locked || []).entries()) {
    try {
      opened.push({ index: i, docs: (await unseal(g.box, code)).docs });
    } catch {}
  }
  return opened;
}
const lockedGroups = () => (file?.locked || []).map((g, index) => ({ ...g, index })).filter((g) => !session.unlocked.has(g.index));
function addUnlocked(groups) {
  for (const g of groups) {
    if (session.unlocked.has(g.index)) continue;
    session.unlocked.add(g.index);
    for (const d of g.docs) state.docs.push({ ...d, unlockedByPassword: true });
  }
}

// ---------- ui helpers ----------
function toast(message, error = false) {
  const t = $("#toast");
  t.textContent = message;
  t.classList.toggle("error", error);
  t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("show"), 3600);
}
const fmtDate = (ts) => new Date(ts).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
const fmtDateTime = (ts) => new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });

// ---------- session ----------
function signOut(message) {
  session = null;
  state = null;
  fileSha = null;
  clearTimeout(saveTimer);
  try { sessionStorage.removeItem(SESSION_KEY); } catch {}
  document.body.classList.remove("locked");
  $("#app").hidden = true;
  $("#session").hidden = true;
  $("#login").hidden = false;
  $("#login-error").textContent = message || "";
  history.replaceState(null, "", location.pathname);
}
$("#signout").addEventListener("click", async () => {
  if (saveState.pending || saveState.saving) {
    toast("Saving your last change first...");
    await saveNow();
    if (saveState.error && !confirm("Your last change didn't save. It's kept in this browser and will be offered next time you sign in. Sign out anyway?")) return;
  }
  signOut();
});

async function signIn(name, code, docCodes = []) {
  if (!file) await loadFile();
  let result = await unlock(code);
  session = { role: result.role, name, code, docCodes: [], unlocked: new Set() };
  state = result.data;

  if (isAdmin()) {
    // With GitHub connected, read the newest saved version straight from GitHub (the site itself can lag a minute behind).
    if (state.github?.token) {
      try {
        const latest = await ghRead(state.github);
        const data = await unseal(latest.json.admin, code);
        file = latest.json;
        fileSha = latest.sha;
        state = data;
      } catch (ex) {
        setSaveStatus("error", `Couldn't reach GitHub: ${ex.message}`);
      }
    }
    state.roster ||= [];
    state.docs ||= [];
    state.announcements ||= file.public?.announcements || [];
    state.codes ||= { admin: code, deputy: null };
    state.github ||= null;
    await restoreDraft();
  } else {
    state.roster ||= [];
    state.docs ||= [];
    if (result.groups) addUnlocked(result.groups);
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
    await loadFile();
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
  $("#save-status").hidden = !isAdmin();
  $('#tabs a[data-tab="roster"]').hidden = session.role === "division";
  document.body.classList.toggle("locked", !isAdmin());
  $("#docs-sub").textContent = isAdmin()
    ? "Every document. You can create and edit them, and set a password on any document."
    : session.role === "division"
      ? "The documents your password unlocks. Documents are read-only."
      : "Department procedures, training material, and references. Locked documents open with their own password. Documents are read-only.";
  fillSelects();
  if (isAdmin()) {
    fillGithubForm();
    if (!saveState.pending && !saveState.error) setSaveStatus(state.github?.token ? "saved" : "offline");
  }
  route();
}

window.addEventListener("hashchange", route);
function route() {
  if (!session) return;
  let [tab, arg] = location.hash.replace("#", "").split("/");
  const tabs = isAdmin() ? ["roster", "docs", "announcements", "saving"] : session.role === "division" ? ["docs"] : ["roster", "docs"];
  if (!tabs.includes(tab)) tab = tabs[0];
  $$(".view").forEach((v) => (v.hidden = v.id !== `view-${tab}`));
  $$("#tabs a").forEach((a) => (a.dataset.tab === tab ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  ({ roster: renderRoster, docs: () => showDocs(arg), announcements: renderAnnouncements, saving: renderSaving })[tab]();
}

// ---------- GitHub storage ----------
const ghUrl = (g) => `https://api.github.com/repos/${encodeURIComponent(g.owner)}/${encodeURIComponent(g.repo)}/contents/${CONTENT_FILE}`;
const ghHeaders = (g, extra = {}) => ({ Authorization: `Bearer ${g.token}`, "X-GitHub-Api-Version": "2022-11-28", ...extra });

function ghProblem(status, body) {
  if (status === 401) return "GitHub rejected the access token. It may have expired. Add a new one on the Saving tab.";
  if (status === 403) return body?.message?.includes("rate limit") ? "GitHub's rate limit was hit. Try again in a few minutes." : "The access token isn't allowed to edit this repository. Check its permissions.";
  if (status === 404) return "GitHub couldn't find that repository or branch. Check the details on the Saving tab.";
  return body?.message || `GitHub returned an error (${status}).`;
}

async function ghRead(g) {
  const res = await fetch(`${ghUrl(g)}?ref=${encodeURIComponent(g.branch || "main")}&t=${Date.now()}`, { headers: ghHeaders(g, { Accept: "application/vnd.github+json" }), cache: "no-store" });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(ghProblem(res.status, body));
  let text = body.content ? b64ToText(body.content) : null;
  if (!text) {
    // Files over 1 MB come back without content; fetch the raw file instead.
    const raw = await fetch(`${ghUrl(g)}?ref=${encodeURIComponent(g.branch || "main")}`, { headers: ghHeaders(g, { Accept: "application/vnd.github.raw+json" }), cache: "no-store" });
    if (!raw.ok) throw new Error(ghProblem(raw.status));
    text = await raw.text();
  }
  return { sha: body.sha, json: JSON.parse(text) };
}

async function ghWrite(g, text, sha) {
  const res = await fetch(ghUrl(g), {
    method: "PUT",
    headers: ghHeaders(g, { Accept: "application/vnd.github+json", "Content-Type": "application/json" }),
    body: JSON.stringify({ message: `Portal update by ${session.name}`, content: textToB64(text), branch: g.branch || "main", ...(sha ? { sha } : {}) }),
  });
  const body = await res.json().catch(() => ({}));
  if (res.status === 409 || res.status === 422) {
    const e = new Error("conflict");
    e.conflict = true;
    throw e;
  }
  if (!res.ok) throw new Error(ghProblem(res.status, body));
  return body.content.sha;
}

// ---------- building content.json ----------
async function buildContent() {
  const codes = state.codes;
  if (!codes.deputy || !codes.admin) throw new Error("The access codes are missing from the content file. Contact the site developer.");
  const full = { roster: state.roster, docs: state.docs, announcements: state.announcements, codes, github: state.github };
  const deputyView = {
    roster: state.roster.map(({ notes, ...r }) => r), // command notes stay command-only
    docs: state.docs.filter((d) => !d.code && d.category !== "Division").map(({ code, ...d }) => d),
  };
  // Password-protected documents: one encrypted group per password. The password itself is never written out.
  const byCode = new Map();
  for (const d of state.docs) {
    if (!d.code) continue;
    if (!byCode.has(d.code)) byCode.set(d.code, []);
    const { code, ...doc } = d;
    byCode.get(d.code).push(doc);
  }
  const locked = [];
  for (const [code, docs] of byCode) {
    const labels = [...new Set(docs.map((d) => (d.category === "Division" ? `Division: ${d.division || "Unassigned"}` : d.category)))];
    locked.push({ labels, count: docs.length, box: await seal({ docs }, code) });
  }
  const out = {
    updated: Date.now(),
    public: { announcements: state.announcements.slice(-5).map(({ id, title, body, at }) => ({ id, title, body, at })) },
    admin: await seal(full, codes.admin),
    deputy: await seal(deputyView, codes.deputy),
    locked,
  };
  return { json: out, text: JSON.stringify(out) };
}

// ---------- saving ----------
const saveState = { pending: false, saving: false, error: null, lastSaved: null };
let saveTimer = null;

function setSaveStatus(kind, message) {
  const el = $("#save-status");
  if (!el) return;
  el.classList.remove("saving", "error");
  if (kind === "saving") { el.textContent = "Saving..."; el.classList.add("saving"); }
  else if (kind === "pending") { el.textContent = "Unsaved changes"; el.classList.add("saving"); }
  else if (kind === "error") { el.textContent = "Not saved"; el.classList.add("error"); saveState.error = message; }
  else if (kind === "offline") { el.textContent = "Saving not set up"; el.classList.add("error"); }
  else { el.textContent = "All changes saved"; saveState.error = null; }
  el.title = message || "";
  if (location.hash === "#saving") renderSaving();
}

// Called after every edit.
function changed() {
  saveState.pending = true;
  writeDraft();
  if (!state.github?.token) {
    setSaveStatus("offline");
    return;
  }
  setSaveStatus("pending");
  clearTimeout(saveTimer);
  saveTimer = setTimeout(saveNow, SAVE_DELAY);
}

async function saveNow() {
  clearTimeout(saveTimer);
  if (!isAdmin() || !state.github?.token) return;
  if (saveState.saving) {
    saveState.again = true;
    return;
  }
  saveState.saving = true;
  saveState.pending = false;
  setSaveStatus("saving");
  try {
    const { json, text } = await buildContent();
    try {
      fileSha = await ghWrite(state.github, text, fileSha || (await ghRead(state.github).catch(() => ({}))).sha);
    } catch (ex) {
      if (!ex.conflict) throw ex;
      await resolveConflict();
      const rebuilt = await buildContent();
      fileSha = await ghWrite(state.github, rebuilt.text, fileSha);
    }
    file = json;
    state._deleted = [];
    saveState.lastSaved = Date.now();
    clearDraft();
    setSaveStatus("saved");
  } catch (ex) {
    saveState.pending = true;
    setSaveStatus("error", ex.message);
    toast(`Not saved: ${ex.message}`, true);
  } finally {
    saveState.saving = false;
    if (saveState.again) {
      saveState.again = false;
      saveNow();
    }
  }
}

// Someone else saved since this page loaded. Keep both sets of edits where possible:
// their version is the base, and anything this person changed more recently replaces it.
async function resolveConflict() {
  const latest = await ghRead(state.github);
  const theirs = await unseal(latest.json.admin, session.code);
  const mergeList = (mine, other, key = "id") => {
    const map = new Map(other.map((x) => [x[key], x]));
    for (const m of mine) {
      const o = map.get(m[key]);
      if (!o || (m.updatedAt || m.at || 0) >= (o.updatedAt || o.at || 0)) map.set(m[key], m);
    }
    for (const id of state._deleted || []) map.delete(id);
    return [...map.values()];
  };
  state.roster = mergeList(state.roster, theirs.roster || []);
  state.docs = mergeList(state.docs, theirs.docs || []);
  state.announcements = mergeList(state.announcements, theirs.announcements || []).sort((a, b) => a.at - b.at);
  state.github = state.github || theirs.github;
  fileSha = latest.sha;
  toast("Another command member saved at the same time. Both sets of changes were kept.");
}

const forget = (id) => { (state._deleted ||= []).push(id); };

// ---------- drafts: unsaved edits kept (encrypted) in this browser until they save ----------
let draftKey = null;
async function writeDraft() {
  try {
    if (!draftKey || draftKey.code !== session.code) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      draftKey = { code: session.code, salt, key: await keyFor(session.code, salt, 250000) };
    }
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, draftKey.key, new TextEncoder().encode(JSON.stringify(state)));
    localStorage.setItem(DRAFT_KEY, JSON.stringify({ base: file?.updated || 0, at: Date.now(), box: { salt: toB64(draftKey.salt), iv: toB64(iv), iterations: 250000, ct: toB64(ct) } }));
  } catch {}
}
function clearDraft() {
  try { localStorage.removeItem(DRAFT_KEY); } catch {}
}
async function restoreDraft() {
  let draft;
  try { draft = JSON.parse(localStorage.getItem(DRAFT_KEY)); } catch {}
  if (!draft) return;
  let data;
  try { data = await unseal(draft.box, session.code); } catch { return; }
  if (!confirm(`This browser has changes from ${fmtDateTime(draft.at)} that never saved. Restore them now? (Cancel throws them away.)`)) {
    clearDraft();
    return;
  }
  data.github = data.github || state.github;
  data.codes = state.codes;
  state = data;
  saveState.pending = true;
  setTimeout(() => (state.github?.token ? saveNow() : setSaveStatus("offline")), 0);
}

window.addEventListener("beforeunload", (e) => {
  if (isAdmin() && (saveState.pending || saveState.saving)) {
    e.preventDefault();
    e.returnValue = "";
  }
});

// ---------- saving tab ----------
function renderSaving() {
  if (!isAdmin()) return;
  const connected = !!state.github?.token;
  let title, detail;
  if (!connected) {
    title = "Saving isn't set up yet";
    detail = "Connect the portal to GitHub below and every change will save to the website automatically. Until then, changes are only kept in this browser.";
  } else if (saveState.saving) {
    title = "Saving...";
    detail = "Writing your changes to the website.";
  } else if (saveState.error) {
    title = "Your last change didn't save";
    detail = `${saveState.error} Your changes are kept in this browser. Fix the problem and press Save now.`;
  } else if (saveState.pending) {
    title = "Unsaved changes";
    detail = "Your changes will save in a moment.";
  } else {
    title = "All changes saved";
    detail = saveState.lastSaved ? `Last saved ${fmtDateTime(saveState.lastSaved)}. Deputies see changes about a minute after saving.` : "Everything here matches the website.";
  }
  $("#saving-state").textContent = title;
  $("#saving-detail").textContent = detail;
  $("#save-now").hidden = !connected;
}

function fillGithubForm() {
  const g = state.github || {};
  $("#gh-owner").value = g.owner || "";
  $("#gh-repo").value = g.repo || "";
  $("#gh-branch").value = g.branch || "main";
  $("#gh-token").value = "";
  $("#gh-token-hint").textContent = g.token ? "A token is saved. Leave empty to keep it." : "Paste the fine-grained token you created on GitHub.";
}

$("#gh-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#gh-error");
  const g = {
    owner: $("#gh-owner").value.trim(),
    repo: $("#gh-repo").value.trim(),
    branch: $("#gh-branch").value.trim() || "main",
    token: $("#gh-token").value.trim() || state.github?.token || "",
  };
  if (!g.owner || !g.repo) return (err.textContent = "Enter the GitHub username and the repository name.");
  if (!g.token) return (err.textContent = "Paste an access token.");
  err.textContent = "";
  const btn = $("#gh-save");
  btn.disabled = true;
  btn.textContent = "Connecting...";
  try {
    let sha = null;
    try {
      sha = (await ghRead(g)).sha;
    } catch (ex) {
      if (!/couldn't find/.test(ex.message)) throw ex; // a missing content.json is fine; it gets created
    }
    state.github = g;
    fileSha = sha;
    fillGithubForm();
    toast("Connected to GitHub. Saving now.");
    await saveNow();
  } catch (ex) {
    err.textContent = ex.message;
  } finally {
    btn.disabled = false;
    btn.textContent = "Connect and save";
  }
});

$("#save-now").addEventListener("click", () => saveNow());

$("#save-download").addEventListener("click", async () => {
  try {
    const { text } = await buildContent();
    const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: CONTENT_FILE });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    toast("Backup copy downloaded. It's locked with the access codes like the live one.");
  } catch (ex) {
    toast(ex.message, true);
  }
});

// ---------- selects ----------
function options(el, values, keepFirst = true) {
  const first = keepFirst ? el.options[0]?.outerHTML || "" : "";
  el.innerHTML = first + values.map((v) => `<option>${esc(v)}</option>`).join("");
}
function fillSelects() {
  options($("#roster-rank"), RANKS.map((r) => r.name));
  options($("#roster-division"), DIVISIONS);
  options($("#roster-status"), STATUSES);
  options($("#r-rank"), RANKS.map((r) => r.name));
  options($("#r-division"), DIVISIONS);
  options($("#r-status"), STATUSES, false);
  options($("#d-category"), CATEGORIES, false);
  options($("#d-division"), DIVISIONS, false);
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
  toast(editingMember ? "Member saved." : "Member added.");
  changed();
  renderRoster();
});

$("#roster-delete").addEventListener("click", () => {
  if (!editingMember || !confirm(`Remove ${editingMember.name} from the roster?`)) return;
  forget(editingMember.id);
  state.roster = state.roster.filter((r) => r !== editingMember);
  $("#roster-dlg").close();
  toast("Member removed from the roster.");
  changed();
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
const groupKey = (d) => (d.category === "Division" ? `Division: ${d.division || "Unassigned"}` : d.category);

function showDocs(id) {
  renderDocList(id);
  if (id) openDoc(id);
  else showReaderEmpty();
}

function showReaderEmpty() {
  currentDoc = null;
  const any = state.docs.length || (!isAdmin() && lockedGroups().length);
  $("#reader").innerHTML = `<div class="empty">${any ? "Pick a document from the list to read it." : isAdmin() ? "There are no documents yet. Create the first one with New document." : "No documents have been published yet."}</div>`;
}

function renderDocList(activeId) {
  const q = $("#doc-search").value.trim().toLowerCase();
  const list = [...state.docs].filter((d) => !q || d.title.toLowerCase().includes(q)).sort((a, b) => a.title.localeCompare(b.title));
  const groups = {};
  for (const d of list) (groups[groupKey(d)] ||= []).push(d);
  // Locked documents (not command): shown under their category, opened with a password. Titles stay hidden.
  if (!isAdmin() && !q) {
    for (const g of lockedGroups()) {
      const key = g.labels.length === 1 ? g.labels[0] : "Locked documents";
      (groups[key] ||= []).push({ locked: true, id: `locked-${g.index}`, title: `${g.count} locked document${g.count === 1 ? "" : "s"}` });
    }
  }
  const order = (k) => { const i = CATEGORIES.indexOf(k.startsWith("Division") ? "Division" : k); return i === -1 ? 99 : i; };
  const keys = Object.keys(groups).sort((a, b) => order(a) - order(b) || a.localeCompare(b));
  const link = (d) =>
    d.locked
      ? `<a class="locked" href="#docs/${d.id}" ${d.id === activeId ? 'aria-current="true"' : ""}><span>${esc(d.title)}</span><span class="lock-tag">Password</span></a>`
      : `<a href="#docs/${esc(d.id)}" ${d.id === activeId ? 'aria-current="true"' : ""}>${esc(d.title)}${isAdmin() && d.code ? ' <span class="lock-tag">Password</span>' : ""}</a>`;
  $("#doc-groups").innerHTML = keys.length
    ? keys.map((k) => `<div class="doc-group"><h3>${esc(k)}</h3>${groups[k].map(link).join("")}</div>`).join("")
    : `<p class="empty">${q ? "No documents match that search." : "No documents yet."}</p>`;
}
$("#doc-search").addEventListener("input", () => renderDocList(currentDoc?.id));

function showUnlock() {
  currentDoc = null;
  $("#reader").innerHTML = `
    <form class="unlock" id="unlock-form" novalidate>
      <h2>Locked document</h2>
      <p>This document has a password. Enter the password you were given by command or your division.</p>
      <div class="field"><label for="unlock-code">Document password</label><input id="unlock-code" type="password" autocomplete="off" required></div>
      <p class="form-error" id="unlock-error" role="alert"></p>
      <button class="btn btn-primary" type="submit" id="unlock-btn">Unlock</button>
    </form>`;
  $("#unlock-code").focus();
  $("#unlock-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const code = $("#unlock-code").value.trim();
    if (!code) return ($("#unlock-error").textContent = "Enter the document password.");
    const btn = $("#unlock-btn");
    btn.disabled = true;
    btn.textContent = "Unlocking...";
    const opened = (await unlockGroups(code)).filter((g) => !session.unlocked.has(g.index));
    btn.disabled = false;
    btn.textContent = "Unlock";
    if (!opened.length) return ($("#unlock-error").textContent = "That password doesn't unlock any locked documents.");
    addUnlocked(opened);
    session.docCodes.push(code);
    rememberSession();
    const docs = opened.flatMap((g) => g.docs);
    toast(`Unlocked ${docs.length} document${docs.length === 1 ? "" : "s"}.`);
    location.hash = `docs/${docs[0].id}`;
  });
}

function watermark() {
  const text = `${session.name}  ${new Date().toLocaleDateString()}  FCSO`;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="320" height="180"><text x="10" y="110" transform="rotate(-24 160 90)" font-family="Arial" font-size="15" font-weight="700" fill="#141b3d">${esc(text)}</text></svg>`;
  return `<div class="watermark" style="background-image:url('data:image/svg+xml;utf8,${encodeURIComponent(svg)}')"></div>`;
}

function accessNote(d) {
  if (d.code) return ` Password: <span class="doc-code">${esc(d.code)}</span>`;
  if (d.category === "Division") return " Command only.";
  return " Open to all deputies.";
}

function openDoc(id) {
  if (!isAdmin() && id.startsWith("locked-")) return showUnlock();
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
      <span>${esc(d.category)}${d.division ? `: ${esc(d.division)}` : ""}. Updated ${esc(fmtDate(d.updatedAt))}${d.updatedBy ? ` by ${esc(d.updatedBy)}` : ""}.${isAdmin() ? accessNote(d) : ""}</span>
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
function syncDivisionField() { $("#d-division-field").hidden = $("#d-category").value !== "Division"; }
function updatePreview() { $("#d-preview").innerHTML = render($("#d-body").value) || "<p class='hint'>The preview shows here as you type.</p>"; }
$("#d-category").addEventListener("change", syncDivisionField);
$("#d-body").addEventListener("input", updatePreview);
$("#doc-new").addEventListener("click", () => openDocEditor(null));

// Readable random password, e.g. "sod-k7mq-p2xd" (no letters that look alike).
$("#d-code-gen").addEventListener("click", () => {
  const abc = "abcdefghjkmnpqrstuvwxyz23456789";
  const part = () => [...crypto.getRandomValues(new Uint8Array(4))].map((b) => abc[b % abc.length]).join("");
  const source = $("#d-category").value === "Division" ? $("#d-division").value : $("#d-category").value;
  const prefix = source.split(" ").filter((w) => /^[A-Z]/.test(w) && !["Division", "Unit"].includes(w)).map((w) => w[0]).join("").toLowerCase() || "doc";
  $("#d-code").value = `${prefix}-${part()}-${part()}`;
});

$("#doc-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const title = $("#d-title").value.trim();
  if (!title) return ($("#doc-error").textContent = "Give the document a title.");
  const category = $("#d-category").value;
  const code = $("#d-code").value.trim();
  if (code && code.length < 6) return ($("#doc-error").textContent = "Document passwords must be at least 6 characters.");
  if (code && (code === state.codes.admin || code === state.codes.deputy)) return ($("#doc-error").textContent = "Use a different password from the deputy and command codes.");
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
  toast(editingDoc ? "Document saved." : "Document created.");
  changed();
  if (location.hash === `#docs/${doc.id}`) showDocs(doc.id);
  else location.hash = `docs/${doc.id}`;
});

$("#doc-delete").addEventListener("click", () => {
  if (!editingDoc || !confirm(`Delete "${editingDoc.title}"? This can't be undone.`)) return;
  forget(editingDoc.id);
  state.docs = state.docs.filter((d) => d !== editingDoc);
  $("#doc-dlg").close();
  toast("Document deleted.");
  changed();
  location.hash = "docs";
  showDocs();
});

// ---------- announcements ----------
function renderAnnouncements() {
  const list = [...state.announcements].reverse();
  $("#ann-list").innerHTML = list.length
    ? list.map((a) => `<div class="ann-item"><div><b>${esc(a.title)}</b><p>${esc(a.body)}</p><span class="hint">Posted ${esc(fmtDateTime(a.at))}${a.by ? ` by ${esc(a.by)}` : ""}</span></div><button class="btn btn-danger btn-sm" data-remove="${esc(a.id)}">Remove</button></div>`).join("")
    : `<p class="empty">No announcements yet. Anything you post shows on the home page.</p>`;
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
  toast("Announcement posted.");
  changed();
  renderAnnouncements();
});

$("#ann-list").addEventListener("click", (e) => {
  const id = e.target.closest("[data-remove]")?.dataset.remove;
  if (!id || !confirm("Remove this announcement from the home page?")) return;
  forget(id);
  state.announcements = state.announcements.filter((a) => a.id !== id);
  toast("Announcement removed.");
  changed();
  renderAnnouncements();
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
window.FCSO_PORTAL_READY = true;
(async () => {
  let saved;
  try { saved = JSON.parse(sessionStorage.getItem(SESSION_KEY)); } catch {}
  if (saved?.code) {
    $("#login-btn").disabled = true;
    $("#login-btn").textContent = "Unlocking...";
    try {
      await loadFile();
      await signIn(saved.name, saved.code, saved.docCodes || []);
      return;
    } catch {
      try { sessionStorage.removeItem(SESSION_KEY); } catch {}
    } finally {
      $("#login-btn").disabled = false;
      $("#login-btn").textContent = "Sign in";
    }
  }
  $("#login").hidden = false;
})();
