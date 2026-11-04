// Public employee directory, built from the roster when command saves in the portal.
const TIERS = [
  ["High Command", ["Sheriff", "Chief Deputy", "Major"]],
  ["Department Command Staff", ["Commander", "Captain", "Lieutenant"]],
  ["Supervisory Board", ["Sergeant"]],
  ["Patrol Staff", ["Corporal", "Master Deputy", "Deputy First Class", "Deputy", "Probationary Deputy"]],
  ["Cadets", ["Cadet"]],
];
const RANKS = TIERS.flatMap(([, ranks]) => ranks);

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const safePhoto = (p) => (typeof p === "string" && (/^data:image\/(jpeg|png|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(p) || /^https:\/\/[^\s"'<>]+$/.test(p)) ? p : "logo.png");
const rankOrder = (r) => { const i = RANKS.indexOf(r); return i === -1 ? 999 : i; };

document.getElementById("year").textContent = new Date().getFullYear();
const toggle = document.querySelector(".nav-toggle");
const nav = document.getElementById("nav");
toggle?.addEventListener("click", () => toggle.setAttribute("aria-expanded", String(nav.classList.toggle("open"))));

let people = [];

function card(p) {
  return `<article class="person">
    <img src="${esc(safePhoto(p.photo))}" alt="" loading="lazy" onerror="this.onerror=null;this.src='logo.png'">
    <div class="who">
      <div class="name">${esc(p.name)}</div>
      <div class="meta">${p.callsign ? `<span class="callsign">${esc(p.callsign)}</span>` : ""}${esc(p.rank || "Department member")}</div>
      ${p.email ? `<a href="mailto:${esc(p.email)}">${esc(p.email)}</a>` : ""}
    </div>
  </article>`;
}

function render() {
  const q = document.getElementById("q").value.trim().toLowerCase();
  const rank = document.getElementById("rank").value;
  const list = people.filter((p) => (!q || p.name.toLowerCase().includes(q) || (p.callsign || "").toLowerCase().includes(q)) && (!rank || p.rank === rank));
  const out = document.getElementById("list");
  if (!people.length) {
    out.innerHTML = `<p class="empty">The directory hasn't been published yet. Check back soon.</p>`;
  } else if (!list.length) {
    out.innerHTML = `<p class="empty">No one matches that search.</p>`;
  } else {
    const groups = TIERS.map(([tier, ranks]) => [tier, list.filter((p) => ranks.includes(p.rank))]);
    const other = list.filter((p) => !RANKS.includes(p.rank));
    if (other.length) groups.push(["Department Members", other]);
    out.innerHTML = groups
      .filter(([, members]) => members.length)
      .map(([tier, members]) => `<section class="tier"><h2>${esc(tier)}</h2><div class="people">${members.map(card).join("")}</div></section>`)
      .join("");
  }
  document.getElementById("count").textContent = people.length ? `Showing ${list.length} of ${people.length} members.` : "";
}

fetch(`content.json?t=${Date.now()}`, { cache: "no-store" })
  .then((r) => (r.ok ? r.json() : null))
  .then((data) => {
    people = (data?.public?.directory || []).slice().sort((a, b) => rankOrder(a.rank) - rankOrder(b.rank) || String(a.callsign).localeCompare(String(b.callsign), undefined, { numeric: true }));
    const used = RANKS.filter((r) => people.some((p) => p.rank === r));
    document.getElementById("rank").innerHTML += used.map((r) => `<option>${esc(r)}</option>`).join("");
    render();
  })
  .catch(() => render());

document.getElementById("q").addEventListener("input", render);
document.getElementById("rank").addEventListener("change", render);
