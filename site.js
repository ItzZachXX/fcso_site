// Public site: mobile menu and announcements (from content.json, saved by command through the portal).
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

document.getElementById("year").textContent = new Date().getFullYear();

const toggle = document.querySelector(".nav-toggle");
const nav = document.getElementById("nav");
toggle?.addEventListener("click", () => {
  const open = nav.classList.toggle("open");
  toggle.setAttribute("aria-expanded", String(open));
});
nav?.addEventListener("click", (e) => {
  if (e.target.tagName === "A") {
    nav.classList.remove("open");
    toggle.setAttribute("aria-expanded", "false");
  }
});

fetch(`content.json?t=${Date.now()}`, { cache: "no-store" })
  .then((r) => (r.ok ? r.json() : null))
  .then((data) => {
    const list = (data?.public?.announcements || []).slice().reverse();
    if (!list.length) return;
    document.getElementById("ann-list").innerHTML = list
      .map((a) => {
        const d = new Date(a.at);
        return `<article class="ann"><time datetime="${d.toISOString()}">${d.toLocaleDateString(undefined, { month: "long", day: "numeric", year: "numeric" })}</time><div><h3>${esc(a.title)}</h3><p>${esc(a.body)}</p></div></article>`;
      })
      .join("");
    document.getElementById("announcements").classList.add("show");
  })
  .catch(() => {});
