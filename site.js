// Public site: mobile menu, live numbers and announcements from the bot.
const API = window.FCSO_API || "https://api.fayettecountysheriffs.xyz";

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

async function loadPublic() {
  try {
    const res = await fetch(`${API}/api/public`);
    if (!res.ok) return;
    const data = await res.json();

    const live = document.getElementById("live");
    const parts = [];
    if (data.onDuty !== null && data.onDuty !== undefined) parts.push(`<b>${data.onDuty}</b> ${data.onDuty === 1 ? "deputy" : "deputies"} on duty right now`);
    if (data.members) parts.push(`<b>${data.members}</b> members in our Discord`);
    if (parts.length) live.innerHTML = parts.join(", ") + ".";

    if (data.announcements?.length) {
      const list = document.getElementById("ann-list");
      list.innerHTML = data.announcements
        .map((a) => {
          const d = new Date(a.at);
          return `<article class="ann"><time datetime="${d.toISOString()}">${d.toLocaleDateString(undefined, { month: "long", day: "numeric", year: "numeric" })}</time><div><h3>${esc(a.title)}</h3><p>${esc(a.body)}</p></div></article>`;
        })
        .join("");
      document.getElementById("announcements").classList.add("show");
    }
  } catch {
    // The site works fine without the live data.
  }
}
loadPublic();
