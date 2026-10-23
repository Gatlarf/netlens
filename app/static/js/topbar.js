// The top bar and the side menu: pop-up menus (Scan, account), the page menu (side menu, a slide-over on narrow screens), hiding on scroll on a phone,
// and publishing its height for the sticky bars below it.
const COMPACT = "(max-width: 1040px)";  // the side menu becomes a slide-over
const PHONE = "(max-width: 700px)";     // the bar also slides away while scrolling down

export function initTopbar() {
  const bar = document.getElementById("topbar");
  if (!bar) return;
  const nav = document.getElementById("nav");
  const navToggle = document.getElementById("nav-toggle");
  const userMenu = document.getElementById("user-menu");
  const userWrap = document.getElementById("user-menu-wrap");
  const body = document.body;
  const menus = [
    { btn: document.getElementById("scan-menu-btn"), panel: document.getElementById("scan-menu") },
    { btn: document.getElementById("user-menu-btn"), panel: userMenu },
  ];
  const compact = window.matchMedia(COMPACT);
  const inPageMenu = (m) => compact.matches && m.panel === userMenu;
  const HIDE_KEY = "netlens.menu.hidden";

  // the side menu: always there on a wide screen (the button folds it away, remembered), a slide-over on a narrow one
  const syncToggle = () => {
    const shown = compact.matches ? body.classList.contains("side-open") : !body.classList.contains("side-hidden");
    navToggle.setAttribute("aria-expanded", String(shown));
  };
  let wasHidden = false;
  try { wasHidden = localStorage.getItem(HIDE_KEY) === "1"; } catch (e) { /* private window */ }
  body.classList.toggle("side-hidden", wasHidden);
  syncToggle();

  const closeMenus = (except) => {
    for (const m of menus) {
      if (!m.btn || m === except) continue;
      if (inPageMenu(m)) continue;  // on a narrow screen the account menu is part of the side menu
      m.panel.hidden = true;
      m.btn.setAttribute("aria-expanded", "false");
    }
  };
  const closeNav = () => { body.classList.remove("side-open"); syncToggle(); };
  const anythingOpen = () => body.classList.contains("side-open") || menus.some((m) => m.panel && !m.panel.hidden && !inPageMenu(m));
  const closeAll = () => { closeMenus(); closeNav(); };

  for (const m of menus) {
    if (!m.btn) continue;
    m.btn.addEventListener("click", (event) => {
      event.stopPropagation();
      if (inPageMenu(m)) return;
      const open = m.panel.hidden;
      closeMenus(m);
      closeNav();
      m.panel.hidden = !open;
      m.btn.setAttribute("aria-expanded", String(open));
      showBar();
    });
    // choosing something in a menu closes it (the buttons keep their own handlers)
    m.panel.addEventListener("click", (event) => {
      if (event.target.closest("button, a")) closeAll();
    });
  }
  navToggle.addEventListener("click", (event) => {
    event.stopPropagation();
    closeMenus();
    if (compact.matches) body.classList.toggle("side-open");
    else {
      const hide = !body.classList.contains("side-hidden");
      body.classList.toggle("side-hidden", hide);
      try { localStorage.setItem(HIDE_KEY, hide ? "1" : "0"); } catch (e) { /* ignore */ }
    }
    syncToggle();
    showBar();
  });
  nav.addEventListener("click", (event) => {
    if (compact.matches && event.target.closest("a")) closeAll();
  });
  document.addEventListener("click", (event) => {
    if (!bar.contains(event.target) && !nav.contains(event.target)) closeAll();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || !anythingOpen()) return;
    const focusBtn = menus.find((m) => m.panel && !m.panel.hidden)?.btn || (body.classList.contains("side-open") ? navToggle : null);
    closeAll();
    if (focusBtn) focusBtn.focus();
  });
  window.addEventListener("hashchange", closeAll);

  // on a narrow screen the account menu lives at the end of the side menu: one place for everything
  const place = () => {
    if (compact.matches) {
      nav.appendChild(userMenu);
      userMenu.hidden = false;
    } else {
      userWrap.appendChild(userMenu);
      userMenu.hidden = true;
      menus[1].btn.setAttribute("aria-expanded", "false");
      body.classList.remove("side-open");
    }
    syncToggle();
  };
  compact.addEventListener("change", place);
  place();

  // height for the sticky bars below (Statistics sections, Settings menu)
  const root = document.documentElement;
  let hidden = false;
  const publish = () => {
    root.style.setProperty("--topbar-h", `${bar.offsetHeight}px`);
    root.style.setProperty("--topbar-vis", hidden ? "0px" : `${bar.offsetHeight}px`);
  };
  function setHidden(value) {
    if (hidden === value) return;
    hidden = value;
    bar.classList.toggle("bar-hidden", hidden);
    publish();
  }
  function showBar() { setHidden(false); }
  publish();
  window.addEventListener("resize", publish);
  if (window.ResizeObserver) new ResizeObserver(publish).observe(bar);

  // phone: slide away while reading down the page, come back on the way up
  const phone = window.matchMedia(PHONE);
  let lastY = window.scrollY;
  window.addEventListener("scroll", () => {
    const y = window.scrollY;
    if (!phone.matches || anythingOpen()) { lastY = y; showBar(); return; }
    if (y < 40 || y < lastY - 6) showBar();
    else if (y > lastY + 8 && y > bar.offsetHeight * 1.5) setHidden(true);
    lastY = y;
  }, { passive: true });
  phone.addEventListener("change", () => { if (!phone.matches) showBar(); });
}
