// A bar of tabs that slides away behind the top bar while you read down the page and comes back at once when you scroll up (like ProxMenux Monitor).
// The bar itself is sticky (css .settings-tabs, .page-tabs); this only toggles the class that moves it.
export function slideAwayOnScroll(bar) {
  let lastY = window.scrollY;
  const onScroll = () => {
    const y = window.scrollY;
    if (y < 80 || y < lastY - 2) bar.classList.remove("tabs-away");
    else if (y > lastY + 6) bar.classList.add("tabs-away");
    lastY = y;
  };
  window.addEventListener("scroll", onScroll, { passive: true });
  return () => window.removeEventListener("scroll", onScroll);
}
