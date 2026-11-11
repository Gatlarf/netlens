// Cards of different heights packed into a grid without holes: a short card moves up next to a tall one instead of being stretched to its height.
// The grid has small implicit rows (css .masonry) and every card spans as many of them as it is tall; "grid-auto-flow: dense" fills the gaps.
// A card that grows or shrinks (its numbers refresh) is measured again.
export function masonry(grid, { unit = 4, gap = 12 } = {}) {
  let frame = 0;
  const fit = () => {
    frame = 0;
    for (const card of grid.children) {
      if (!(card instanceof HTMLElement)) continue;
      const height = card.getBoundingClientRect().height;
      card.style.gridRowEnd = height ? `span ${Math.max(1, Math.ceil((height + gap) / unit))}` : "";
    }
  };
  const soon = () => { if (!frame) frame = requestAnimationFrame(fit); };
  let sizes = null;
  if (typeof ResizeObserver !== "undefined") {
    sizes = new ResizeObserver(soon);
    sizes.observe(grid);
  }
  const watch = () => { if (sizes) for (const card of grid.children) sizes.observe(card); };
  const changes = new MutationObserver(() => { watch(); fit(); });
  changes.observe(grid, { childList: true });
  watch();
  grid.classList.add("masonry");
  fit();
  return { refresh: fit, stop: () => { changes.disconnect(); if (sizes) sizes.disconnect(); if (frame) cancelAnimationFrame(frame); grid.classList.remove("masonry"); } };
}
