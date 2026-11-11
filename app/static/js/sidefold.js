// Folding the page menu (the side menu) for a page that wants the room: Settings while you are in it, the HUD after a while.
// The user's own choice with the menu button is never overridden: once the button was used the menu stays as they left it.
const WIDE = "(min-width: 1041px)";
let state = null;                                        // {wasHidden, touched, burger, onClick} while a page holds the menu folded

export const canFold = () => window.matchMedia(WIDE).matches;

function sync(burger) {
  if (burger) burger.setAttribute("aria-expanded", String(!document.body.classList.contains("side-hidden")));
}

// Fold the menu; returns false when it cannot be done here (a narrow screen has a slide-over menu already)
export function fold() {
  if (!canFold()) return false;
  const burger = document.getElementById("nav-toggle");
  if (!state) {
    state = { wasHidden: document.body.classList.contains("side-hidden"), touched: false, burger, onClick: () => { if (state) state.touched = true; } };
    if (burger) burger.addEventListener("click", state.onClick, true);
  }
  if (!state.touched) {
    document.body.classList.add("side-hidden");
    sync(burger);
  }
  return true;
}

// Show it again for a moment (the pointer at the left edge) without giving up the fold
export function peek(show) {
  if (!state || state.touched) return;
  document.body.classList.toggle("side-hidden", !show);
  sync(state.burger);
}

// Give the menu back as it was before the fold
export function unfold() {
  if (!state) return;
  const { wasHidden, touched, burger, onClick } = state;
  state = null;
  if (burger) burger.removeEventListener("click", onClick, true);
  if (touched) return;
  document.body.classList.toggle("side-hidden", wasHidden);
  sync(burger);
}

export const isFolded = () => Boolean(state);
