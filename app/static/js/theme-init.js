// Runs before the page paints so a chosen theme never flashes the wrong colours first.
// (A classic script on purpose: the Content-Security-Policy forbids inline scripts.)
(function () {
  try {
    var saved = localStorage.getItem("netlens.theme");
    if (saved === "dark" || saved === "light") document.documentElement.setAttribute("data-theme", saved);
    if (localStorage.getItem("netlens.skin") === "hud") document.documentElement.setAttribute("data-skin", "hud");      // the HUD look sits on top of the dark theme
  } catch (e) {
    // storage unavailable: follow the system setting
  }
})();
