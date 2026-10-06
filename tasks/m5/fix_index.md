Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
Add a fourth stylesheet link <link rel="stylesheet" href="css/terminal.css"> after the css/map.css link.

CURRENT FILE:
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Netlens</title>
  <link rel="stylesheet" href="css/app.css">
  <link rel="stylesheet" href="css/pages.css">
  <link rel="stylesheet" href="css/map.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="#/">Netlens</a>
    <nav id="nav">
      <a class="nav-link" href="#/map" data-route="map">Map</a>
      <a class="nav-link" href="#/devices" data-route="devices">Devices</a>
      <a class="nav-link" href="#/scans" data-route="scans">Scans &amp; events</a>
      <a class="nav-link" href="#/settings" data-route="settings">Settings</a>
    </nav>
    <div class="topbar-actions">
      <span id="scan-status" class="scan-status"></span>
      <button id="scan-quick" class="btn">Quick scan</button>
      <button id="scan-deep" class="btn">Deep scan</button>
      <button id="logout" class="btn ghost">Log out</button>
    </div>
  </header>

  <main id="view" class="view" tabindex="-1"></main>

  <dialog id="login-dialog">
    <form id="login-form" method="dialog">
      <h2>Sign in</h2>
      <p>Enter the access token configured in NETLENS_TOKEN.</p>
      <label for="login-token">Access token</label>
      <input id="login-token" type="password" autocomplete="current-password" required>
      <p id="login-error" class="error" hidden></p>
      <button class="btn primary" type="submit">Sign in</button>
    </form>
  </dialog>

  <div id="toasts"></div>

  <script type="module" src="js/app.js"></script>
</body>
</html>