// A progress bar under the spinner of index.html while the scripts and style sheets come in (a classic script on purpose: it runs
// right after the spinner is painted, before the module scripts are fetched). It counts the files the page lists up front.
(function () {
  var bar = document.getElementById("boot-bar");
  if (!bar || !window.PerformanceObserver) return;
  var done = 0;
  function expected() {
    return document.querySelectorAll('link[rel="modulepreload"], link[rel="stylesheet"]').length + 2;
  }
  function update() {
    var total = Math.max(expected(), 1);
    bar.style.width = Math.min(95, Math.round((done / total) * 95)) + "%";
    if (!document.getElementById("boot")) observer.disconnect();
  }
  var observer = new PerformanceObserver(function (list) {
    done += list.getEntries().filter(function (e) { return /\.(js|css)(\?|$)/.test(e.name) && e.name.indexOf("/boot.js") < 0; }).length;
    update();
  });
  try {
    observer.observe({ type: "resource", buffered: true });
  } catch (e) {
    // no resource timing: the spinner alone is shown
  }
})();
