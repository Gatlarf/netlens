// Netlens service worker: makes the app installable and opens it fast. It handles only the public interface files
// (HTML, JS, CSS, images), network first, so a new Netlens version is picked up at once. It NEVER touches the API,
// share links, metrics or anything with data in it: those always go straight to the server, so nothing private is
// stored on the device and nothing can be shown without logging in.
const CACHE = "netlens-shell";
const NEVER = ["api/", "share", "metrics"]; // share pages and links stay live, so a revoked link stops working at once
const BASE = new URL("./", self.location).pathname; // "/" or the sub-path Netlens is served under behind a reverse proxy

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  const url = new URL(req.url);
  if (req.method !== "GET" || url.origin !== self.location.origin || NEVER.some((p) => url.pathname.startsWith(BASE + p))) return;
  event.respondWith(
    fetch(req)
      .then((res) => {
        if (res.ok && res.type === "basic") {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
        }
        return res;
      })
      .catch(() => caches.match(req).then((hit) => hit || (req.mode === "navigate" ? caches.match("./") : undefined) || Response.error()))
  );
});
