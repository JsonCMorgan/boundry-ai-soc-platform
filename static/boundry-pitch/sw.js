const CACHE = "boundry-pitch-v3";
const BASE = "/static/boundry-pitch/";
const ASSETS = [
  BASE + "index.html",
  BASE + "app.js",
  BASE + "quiz-data.js",
  BASE + "manifest.webmanifest",
  BASE + "icon-192.png",
];
self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(ASSETS).catch(() => null)).then(() => self.skipWaiting())
  );
});
self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});
self.addEventListener("fetch", (e) => {
  if (e.request.method !== "GET") return;
  e.respondWith(
    caches.match(e.request).then((r) => {
      if (r) return r;
      return fetch(e.request).catch(() => caches.match(BASE + "index.html"));
    })
  );
});
