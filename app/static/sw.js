// Offline shell only: never cache API responses, previews or private documents.
const CACHE = 'archivraum-shell-v7';
const ASSETS = ['/static/style.css', '/static/app.js', '/static/features.js', '/static/icon.svg', '/static/icon-192.png', '/static/icon-512.png'];
self.addEventListener('install', event => { event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(ASSETS))); self.skipWaiting(); });
self.addEventListener('activate', event => { event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET' || new URL(event.request.url).origin !== self.location.origin) return;
  const path = new URL(event.request.url).pathname;
  if (path.startsWith('/api/')) return;
  if (ASSETS.includes(path)) event.respondWith(fetch(event.request).then(response => { if (response.ok) { const copy = response.clone(); caches.open(CACHE).then(cache => cache.put(event.request, copy)); } return response; }).catch(() => caches.match(event.request)));
  else if (event.request.mode === 'navigate') event.respondWith(fetch(event.request).catch(() => new Response('<!doctype html><html lang="de"><meta name="viewport" content="width=device-width"><title>Archivraum – offline</title><body><h1>Sie sind offline.</h1><p>Für den Zugriff auf Ihre Dokumente wird eine Verbindung zum DMS benötigt.</p><a href="/">Erneut verbinden</a></body></html>', {headers: {'Content-Type': 'text/html; charset=utf-8'}})));
});
