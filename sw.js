// Aperture Handbook (GitHub copy): decrypts the handbook in the browser.
// Every page, image and video piece is stored encrypted under d/<hashed name>. Requests for h/<path> come here: the file's
// name is worked out with the name key, fetched, decrypted with the AES key and returned as if GitHub had served it.
// The keys come from the sign-in page (index.html), which makes them from the password and keeps them in IndexedDB.
// Written by build-github.mjs; nothing secret lives in this file.
const SCOPE = self.registration.scope;               // https://<user>.github.io/<repo>/
const H = SCOPE + "h/";
const DB = "aperture-handbook";
const enc = new TextEncoder();
let keys = null;

const TYPES = {
  html: "text/html; charset=utf-8", css: "text/css; charset=utf-8", js: "text/javascript; charset=utf-8",
  json: "application/json; charset=utf-8", txt: "text/plain; charset=utf-8", srt: "text/plain; charset=utf-8",
  vtt: "text/vtt; charset=utf-8", svg: "image/svg+xml", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg",
  webp: "image/webp", gif: "image/gif", pdf: "application/pdf", woff2: "font/woff2",
  m3u8: "application/vnd.apple.mpegurl", m4s: "video/iso.segment", mp4: "video/mp4",
};

function idb(mode, fn) {
  return new Promise((ok, fail) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore("keys");
    r.onerror = () => fail(r.error);
    r.onsuccess = () => {
      const tx = r.result.transaction("keys", mode), q = fn(tx.objectStore("keys"));
      tx.oncomplete = () => ok(q && q.result);
      tx.onerror = () => fail(tx.error);
    };
  });
}
async function getKeys() {
  if (!keys) keys = (await idb("readonly", (s) => s.get("k"))) || null;
  if (keys && keys.exp < Date.now()) await signOut();
  return keys;
}
async function signOut() { keys = null; await idb("readwrite", (s) => s.delete("k")); }

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("message", (e) => { if (e.data === "keys-changed") keys = null; });
self.addEventListener("fetch", (e) => { if (e.request.url.startsWith(H)) e.respondWith(serve(e.request)); });

function toSignIn(req, url) {
  if (req.mode !== "navigate") return new Response("Signed out", { status: 401 });
  return Response.redirect(SCOPE + "?next=" + encodeURIComponent(decodeURIComponent(url.pathname.slice(new URL(H).pathname.length)) + url.search), 302);
}
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function serve(req) {
  const url = new URL(req.url);
  let rel = decodeURIComponent(url.pathname.slice(new URL(H).pathname.length));
  if (rel === "__signout") { await signOut(); return Response.redirect(SCOPE, 302); }
  const k = await getKeys();
  if (!k) return toSignIn(req, url);
  if (rel === "" || rel.endsWith("/")) rel += "index.html";
  const ext = (rel.match(/\.([a-z0-9]+)$/i) || ["", ""])[1].toLowerCase();
  const name = hex(await crypto.subtle.sign("HMAC", k.name, enc.encode(rel))).slice(0, 40);
  // pages and scripts are checked for a newer version every time; images and video use GitHub's own caching
  const res = await fetch(SCOPE + "d/" + name, { cache: /^(html|js|css|json)$/.test(ext) ? "no-cache" : "default" });
  if (!res.ok) {
    return new Response('<!doctype html><meta charset="utf-8"><title>Not found</title><p style="font-family:sans-serif;padding:2rem">'
      + 'This page isn\'t in the handbook. <a href="' + H + '">Go to the start</a>.</p>', { status: 404, headers: { "Content-Type": TYPES.html } });
  }
  const box = await res.arrayBuffer();
  let body;
  try { body = await crypto.subtle.decrypt({ name: "AES-GCM", iv: box.slice(0, 12) }, k.enc, box.slice(12)); }
  catch (_) { await signOut(); return toSignIn(req, url); }   // the password was changed since this device signed in
  const headers = { "Content-Type": TYPES[ext] || "application/octet-stream", "Cache-Control": "no-store", "Accept-Ranges": "bytes" };
  const range = /^bytes=(\d*)-(\d*)$/.exec(req.headers.get("range") || "");
  if (range && (range[1] || range[2])) {             // Safari asks for media in byte ranges
    const size = body.byteLength;
    let a = range[1] ? +range[1] : size - +range[2], b = range[1] && range[2] ? Math.min(+range[2], size - 1) : size - 1;
    if (a < 0) a = 0;
    if (a >= size) return new Response(null, { status: 416, headers: { "Content-Range": "bytes */" + size } });
    return new Response(body.slice(a, b + 1), { status: 206, headers: { ...headers, "Content-Range": `bytes ${a}-${b}/${size}` } });
  }
  return new Response(body, { headers });
}
