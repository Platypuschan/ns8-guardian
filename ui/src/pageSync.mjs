// The NS8 shell shows this app in an iframe and navigates by changing the URL of the PARENT window
// (#/apps/<instance>?page=<page>); it never tells the app. The app has to watch that URL itself.

// Page requested by the parent URL ("" when none). Only the part after "#" is read: it is the shell's own route.
export function pageFromUrl(url) {
  const hash = String(url).split("#").slice(1).join("#");
  const query = hash.includes("?") ? hash.slice(hash.indexOf("?") + 1) : "";
  return new URLSearchParams(query).get("page") || "";
}

// Calls onPage(page) whenever the parent URL changes. Returns a function that stops the watcher.
export function startPageSync(win, onPage, intervalMs = 500, timers = {
    // not bare references: a browser's setInterval throws "Illegal invocation" when called as a method of another object
    setInterval: (...args) => setInterval(...args),
    clearInterval: (id) => clearInterval(id),
  }) {
  let last = win.location.href;
  const id = timers.setInterval(() => {
    const url = win.location.href;
    if (url === last) return;
    last = url;
    onPage(pageFromUrl(url));
  }, intervalMs);
  return () => timers.clearInterval(id);
}
