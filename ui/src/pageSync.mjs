// The NS8 shell shows this app in an iframe and navigates by changing the URL of the PARENT window
// (#/apps/<instance>?page=<page>); it never tells the app. The app has to watch that URL itself.

// Page requested by the parent URL ("" when none). Only the part after "#" is read: it is the shell's own route.
export function pageFromUrl(url) {
  const hash = String(url).split("#").slice(1).join("#");
  const query = hash.includes("?") ? hash.slice(hash.indexOf("?") + 1) : "";
  return new URLSearchParams(query).get("page") || "";
}

// Switches the app to `page` (settings when empty) unless it is unknown or already shown. Returns true when it moved.
export function navigateToPage(router, current, page) {
  const target = router.resolve("/" + (page || "settings"));
  if (!target.route.matched.length || target.route.name === current.name) return false;
  const moved = router.replace(target.location);
  if (moved && typeof moved.catch === "function") moved.catch(() => {});
  return true;
}

// Calls onPage(page) whenever the parent URL changes. Returns a function that stops the watcher.
// The shell's router changes the URL with history.pushState, which fires NO event: the poll is what notices menu
// clicks of the shell and links from other modules. Back/forward (popstate) and manual hash edits are noticed at once.
export function startPageSync(win, onPage, intervalMs = 500, timers = {
  // not bare references: a browser's setInterval throws "Illegal invocation" when called as a method of another object
  setInterval: (...args) => setInterval(...args),
  clearInterval: (id) => clearInterval(id),
}) {
  let last = win.location.href;
  const check = () => {
    const url = win.location.href;
    if (url === last) return;
    last = url;
    onPage(pageFromUrl(url));
  };
  const id = timers.setInterval(check, intervalMs);
  if (win.addEventListener) {
    win.addEventListener("popstate", check);
    win.addEventListener("hashchange", check);
  }
  return () => {
    timers.clearInterval(id);
    if (win.removeEventListener) {
      win.removeEventListener("popstate", check);
      win.removeEventListener("hashchange", check);
    }
  };
}
