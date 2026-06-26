window.apiUrl = function apiUrl(path) {
  const base = window.APP_BASE || "";
  return `${base}${path.startsWith("/") ? path : `/${path}`}`;
};

window.pageUrl = window.apiUrl;
