(function () {
  var t = null;
  try { t = localStorage.getItem("theme"); } catch (e) {}
  var dark = t ? t === "dark" : !window.matchMedia || window.matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.classList.toggle("dark", dark);
})();
