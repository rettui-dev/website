// Sets the theme before the page paints: the saved choice, else the system's.
(function () {
  var root = document.documentElement;
  var saved = null;
  try { saved = localStorage.getItem('theme'); } catch (e) { /* storage blocked */ }
  var dark = saved === 'dark' || (saved !== 'light' && !matchMedia('(prefers-color-scheme: light)').matches);
  root.setAttribute('data-theme', dark ? 'dark' : 'light');

  document.addEventListener('DOMContentLoaded', function () {
    var button = document.getElementById('theme-toggle');
    if (!button) return;
    function show() {
      var isLight = root.getAttribute('data-theme') === 'light';
      button.textContent = isLight ? 'Theme: light' : 'Theme: dark';
      button.setAttribute('aria-label', 'Switch to ' + (isLight ? 'dark' : 'light') + ' theme');
    }
    button.addEventListener('click', function () {
      var next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('theme', next); } catch (e) { /* storage blocked */ }
      show();
    });
    show();
  });
})();
