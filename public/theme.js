// Sets the theme before the page paints: the saved choice, else the system's.
(function () {
  var root = document.documentElement;
  var saved = null;
  try { saved = localStorage.getItem('theme'); } catch (e) { /* storage blocked */ }
  var query = matchMedia('(prefers-color-scheme: light)');
  var dark = saved === 'dark' || (saved !== 'light' && !query.matches);
  root.setAttribute('data-theme', dark ? 'dark' : 'light');
  // With no saved choice the page follows the system, also when it changes while the page is open.
  function follow(e) {
    if (saved === 'dark' || saved === 'light') return;
    root.setAttribute('data-theme', e.matches ? 'light' : 'dark');
    var b = document.getElementById('theme-toggle');
    if (b) b.dispatchEvent(new Event('themechange'));
  }
  if (query.addEventListener) query.addEventListener('change', follow);
  // Lets the stylesheet show the theme button only when it can work.
  root.classList.add('js');

  document.addEventListener('DOMContentLoaded', function () {
    var button = document.getElementById('theme-toggle');
    if (!button) return;
    function show() {
      var isLight = root.getAttribute('data-theme') === 'light';
      button.textContent = isLight ? 'Theme: light' : 'Theme: dark';
      // The name starts with the visible text, so voice control can say what it sees.
      button.setAttribute('aria-label', button.textContent + ', switch to ' + (isLight ? 'dark' : 'light'));
    }
    button.addEventListener('click', function () {
      var next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      root.setAttribute('data-theme', next);
      saved = next;
      try { localStorage.setItem('theme', next); } catch (e) { /* storage blocked */ }
      show();
    });
    button.addEventListener('themechange', show);
    show();
  });
})();
