// Shows /api/status and refreshes it. Text is set with textContent only.
(function () {
  var REFRESH_MS = 15000;
  var LABEL = { up: '● Up', down: '✕ Down', unknown: '? Unknown' };
  var TITLE = {
    up: 'All entry points are reachable',
    degraded: 'Some entry points are unreachable',
    down: 'No entry point is reachable',
    unknown: 'Waiting for the first check'
  };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function ago(iso) {
    if (!iso) return 'never';
    var s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    return Math.floor(s / 3600) + 'h ago';
  }

  function stat(label, value) {
    var s = el('span', null, label + ' ');
    s.appendChild(el('b', null, value));
    return s;
  }

  function hostItem(h) {
    var li = el('li', 'host');
    var head = el('div', 'host-head');
    head.appendChild(el('span', 'host-name', h.host + ':' + h.port));
    head.appendChild(el('span', 'pill ' + h.status, LABEL[h.status] || LABEL.unknown));
    li.appendChild(head);

    var stats = el('div', 'stats');
    stats.appendChild(stat('Connect', h.latencyMs === null ? '-' : h.latencyMs + ' ms'));
    stats.appendChild(stat('Uptime', h.uptimePercent === null ? '-' : h.uptimePercent + '%'));
    var checked = stat('Checked', ago(h.lastChecked));
    if (h.lastChecked) checked.title = new Date(h.lastChecked).toLocaleString();
    stats.appendChild(checked);
    if (h.error) stats.appendChild(stat('Error', h.error));
    li.appendChild(stats);

    var bar = el('div', 'bar');
    bar.setAttribute('role', 'img');
    var ups = h.history.filter(function (c) { return c.up; }).length;
    bar.setAttribute('aria-label', 'Last ' + h.history.length + ' checks: ' + ups + ' up, ' + (h.history.length - ups) + ' down');
    // Pad on the left so a short history still fills from the right.
    for (var i = h.history.length; i < 90; i++) bar.appendChild(el('span', 'none'));
    h.history.forEach(function (c) {
      var s = el('span', c.up ? 'up' : 'down');
      s.title = new Date(c.t).toLocaleString() + (c.up ? ': up, ' + c.ms + ' ms' : ': down');
      bar.appendChild(s);
    });
    li.appendChild(bar);
    return li;
  }

  function render(data) {
    var banner = document.getElementById('banner');
    banner.className = 'banner ' + data.overall;
    document.getElementById('banner-title').textContent = TITLE[data.overall] || TITLE.unknown;
    var up = data.hosts.filter(function (h) { return h.status === 'up'; }).length;
    document.getElementById('banner-sub').textContent =
      up + ' of ' + data.hosts.length + ' up. Last checked ' + ago(data.checkedAt) + '.';
    var list = document.getElementById('hosts');
    list.replaceChildren.apply(list, data.hosts.map(hostItem));
  }

  function load() {
    fetch('/api/status', { cache: 'no-store' })
      .then(function (r) {
        if (!r.ok) throw new Error('status ' + r.status);
        return r.json();
      })
      .then(render)
      .catch(function () {
        var banner = document.getElementById('banner');
        banner.className = 'banner unknown';
        document.getElementById('banner-title').textContent = 'Status unavailable';
        document.getElementById('banner-sub').textContent = 'Could not reach the status service. Trying again shortly.';
      });
  }

  load();
  setInterval(load, REFRESH_MS);
})();
