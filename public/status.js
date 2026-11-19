// Shows /api/status and refreshes it. Text is set with textContent only.
(function () {
  var REFRESH_MS = 15000;
  var TIMEOUT_MS = 10000;
  var TICK_MS = 1000;
  var GLYPH = { up: '● ', down: '✕ ', unknown: '? ' };
  var WORD = { up: 'Up', down: 'Down', unknown: 'Unknown' };
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

  function clock(iso) {
    return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  // The bar's accessible name: how many checks, over what time, and how they went.
  function barLabel(history) {
    if (history.length === 0) return 'No checks yet';
    var ups = history.filter(function (c) { return c.up; }).length;
    return 'Last ' + history.length + ' checks, ' + clock(history[0].t) + ' to ' + clock(history[history.length - 1].t) +
      ': ' + ups + ' up, ' + (history.length - ups) + ' down';
  }

  // A time that the timer keeps current: "12s ago" counts up between fetches.
  function agoTime(iso) {
    var t = el('time', null, ago(iso));
    if (iso) {
      t.setAttribute('datetime', iso);
      t.setAttribute('data-ago', iso);
      t.title = new Date(iso).toLocaleString();
    }
    return t;
  }

  function stat(label, value) {
    var s = el('span', null, label + ' ');
    s.appendChild(typeof value === 'string' ? el('b', null, value) : value);
    return s;
  }

  // 1536 -> "1.5 KiB". Whole numbers below 1 KiB.
  function bytes(n) {
    var units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
    var i = 0;
    while (n >= 1024 && i < units.length - 1) {
      n /= 1024;
      i++;
    }
    return (i === 0 || n >= 100 ? Math.round(n) : Math.round(n * 10) / 10) + ' ' + units[i];
  }

  // 93784 -> "1d 2h", 3700 -> "1h 1m", 42 -> "42s": the two biggest units.
  function duration(sec) {
    var d = Math.floor(sec / 86400);
    var h = Math.floor((sec % 86400) / 3600);
    var m = Math.floor((sec % 3600) / 60);
    if (d > 0) return d + 'd ' + h + 'h';
    if (h > 0) return h + 'h ' + m + 'm';
    if (m > 0) return m + 'm ' + Math.floor(sec % 60) + 's';
    return Math.floor(sec) + 's';
  }

  function num(n) {
    return n.toLocaleString === undefined ? String(n) : n.toLocaleString('en-US');
  }

  // The words of the node stats line, as [label, value] pairs.
  function nodeStatPairs(d) {
    var pairs = [];
    if (d.interfaces.clients !== null) pairs.push(['Clients', num(d.interfaces.clients)]);
    pairs.push(['Interfaces', d.interfaces.online + '/' + d.interfaces.total + ' online']);
    pairs.push(['Traffic', '↓ ' + bytes(d.interfaces.rxBytes) + ' ↑ ' + bytes(d.interfaces.txBytes)]);
    pairs.push(['Peers heard', num(d.peersHeard.total)]);
    pairs.push(['Announces', num(d.announcesLastMinute) + '/min']);
    pairs.push(['Node up', duration(d.uptimeSeconds)]);
    return pairs;
  }

  // Null when the host has no stats URL, so nothing is drawn for it.
  function nodeStats(st) {
    if (!st) return null;
    var line = el('div', 'stats node-stats');
    if (!st.data) {
      line.classList.add('unavailable');
      line.appendChild(el('span', null, 'Stats unavailable'));
      return line;
    }
    nodeStatPairs(st.data).forEach(function (p) { line.appendChild(stat(p[0], p[1])); });
    if (st.stale) {
      line.classList.add('stale-stats');
      var note = el('span', 'muted', 'Stale, from ');
      note.appendChild(agoTime(st.fetchedAt));
      line.appendChild(note);
    }
    return line;
  }

  function hostItem(h) {
    var li = el('li', 'host');
    var head = el('div', 'host-head');
    head.appendChild(el('span', 'host-name', h.host + ':' + h.port));
    var pill = el('span', 'pill ' + h.status);
    var status = WORD[h.status] ? h.status : 'unknown';
    pill.appendChild(el('span', null, GLYPH[status])).setAttribute('aria-hidden', 'true');
    pill.appendChild(document.createTextNode(WORD[status]));
    head.appendChild(pill);
    li.appendChild(head);

    var stats = el('div', 'stats');
    stats.appendChild(stat('Connect', h.latencyMs === null ? 'n/a' : h.latencyMs + ' ms'));
    stats.appendChild(stat('Uptime', h.uptimePercent === null ? '-' : h.uptimePercent + '%'));
    stats.appendChild(stat('Checked', agoTime(h.lastChecked)));
    if (h.error) stats.appendChild(stat('Error', h.error));
    li.appendChild(stats);
    var node = nodeStats(h.stats);
    if (node) li.appendChild(node);

    var bar = el('div', 'bar');
    bar.setAttribute('role', 'img');
    bar.setAttribute('aria-label', barLabel(h.history));
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

  var lastData = null;
  var lastOk = 0;
  var failed = false;

  function setText(id, text) {
    var e = document.getElementById(id);
    // The headline is a live region: only touch it when the words change.
    if (e.textContent !== text) e.textContent = text;
  }

  function sub() {
    var text;
    if (!lastData) {
      text = 'Could not reach the status service. Trying again shortly.';
      setText('banner-sub', text);
      return;
    }
    var up = lastData.hosts.filter(function (h) { return h.status === 'up'; }).length;
    var banner = document.getElementById('banner-sub');
    banner.replaceChildren(document.createTextNode(up + ' of ' + lastData.hosts.length + ' up. '));
    if (failed) {
      banner.appendChild(document.createTextNode('Showing data from '));
      banner.appendChild(agoTime(new Date(lastOk).toISOString()));
      banner.appendChild(document.createTextNode(', not current. Could not reach the status service; trying again.'));
    } else {
      banner.appendChild(document.createTextNode('Last checked '));
      banner.appendChild(agoTime(lastData.checkedAt));
      banner.appendChild(document.createTextNode('.'));
    }
  }

  function render(data) {
    lastData = data;
    lastOk = Date.now();
    failed = false;
    document.body.classList.remove('stale');
    document.getElementById('banner').className = 'banner ' + data.overall;
    setText('banner-title', TITLE[data.overall] || TITLE.unknown);
    sub();
    var list = document.getElementById('hosts');
    list.replaceChildren.apply(list, data.hosts.map(hostItem));
    if (data.hosts.length > 0) list.setAttribute('aria-label', 'Entry points');
    else list.removeAttribute('aria-label');
  }

  function fail() {
    failed = true;
    if (lastData) {
      // Keep the old numbers, dimmed, and say how old they are.
      document.body.classList.add('stale');
    } else {
      document.getElementById('banner').className = 'banner unknown';
      setText('banner-title', 'Status unavailable');
    }
    sub();
  }

  // Keeps the "N s ago" texts moving between fetches.
  function tick() {
    var times = document.querySelectorAll('time[data-ago]');
    for (var i = 0; i < times.length; i++) {
      var text = ago(times[i].getAttribute('data-ago'));
      if (times[i].textContent !== text) times[i].textContent = text;
    }
  }

  function load() {
    var ctl = new AbortController();
    var timer = setTimeout(function () { ctl.abort(); }, TIMEOUT_MS);
    fetch('/api/status', { cache: 'no-store', signal: ctl.signal })
      .then(function (r) {
        if (!r.ok) throw new Error('status ' + r.status);
        return r.json();
      })
      .then(render)
      .catch(fail)
      .then(function () { clearTimeout(timer); });
  }

  if (typeof document === 'undefined') {
    // Loaded by the tests: expose the pure parts only.
    globalThis.statusLogic = { ago: ago, barLabel: barLabel, bytes: bytes, duration: duration, nodeStatPairs: nodeStatPairs };
    return;
  }
  load();
  setInterval(load, REFRESH_MS);
  setInterval(tick, TICK_MS);
})();
