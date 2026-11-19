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
    if (h.hasDetail) li.appendChild(detailButton(h));

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

  // ---- Details: pure helpers (also used by the tests) ----

  var SVG_NS = 'http://www.w3.org/2000/svg';
  var RANGE_WORDS = { '6h': 'last 6 hours', '24h': 'last 24 hours', '7d': 'last 7 days' };
  var RANGE_MS = { '6h': 6 * 3600000, '24h': 24 * 3600000, '7d': 7 * 86400000 };
  var DETAIL_REFRESH_MS = 60000;

  // 1536 -> "1.5 KiB/s". Fractions of a byte show as "0 B/s".
  function formatRate(bps) {
    return bytes(bps) + '/s';
  }

  // The tick values of a y axis from 0: a "nice" step (1, 2 or 5 times a power
  // of ten) so that about `count` steps cover max. Always at least one step.
  function niceTicks(max, count) {
    var n = count || 4;
    if (!(max > 0) || !isFinite(max)) return [0, 1];
    var raw = max / n;
    var pow = Math.pow(10, Math.floor(Math.log(raw) / Math.LN10));
    var f = raw / pow;
    var step = (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * pow;
    var ticks = [];
    for (var v = 0; v < max + step * 0.999; v += step) ticks.push(Math.round(v / step) * step);
    return ticks;
  }

  // Splits [[t, v|null]] into runs of consecutive values, so gaps are not joined.
  function runs(points) {
    var out = [];
    var cur = [];
    points.forEach(function (p) {
      if (p[1] === null || typeof p[1] !== 'number' || !isFinite(p[1])) {
        if (cur.length) out.push(cur);
        cur = [];
      } else {
        cur.push(p);
      }
    });
    if (cur.length) out.push(cur);
    return out;
  }

  // Last, smallest, largest and average of the values; null when there are none.
  function summarize(points) {
    var v = points.filter(function (p) { return p[1] !== null && isFinite(p[1]); });
    if (!v.length) return null;
    var vals = v.map(function (p) { return p[1]; });
    return {
      last: vals[vals.length - 1],
      min: Math.min.apply(null, vals),
      max: Math.max.apply(null, vals),
      avg: vals.reduce(function (a, b) { return a + b; }, 0) / vals.length
    };
  }

  // "now 1.2 KiB/s, average 900 B/s, peak 4 KiB/s", or "no data".
  function summaryText(points, fmt) {
    var s = summarize(points);
    if (!s) return 'no data';
    return 'now ' + fmt(s.last) + ', average ' + fmt(s.avg) + ', peak ' + fmt(s.max);
  }

  // The label of a time on the x axis: the clock, with the weekday over 7 days.
  function axisTime(t, range) {
    var d = new Date(t);
    var clockText = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
    return range !== '6h' ? d.toLocaleDateString([], { weekday: 'short' }) + ' ' + clockText : clockText;
  }

  // Whole numbers with thousands separators; fractions only below 10.
  function count(n) {
    if (!isFinite(n)) return '-';
    return n < 10 && n !== Math.floor(n) ? String(Math.round(n * 10) / 10) : num(Math.round(n));
  }

  // The peer breakdown: label, count and share of all peers heard (whole
  // percent). "Other" is whatever the three kinds do not cover.
  function peerShares(p) {
    var total = p.total;
    function pct(n) { return total > 0 ? Math.round((n / total) * 100) : 0; }
    var rows = [
      { key: 'lxmf', label: 'LXMF', count: p.lxmf, percent: pct(p.lxmf) },
      { key: 'nomad', label: 'NomadNet', count: p.nomad, percent: pct(p.nomad) },
      { key: 'propagation', label: 'Propagation', count: p.propagation, percent: pct(p.propagation) }
    ];
    var rest = total - p.lxmf - p.nomad - p.propagation;
    if (rest > 0) rows.push({ key: 'other', label: 'Other', count: rest, percent: pct(rest) });
    return rows;
  }

  // Null when every node with stats runs the same version, else a sentence
  // naming each version and the hosts on it.
  function versionSummary(hosts) {
    var byVersion = {};
    var order = [];
    hosts.forEach(function (h) {
      var v = h.stats && h.stats.data && h.stats.data.rettuiVersion;
      if (!v) return;
      if (!Object.prototype.hasOwnProperty.call(byVersion, v)) {
        byVersion[v] = [];
        order.push(v);
      }
      byVersion[v].push(h.port === undefined ? h.host : h.host + ':' + h.port);
    });
    if (order.length < 2) return null;
    return 'Nodes run different versions: ' + order.map(function (v) {
      return v + ' (' + byVersion[v].join(', ') + ')';
    }).join('; ') + '.';
  }

  // ---- Details: drawing ----

  function svg(tag, attrs, cls) {
    var e = document.createElementNS(SVG_NS, tag);
    if (cls) e.setAttribute('class', cls);
    for (var k in attrs) e.setAttribute(k, String(attrs[k]));
    return e;
  }

  function svgText(text, attrs) {
    var t = svg('text', attrs);
    t.textContent = text;
    return t;
  }

  function swatch(cls) {
    var s = svg('svg', { width: 22, height: 10, viewBox: '0 0 22 10', 'aria-hidden': 'true', focusable: 'false' }, 'swatch');
    s.appendChild(svg('line', { x1: 1, x2: 21, y1: 5, y2: 5 }, 'ln ' + cls));
    return s;
  }

  // A line chart as an SVG sized to `width` pixels. lines: [{label, cls, points}],
  // points [[t ms, value|null]]. Gaps in the data are gaps in the line.
  function lineChart(o) {
    var fmt = o.fmt;
    var all = [];
    o.lines.forEach(function (l) { all = all.concat(l.points); });
    var top = summarize(all);
    var ticks = niceTicks(top ? top.max : 0, 4);
    var yMax = ticks[ticks.length - 1];
    var labels = ticks.map(fmt);
    var widest = labels.reduce(function (a, s) { return Math.max(a, s.length); }, 1);
    var left = Math.ceil(widest * 6.8) + 10;
    var w = Math.max(240, Math.floor(o.width));
    var h = w < 420 ? 150 : 180;
    var right = 10;
    var topPad = 8;
    var bottom = 22;
    var pw = w - left - right;
    var ph = h - topPad - bottom;
    function x(t) { return left + ((t - o.from) / (o.to - o.from)) * pw; }
    function y(v) { return topPad + ph - (v / yMax) * ph; }

    var fig = el('figure', 'chart');
    var legend = el('ul', 'legend');
    o.lines.forEach(function (l) {
      var li = el('li');
      li.appendChild(swatch(l.cls));
      li.appendChild(document.createTextNode(l.label));
      legend.appendChild(li);
    });
    var summary = o.lines.map(function (l) { return l.label + ': ' + summaryText(l.points, fmt); }).join('. ');
    var chart = svg('svg', { viewBox: '0 0 ' + w + ' ' + h, width: w, height: h, role: 'img', 'aria-label': o.title + ', ' + RANGE_WORDS[o.range] + '. ' + summary + '.' });
    ticks.forEach(function (v, i) {
      chart.appendChild(svg('line', { x1: left, x2: w - right, y1: y(v), y2: y(v) }, i === 0 ? 'axis' : 'grid'));
      chart.appendChild(svgText(labels[i], { x: left - 6, y: y(v) + 4, 'text-anchor': 'end' }));
    });
    // On a narrow chart the middle label would touch the end ones.
    (w < 420 ? [[0, 'start'], [1, 'end']] : [[0, 'start'], [0.5, 'middle'], [1, 'end']]).forEach(function (p) {
      var t = o.from + (o.to - o.from) * p[0];
      var px = left + pw * p[0];
      chart.appendChild(svgText(axisTime(t, o.range), { x: px, y: h - 6, 'text-anchor': p[1] }));
    });
    o.lines.forEach(function (l) {
      runs(l.points).forEach(function (run) {
        if (run.length === 1) {
          chart.appendChild(svg('circle', { cx: x(run[0][0]), cy: y(run[0][1]), r: 2.5 }, 'dot ' + l.cls));
          return;
        }
        var d = run.map(function (p, i) { return (i ? 'L' : 'M') + x(p[0]).toFixed(1) + ' ' + y(p[1]).toFixed(1); }).join('');
        chart.appendChild(svg('path', { d: d }, 'ln ' + l.cls));
      });
    });
    var caption = el('figcaption', 'chart-note', summary + '.');
    caption.setAttribute('aria-hidden', 'true');
    fig.appendChild(legend);
    fig.appendChild(chart);
    fig.appendChild(caption);
    return fig;
  }

  // The stacked bar of the peer kinds, as an SVG.
  function peerBar(rows, total, width) {
    var sum = rows.reduce(function (a, r) { return a + r.count; }, 0);
    var scale = Math.max(total, sum, 1);
    var w = Math.max(200, Math.floor(width));
    var bar = svg('svg', { viewBox: '0 0 ' + w + ' 20', width: w, height: 20, role: 'img',
      'aria-label': 'Peers heard by kind: ' + rows.map(function (r) { return r.label + ' ' + r.count + ' (' + r.percent + '%)'; }).join(', ') });
    bar.appendChild(svg('rect', { x: 0, y: 0, width: w, height: 20, rx: 3 }, 'bar-bg'));
    var at = 0;
    rows.forEach(function (r, i) {
      var sw = (r.count / scale) * w;
      if (sw <= 0) return;
      bar.appendChild(svg('rect', { x: at.toFixed(1), y: 0, width: Math.max(sw - (i < rows.length - 1 ? 1 : 0), 0.5).toFixed(1), height: 20 }, 'fill ' + SHARE_CLASS[r.key]));
      at += sw;
    });
    return bar;
  }

  var SHARE_CLASS = { lxmf: 'c1', nomad: 'c2', propagation: 'c3', other: 'c5' };

  // ---- Details: the dialog ----

  var dlg = null;
  var detailHost = null;
  var detailRange = '24h';
  var detailData = null;
  var detailSeq = 0;
  var detailTimer = null;
  var resizeTimer = null;

  function detailButton(h) {
    var key = h.host + ':' + h.port;
    var b = el('button', 'detail-btn', 'Details');
    b.type = 'button';
    b.setAttribute('data-host', key);
    b.setAttribute('aria-label', 'Details for ' + key);
    b.addEventListener('click', function () { openDetail(key); });
    return b;
  }

  function section(title) {
    var s = el('section', 'detail-section');
    s.appendChild(el('h3', null, title));
    return s;
  }

  function when(iso) {
    return new Date(iso).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
  }

  function bodyWidth() {
    var body = document.getElementById('detail-body');
    return body.clientWidth > 0 ? body.clientWidth : 320;
  }

  function versionSection(d) {
    var s = section('Version');
    var cur = d.stats && d.stats.data ? d.stats.data : null;
    var dl = el('dl', 'facts');
    function fact(k, v) {
      dl.appendChild(el('dt', null, k));
      dl.appendChild(el('dd', null, v));
    }
    fact('Running', d.version.current || 'unknown');
    fact('Node up', d.version.uptimeSeconds === null ? 'unknown' : duration(d.version.uptimeSeconds));
    if (cur) {
      fact('Interfaces', cur.interfaces.online + '/' + cur.interfaces.total + ' online');
      if (cur.interfaces.clients !== null) fact('Clients', num(cur.interfaces.clients));
      fact('Traffic since start', '↓ ' + bytes(cur.interfaces.rxBytes) + ' ↑ ' + bytes(cur.interfaces.txBytes));
    }
    s.appendChild(dl);
    if (d.stats && d.stats.stale) s.appendChild(el('p', 'note', 'These numbers are stale: the last fetch failed.'));
    if (d.version.history.length) {
      s.appendChild(el('h4', null, 'Versions seen'));
      var ul = el('ul', 'versions');
      d.version.history.slice().reverse().forEach(function (v) {
        var li = el('li', null, v.version);
        li.appendChild(el('span', 'muted', ' since ' + when(v.firstSeen)));
        ul.appendChild(li);
      });
      s.appendChild(ul);
    }
    var note = lastData ? versionSummary(lastData.hosts) : null;
    if (note) s.appendChild(el('p', 'note', note));
    return s;
  }

  function peersSection(d, ser, width, collecting) {
    var s = section('Peers heard');
    var cur = d.stats && d.stats.data ? d.stats.data.peersHeard : null;
    if (cur) {
      var rows = peerShares(cur);
      s.appendChild(el('p', 'total', num(cur.total) + ' peers heard now'));
      s.appendChild(peerBar(rows, cur.total, width));
      var ul = el('ul', 'shares');
      rows.forEach(function (r) {
        var li = el('li');
        var sw = svg('svg', { width: 12, height: 12, viewBox: '0 0 12 12', 'aria-hidden': 'true', focusable: 'false' }, 'swatch-box');
        sw.appendChild(svg('rect', { x: 0, y: 0, width: 12, height: 12, rx: 2 }, 'fill ' + SHARE_CLASS[r.key]));
        li.appendChild(sw);
        li.appendChild(el('span', 'share-label', r.label));
        li.appendChild(el('b', null, num(r.count)));
        li.appendChild(el('span', 'muted', r.percent + '%'));
        ul.appendChild(li);
      });
      s.appendChild(ul);
    } else {
      s.appendChild(el('p', 'note', 'Stats unavailable.'));
    }
    if (!collecting) {
      s.appendChild(lineChart({
        title: 'Peers heard over time', range: d.range, from: ser.from, to: ser.to, width: width, fmt: count,
        lines: [
          { label: 'Total', cls: 'c4', points: ser.peers.total },
          { label: 'LXMF', cls: 'c1', points: ser.peers.lxmf },
          { label: 'NomadNet', cls: 'c2 d1', points: ser.peers.nomad },
          { label: 'Propagation', cls: 'c3 d2', points: ser.peers.propagation }
        ]
      }));
    }
    return s;
  }

  function renderDetail() {
    var body = document.getElementById('detail-body');
    var d = detailData;
    if (!d) return;
    var width = bodyWidth();
    var ser = d.series;
    var collecting = ser.sampleCount < 2;
    var parts = [versionSection(d)];
    if (collecting) {
      var empty = el('p', 'empty', 'Collecting data, graphs fill in over time.');
      empty.appendChild(el('span', 'muted', ' ' + ser.sampleCount + (ser.sampleCount === 1 ? ' sample' : ' samples') + ' so far in the ' + RANGE_WORDS[d.range] + '; one is taken about every 5 minutes.'));
      parts.push(empty);
    }
    parts.push(peersSection(d, ser, width, collecting));
    if (!collecting) {
      var net = section('Network usage');
      net.appendChild(lineChart({
        title: 'Network usage', range: d.range, from: ser.from, to: ser.to, width: width, fmt: formatRate,
        lines: [{ label: 'In', cls: 'c1', points: ser.bytesIn }, { label: 'Out', cls: 'c3 d1', points: ser.bytesOut }]
      }));
      parts.push(net);
      var cl = section('Clients');
      if (summarize(ser.clients)) {
        cl.appendChild(lineChart({ title: 'Clients', range: d.range, from: ser.from, to: ser.to, width: width, fmt: count, lines: [{ label: 'Clients', cls: 'c2', points: ser.clients }] }));
      } else {
        cl.appendChild(el('p', 'note', 'This node does not report its clients.'));
      }
      parts.push(cl);
      var an = section('Announces per minute');
      an.appendChild(lineChart({ title: 'Announces per minute', range: d.range, from: ser.from, to: ser.to, width: width, fmt: count, lines: [{ label: 'Announces', cls: 'c4', points: ser.announces }] }));
      parts.push(an);
    }
    body.replaceChildren.apply(body, parts);
  }

  function setRangeButtons() {
    var buttons = document.querySelectorAll('#detail-range button');
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].setAttribute('aria-pressed', buttons[i].getAttribute('data-range') === detailRange ? 'true' : 'false');
    }
  }

  function loadDetail(showLoading) {
    var body = document.getElementById('detail-body');
    var seq = ++detailSeq;
    if (showLoading) {
      detailData = null;
      body.replaceChildren(el('p', 'note', 'Loading...'));
    }
    var ctl = new AbortController();
    var timer = setTimeout(function () { ctl.abort(); }, TIMEOUT_MS);
    fetch('/api/stats?host=' + encodeURIComponent(detailHost) + '&range=' + detailRange, { cache: 'no-store', signal: ctl.signal })
      .then(function (r) {
        if (!r.ok) throw new Error('status ' + r.status);
        return r.json();
      })
      .then(function (data) {
        if (seq !== detailSeq) return;
        detailData = data;
        renderDetail();
      })
      .catch(function () {
        if (seq !== detailSeq || detailData) return;
        var retry = el('button', null, 'Try again');
        retry.type = 'button';
        retry.addEventListener('click', function () { loadDetail(true); });
        var p = el('p', 'note', 'Could not load the details. ');
        p.appendChild(retry);
        body.replaceChildren(p);
      })
      .then(function () { clearTimeout(timer); });
  }

  function openDetail(key) {
    detailHost = key;
    document.getElementById('detail-title').textContent = key;
    setRangeButtons();
    if (!dlg.open) dlg.showModal();
    loadDetail(true);
    clearInterval(detailTimer);
    detailTimer = setInterval(function () { loadDetail(false); }, DETAIL_REFRESH_MS);
  }

  function setupDetail() {
    dlg = document.getElementById('detail');
    if (!dlg || typeof dlg.showModal !== 'function') return;
    document.getElementById('detail-close').addEventListener('click', function () { dlg.close(); });
    // A click on the backdrop (the dialog itself, outside its content) closes it.
    dlg.addEventListener('click', function (e) { if (e.target === dlg) dlg.close(); });
    dlg.addEventListener('close', function () {
      clearInterval(detailTimer);
      detailSeq++;
      // The list is rebuilt on every refresh, so find the button again.
      var buttons = document.querySelectorAll('.detail-btn');
      for (var i = 0; i < buttons.length; i++) {
        if (buttons[i].getAttribute('data-host') === detailHost) {
          buttons[i].focus();
          break;
        }
      }
    });
    document.getElementById('detail-range').addEventListener('click', function (e) {
      var r = e.target && e.target.getAttribute && e.target.getAttribute('data-range');
      if (!r || r === detailRange || !RANGE_MS[r]) return;
      detailRange = r;
      setRangeButtons();
      loadDetail(false);
    });
    window.addEventListener('resize', function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function () { if (dlg.open) renderDetail(); }, 150);
    });
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
    globalThis.statusLogic = { ago: ago, barLabel: barLabel, bytes: bytes, duration: duration, nodeStatPairs: nodeStatPairs,
      formatRate: formatRate, niceTicks: niceTicks, runs: runs, summarize: summarize, summaryText: summaryText, axisTime: axisTime,
      peerShares: peerShares, versionSummary: versionSummary, count: count };
    return;
  }
  setupDetail();
  load();
  setInterval(load, REFRESH_MS);
  setInterval(tick, TICK_MS);
})();
