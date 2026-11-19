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

  var badges = false;
  var allHosts = [];

  function hostItem(h, members) {
    var li = el('li', 'host' + (h.role === 'proxy' ? ' proxy' : '') + (h.proxiedBy ? ' member' : ''));
    var head = el('div', 'host-head');
    var title = el('span', 'host-title');
    title.appendChild(el('span', 'host-name', displayName(h)));
    if (h.name) title.appendChild(el('span', 'host-addr', hostKey(h)));
    if (badges) {
      var badge = el('span', 'badge ' + h.role, badgeText(h));
      badge.title = badgeTitle(h, allHosts);
      badge.setAttribute('aria-label', badgeTitle(h, allHosts));
      title.appendChild(badge);
    }
    head.appendChild(title);
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
    if (h.group) li.appendChild(groupBlock(h, members || []));
    return li;
  }

  // The combined line of a proxy and the nodes behind it, nested under it.
  function groupBlock(h, members) {
    var g = h.group;
    var box = el('section', 'group');
    var heading = el('h3', null, 'All nodes (' + g.nodes + ')');
    heading.id = 'group-' + hostKey(h).replace(/[^a-z0-9]/gi, '-');
    box.setAttribute('aria-labelledby', heading.id);
    box.appendChild(heading);
    var names = {};
    allHosts.forEach(function (x) { names[hostKey(x)] = displayName(x); });
    if (g.data) {
      var line = el('div', 'stats node-stats');
      groupPairs(g).forEach(function (p) { line.appendChild(stat(p[0], p[1])); });
      box.appendChild(line);
      box.appendChild(el('p', 'note', g.data.peersHeard.exact
        ? 'Peers heard is de-duplicated: each peer is counted once, however many nodes heard it.'
        : 'Peers heard cannot be de-duplicated, so it is shown as a range (at least the largest node, at most the sum).' +
          (g.data.peersHeard.lists.have > 0 ? ' ' + g.data.peersHeard.lists.have + ' of ' + g.data.peersHeard.lists.of + ' nodes supplied peer lists.' : '')));
    } else {
      box.appendChild(el('p', 'note', 'No node of this group has reported stats.'));
    }
    var cover = el('p', 'note' + (g.partial ? ' partial' : ''), (g.partial ? 'Partial: ' : '') + groupCoverage(g, names) + (g.countOwn ? ', including this node' : '') + '.');
    box.appendChild(cover);
    if (members.length) {
      var ul = el('ul', 'members');
      ul.setAttribute('aria-label', 'Nodes behind ' + displayName(h));
      members.forEach(function (m) { ul.appendChild(hostItem(m)); });
      box.appendChild(ul);
    }
    return box;
  }


  // ---- Proxies and groups (pure helpers) ----

  function hostKey(h) { return h.host + ':' + h.port; }

  // The name to show: the configured display name, else the address.
  function displayName(h) { return h.name || hostKey(h); }

  // Badges only help once at least one proxy is configured; with the plain
  // environment setup every node would say the same thing.
  function showBadges(hosts) {
    return hosts.some(function (h) { return h.role === 'proxy'; });
  }

  function badgeText(h) { return h.role === 'proxy' ? 'Proxy' : 'RNS node'; }

  // The title and screen reader words of the badge.
  function badgeTitle(h, hosts) {
    if (h.role === 'proxy') {
      var n = h.proxy ? h.proxy.for.length : 0;
      return 'Proxy for ' + n + (n === 1 ? ' node' : ' nodes');
    }
    if (h.proxiedBy) {
      var p = hosts.filter(function (x) { return hostKey(x) === h.proxiedBy; })[0];
      return 'RNS node, behind the proxy ' + (p ? displayName(p) : h.proxiedBy);
    }
    return 'RNS node';
  }

  // The hosts in display order as [{h, members: [h]}]: a proxy is followed by
  // the nodes it proxies, in its own order, and those are not listed again.
  function groupHosts(hosts) {
    var byKey = {};
    hosts.forEach(function (h) { byKey[hostKey(h)] = h; });
    var out = [];
    hosts.forEach(function (h) {
      // A node whose proxy is not in the list stands on its own.
      if (h.proxiedBy && Object.prototype.hasOwnProperty.call(byKey, h.proxiedBy)) return;
      var members = h.proxy ? h.proxy.for.filter(function (k) { return Object.prototype.hasOwnProperty.call(byKey, k); }).map(function (k) { return byKey[k]; }) : [];
      out.push({ h: h, members: members });
    });
    return out;
  }

  // "3 to 9" for a lower and an upper bound; one number when they agree.
  function peerRange(low, high) {
    return low === high ? num(low) : num(low) + '–' + num(high);
  }

  // How many members reported, and which did not.
  function groupCoverage(g, names) {
    var text = g.reporting + ' of ' + g.nodes + ' nodes reporting';
    if (g.partial && g.missing.length) {
      text += ' (not: ' + g.missing.map(function (k) { return names && names[k] ? names[k] : k; }).join(', ') + ')';
    }
    return text;
  }

  // The [label, value] pairs of a group's combined stats line; [] without data.
  function groupPairs(g) {
    if (!g || !g.data) return [];
    var d = g.data;
    var pairs = [];
    if (d.interfaces.clients !== null) pairs.push(['Clients', num(d.interfaces.clients)]);
    pairs.push(['Interfaces', d.interfaces.online + '/' + d.interfaces.total + ' online']);
    pairs.push(['Traffic', '↓ ' + bytes(d.interfaces.rxBytes) + ' ↑ ' + bytes(d.interfaces.txBytes)]);
    pairs.push(['Peers heard', d.peersHeard.exact ? num(d.peersHeard.union.total) + ' (de-duplicated)' : peerRange(d.peersHeard.max.total, d.peersHeard.sum.total)]);
    pairs.push(['Announces', num(d.announcesLastMinute) + '/min']);
    return pairs;
  }

  // The sentence under a group's peers heard: exact, or a range and how many nodes sent lists.
  function peerNote(p) {
    if (p.exact) return 'Peers heard is de-duplicated: every reporting node supplied its peer list, so a peer heard by several nodes is counted once.';
    var text = PEER_NOTE;
    if (p.lists && p.lists.have > 0) text += ' ' + p.lists.have + ' of ' + p.lists.of + ' reporting nodes supplied a peer list; it takes all of them to remove the overlap.';
    return text;
  }

  var PEER_NOTE = 'Peers heard is a range: nodes publish counts only, so a peer heard by more than one node cannot be removed. The real number is at least the largest single node and at most the sum.';

  // The rows of the combined peer breakdown: label, range text, and the sum used for the bar.
  function peerRangeRows(p) {
    if (p.exact) {
      var u = p.union;
      var ex = [['lxmf', 'LXMF'], ['nomad', 'NomadNet'], ['propagation', 'Propagation']].map(function (k) {
        return { key: k[0], label: k[1], count: u[k[0]], text: num(u[k[0]]), percent: u.total > 0 ? Math.round((u[k[0]] / u.total) * 100) : 0 };
      });
      var other = u.total - u.lxmf - u.nomad - u.propagation;
      if (other > 0) ex.push({ key: 'other', label: 'Other', count: other, text: num(other), percent: u.total > 0 ? Math.round((other / u.total) * 100) : 0 });
      return ex;
    }
    var rows = [['lxmf', 'LXMF'], ['nomad', 'NomadNet'], ['propagation', 'Propagation']].map(function (k) {
      return { key: k[0], label: k[1], count: p.sum[k[0]], text: peerRange(p.max[k[0]], p.sum[k[0]]), percent: p.sum.total > 0 ? Math.round((p.sum[k[0]] / p.sum.total) * 100) : 0 };
    });
    var rest = p.sum.total - p.sum.lxmf - p.sum.nomad - p.sum.propagation;
    if (rest > 0) rows.push({ key: 'other', label: 'Other', count: rest, text: num(rest), percent: p.sum.total > 0 ? Math.round((rest / p.sum.total) * 100) : 0 });
    return rows;
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
  // With maxGap (ms), a hole in time wider than that also ends a run: samples
  // that were never taken are a gap too, not a straight line.
  function runs(points, maxGap) {
    var out = [];
    var cur = [];
    points.forEach(function (p) {
      if (cur.length && maxGap > 0 && p[0] - cur[cur.length - 1][0] > maxGap) {
        out.push(cur);
        cur = [];
      }
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

  // The widest step between neighbouring times that still counts as joined:
  // three times the usual (median) step. 0 when there are too few points.
  function gapLimit(points) {
    if (points.length < 3) return 0;
    var d = [];
    for (var i = 1; i < points.length; i++) d.push(points[i][0] - points[i - 1][0]);
    d.sort(function (a, b) { return a - b; });
    return d[Math.floor(d.length / 2)] * 3;
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

  // 300 -> "5 minutes", 60 -> "minute", 45 -> "45 seconds": for "about every ...".
  function intervalWords(sec) {
    if (!(sec > 0)) return 'so often';
    if (sec % 60 === 0) return sec === 60 ? 'minute' : sec / 60 + ' minutes';
    return sec === 1 ? 'second' : Math.round(sec) + ' seconds';
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


  // ---- Details: hover, touch and keyboard inspection (pure parts) ----

  // The index of the time nearest to t, clamped to the ends; -1 for no times.
  // Times are ascending. On a tie the earlier one wins.
  function nearestIndex(times, t) {
    var n = times.length;
    if (n === 0 || typeof t !== 'number' || t !== t) return -1;
    if (t <= times[0]) return 0;
    if (t >= times[n - 1]) return n - 1;
    var lo = 0;
    var hi = n - 1;
    while (hi - lo > 1) {
      var mid = (lo + hi) >> 1;
      if (times[mid] <= t) lo = mid; else hi = mid;
    }
    return t - times[lo] <= times[hi] - t ? lo : hi;
  }

  // The time under an x position on the plot (pixels), clamped to the window.
  function timeAt(px, left, width, from, to) {
    if (!(width > 0)) return from;
    var f = Math.min(Math.max((px - left) / width, 0), 1);
    return from + f * (to - from);
  }

  // "Thu, Nov 19, 2026, 06:28": the full local date and the 24 hour clock.
  function tooltipTitle(t) {
    return new Date(t).toLocaleString([], { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });
  }

  // One row per line at point `index`: {label, cls, text}. A missing or null
  // value reads "no data".
  function tooltipRows(lines, index, fmt) {
    return lines.map(function (l) {
      var p = index >= 0 && index < l.points.length ? l.points[index] : null;
      var ok = p && typeof p[1] === 'number' && isFinite(p[1]);
      return { label: l.label, cls: l.cls, text: ok ? fmt(p[1]) : 'no data' };
    });
  }

  // The words of a tooltip for a screen reader: "Thu, ...: In 3 KiB/s, Out no data".
  function tooltipSpeech(title, rows) {
    return title + ': ' + rows.map(function (r) { return r.label + ' ' + r.text; }).join(', ');
  }

  // Where the top left of a tooltip box goes: right of the anchor, flipped to the
  // left when it would pass the right edge, and kept inside the area.
  function tooltipPosition(ax, ay, boxW, boxH, areaW, areaH, gap) {
    var g = gap === undefined ? 12 : gap;
    var x = ax + g + boxW <= areaW ? ax + g : ax - g - boxW;
    x = Math.max(0, Math.min(x, Math.max(areaW - boxW, 0)));
    var y = Math.max(0, Math.min(ay - boxH / 2, Math.max(areaH - boxH, 0)));
    return { x: x, y: y };
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
      runs(l.points, gapLimit(l.points)).forEach(function (run) {
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
    var plot = el('div', 'plot');
    var tip = el('div', 'tip');
    tip.hidden = true;
    tip.setAttribute('aria-hidden', 'true');
    var live = el('div', 'sr-only');
    live.setAttribute('aria-live', 'polite');
    live.setAttribute('aria-atomic', 'true');
    plot.appendChild(chart);
    plot.appendChild(tip);
    plot.appendChild(live);
    fig.appendChild(legend);
    fig.appendChild(plot);
    fig.appendChild(caption);
    attachInspector({ chart: chart, tip: tip, live: live, o: o, left: left, pw: pw, w: w, h: h, x: x, y: y });
    return fig;
  }

  // A vertical guide, highlighted points and a tooltip for the sample nearest
  // to the pointer (mouse, pen or touch) or to the arrow keys.
  var hideActive = null;

  function attachInspector(c) {
    var o = c.o;
    var longest = o.lines.reduce(function (a, l) { return l.points.length > a.length ? l.points : a; }, []);
    var times = longest.map(function (p) { return p[0]; });
    if (times.length === 0) return;
    var guide = svg('line', { y1: 8, y2: c.h - 22, visibility: 'hidden' }, 'guide');
    var marks = o.lines.map(function (l) {
      var m = svg('circle', { r: 4, visibility: 'hidden' }, 'hp ' + l.cls);
      return m;
    });
    c.chart.appendChild(guide);
    marks.forEach(function (m) { c.chart.appendChild(m); });
    c.chart.setAttribute('tabindex', '0');
    var current = -1;

    function hide() {
      current = -1;
      c.tip.hidden = true;
      guide.setAttribute('visibility', 'hidden');
      marks.forEach(function (m) { m.setAttribute('visibility', 'hidden'); });
      if (hideActive === hide) hideActive = null;
    }

    // py is the pointer's y in pixels on the picture; null puts the box at the first value.
    function show(index, py, speak) {
      if (index < 0) return hide();
      if (hideActive && hideActive !== hide) hideActive();
      hideActive = hide;
      current = index;
      var t = times[index];
      var rect = c.chart.getBoundingClientRect();
      var scale = c.w > 0 && rect.width > 0 ? rect.width / c.w : 1;
      var gx = c.x(t);
      guide.setAttribute('x1', gx);
      guide.setAttribute('x2', gx);
      guide.setAttribute('visibility', 'visible');
      var firstY = null;
      o.lines.forEach(function (l, i) {
        var p = index < l.points.length ? l.points[index] : null;
        if (p && typeof p[1] === 'number' && isFinite(p[1])) {
          marks[i].setAttribute('cx', gx);
          marks[i].setAttribute('cy', c.y(p[1]));
          marks[i].setAttribute('visibility', 'visible');
          if (firstY === null) firstY = c.y(p[1]);
        } else {
          marks[i].setAttribute('visibility', 'hidden');
        }
      });
      var title = tooltipTitle(t);
      var rows = tooltipRows(o.lines, index, o.fmt);
      var head = el('div', 'tip-time', title);
      var list = el('ul', 'tip-rows');
      rows.forEach(function (r) {
        var li = el('li');
        li.appendChild(swatch(r.cls));
        li.appendChild(el('span', 'tip-label', r.label));
        li.appendChild(el('b', r.text === 'no data' ? 'muted' : null, r.text));
        list.appendChild(li);
      });
      c.tip.replaceChildren(head, list);
      c.tip.hidden = false;
      var anchorY = (py === null ? (firstY === null ? c.h / 2 : firstY) : py) * scale;
      var pos = tooltipPosition(gx * scale, anchorY, c.tip.offsetWidth, c.tip.offsetHeight, rect.width, rect.height);
      c.tip.style.left = Math.round(pos.x) + 'px';
      c.tip.style.top = Math.round(pos.y) + 'px';
      if (speak) c.live.textContent = tooltipSpeech(title, rows);
    }

    function fromPointer(e) {
      var rect = c.chart.getBoundingClientRect();
      var scale = rect.width > 0 ? c.w / rect.width : 1;
      var px = (e.clientX - rect.left) * scale;
      var py = (e.clientY - rect.top) * scale;
      show(nearestIndex(times, timeAt(px, c.left, c.pw, o.from, o.to)), py, false);
    }

    c.chart.addEventListener('pointerdown', fromPointer);
    c.chart.addEventListener('pointermove', fromPointer);
    // A finger that lifts leaves the tooltip up, so a tap can be read.
    c.chart.addEventListener('pointerleave', function (e) { if (e.pointerType !== 'touch') hide(); });
    c.chart.addEventListener('pointercancel', hide);
    c.chart.addEventListener('blur', function () { hide(); c.live.textContent = ''; });
    c.chart.addEventListener('keydown', function (e) {
      var next = null;
      if (e.key === 'ArrowLeft') next = current < 0 ? times.length - 1 : Math.max(current - 1, 0);
      else if (e.key === 'ArrowRight') next = current < 0 ? times.length - 1 : Math.min(current + 1, times.length - 1);
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = times.length - 1;
      else if (e.key === 'Escape' && current >= 0) {
        // Close the tooltip only; a second Escape closes the dialog.
        e.preventDefault();
        e.stopPropagation();
        hide();
        return;
      } else return;
      e.preventDefault();
      show(next, null, true);
    });
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
  var detailChoice = 'combined';
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

  function emptyState(d, ser) {
    var empty = el('p', 'empty', 'Collecting data, graphs fill in over time.');
    var what = d.view === 'combined' ? 'complete' : '';
    empty.appendChild(el('span', 'muted', ' ' + ser.sampleCount + (what ? ' ' + what : '') + (ser.sampleCount === 1 ? ' sample' : ' samples') + ' so far in the ' + RANGE_WORDS[d.range] + '; one is taken about every ' + intervalWords(d.sampleIntervalSeconds) + '.'));
    return empty;
  }

  // The network, clients and announces graphs: the same for one node and a group.
  function usageSections(d, ser, width) {
    var net = section('Network usage');
    net.appendChild(lineChart({
      title: 'Network usage', range: d.range, from: ser.from, to: ser.to, width: width, fmt: formatRate,
      lines: [{ label: 'In', cls: 'c1', points: ser.bytesIn }, { label: 'Out', cls: 'c3 d1', points: ser.bytesOut }]
    }));
    var cl = section('Clients');
    if (summarize(ser.clients)) {
      cl.appendChild(lineChart({ title: 'Clients', range: d.range, from: ser.from, to: ser.to, width: width, fmt: count, lines: [{ label: 'Clients', cls: 'c2', points: ser.clients }] }));
    } else {
      cl.appendChild(el('p', 'note', d.view === 'combined' ? 'No client count for the whole group: a node does not report its clients.' : 'This node does not report its clients.'));
    }
    var an = section('Announces per minute');
    an.appendChild(lineChart({ title: 'Announces per minute', range: d.range, from: ser.from, to: ser.to, width: width, fmt: count, lines: [{ label: 'Announces', cls: 'c4', points: ser.announces }] }));
    return [net, cl, an];
  }

  // The members of a combined view: what each runs, and what is left out.
  function membersSection(d) {
    var s = section('Nodes');
    var g = d.group;
    var names = {};
    d.members.forEach(function (m) { names[m.host] = m.name || m.host; });
    if (g) s.appendChild(el('p', 'total', groupCoverage(g, names) + '.'));
    var ul = el('ul', 'versions');
    d.members.forEach(function (m) {
      var li = el('li', null, m.name || m.host);
      li.appendChild(el('span', 'muted', ' ' + (m.version ? 'runs ' + m.version : 'version unknown') + (m.uptimeSeconds === null ? '' : ', up ' + duration(m.uptimeSeconds)) + (m.hasHistory ? '' : ', no stats URL so not in the graphs')));
      ul.appendChild(li);
    });
    s.appendChild(ul);
    var note = versionSummary(d.members.map(function (m) { return { host: m.name || m.host, stats: m.version ? { data: { rettuiVersion: m.version } } : null }; }));
    if (note) s.appendChild(el('p', 'note', note));
    if (g && g.data) {
      var dl = el('dl', 'facts');
      groupPairs(g).forEach(function (p) {
        dl.appendChild(el('dt', null, p[0]));
        dl.appendChild(el('dd', null, p[1]));
      });
      s.appendChild(dl);
    }
    return s;
  }

  function combinedPeersSection(d, ser, width, collecting) {
    var s = section('Peers heard');
    var p = d.group && d.group.data ? d.group.data.peersHeard : null;
    if (p) {
      var rows = peerRangeRows(p);
      var now = p.exact ? p.union.total : null;
      s.appendChild(el('p', 'total', (p.exact ? num(now) + ' peers heard now (de-duplicated)' : peerRange(p.max.total, p.sum.total) + ' peers heard now')));
      s.appendChild(peerBar(rows.map(function (r) { return { key: r.key, label: r.label, count: r.count, percent: r.percent }; }), p.exact ? p.union.total : p.sum.total, width));
      var ul = el('ul', 'shares');
      rows.forEach(function (r) {
        var li = el('li');
        var sw = svg('svg', { width: 12, height: 12, viewBox: '0 0 12 12', 'aria-hidden': 'true', focusable: 'false' }, 'swatch-box');
        sw.appendChild(svg('rect', { x: 0, y: 0, width: 12, height: 12, rx: 2 }, 'fill ' + SHARE_CLASS[r.key]));
        li.appendChild(sw);
        li.appendChild(el('span', 'share-label', r.label));
        li.appendChild(el('b', null, r.text));
        li.appendChild(el('span', 'muted', r.percent + '%'));
        ul.appendChild(li);
      });
      s.appendChild(ul);
      s.appendChild(el('p', 'note', peerNote(p) + (p.exact ? ' The graph below is still a range: past values were not de-duplicated.' : ' The bar and percentages use the sum.')));
    } else {
      s.appendChild(el('p', 'note', 'No node of this group has reported stats.'));
    }
    if (!collecting) {
      s.appendChild(lineChart({
        title: 'Peers heard over time', range: d.range, from: ser.from, to: ser.to, width: width, fmt: count,
        lines: [
          { label: 'Sum of nodes (at most)', cls: 'c4', points: ser.peers.total },
          { label: 'Largest node (at least)', cls: 'c1 d1', points: ser.peersLow.total }
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
    var combined = d.view === 'combined';
    var parts = [combined ? membersSection(d) : versionSection(d)];
    if (collecting) parts.push(emptyState(d, ser));
    parts.push(combined ? combinedPeersSection(d, ser, width, collecting) : peersSection(d, ser, width, collecting));
    if (!collecting) parts = parts.concat(usageSections(d, ser, width));
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
    fetch('/api/stats?host=' + encodeURIComponent(detailChoice === 'combined' ? detailHost : detailChoice) + '&range=' + detailRange + (detailChoice === 'combined' ? '&view=combined' : ''), { cache: 'no-store', signal: ctl.signal })
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

  // The "View" choice of a proxy: its combined graphs, itself, and each node behind it.
  function fillViews(key) {
    var bar = document.getElementById('detail-viewbar');
    var select = document.getElementById('detail-view');
    var host = allHosts.filter(function (h) { return hostKey(h) === key; })[0];
    if (!host || !host.proxy) {
      bar.hidden = true;
      select.replaceChildren();
      return;
    }
    var opts = [];
    function add(value, text) {
      var o = el('option', null, text);
      o.value = value;
      select.appendChild(o);
      opts.push(value);
    }
    select.replaceChildren();
    add('combined', 'Combined (' + host.group.nodes + ' nodes)');
    allHosts.forEach(function (h) {
      var k = hostKey(h);
      if (h.hasDetail && h.stats && (k === key || host.proxy.for.indexOf(k) !== -1)) add(k, displayName(h) + (k === key ? ' (this node)' : ''));
    });
    select.value = detailChoice;
    bar.hidden = false;
  }

  function openDetail(key) {
    detailHost = key;
    var host = allHosts.filter(function (h) { return hostKey(h) === key; })[0];
    detailChoice = host && host.proxy ? 'combined' : key;
    var title = document.getElementById('detail-title');
    title.textContent = host ? displayName(host) : key;
    if (host && host.name) title.appendChild(el('span', 'host-addr', key));
    fillViews(key);
    setRangeButtons();
    if (!dlg.open) dlg.showModal();
    loadDetail(true);
    clearInterval(detailTimer);
    detailTimer = setInterval(function () { loadDetail(false); }, DETAIL_REFRESH_MS);
  }

  function setupDetail() {
    dlg = document.getElementById('detail');
    if (!dlg || typeof dlg.showModal !== 'function') return;
    // A tap anywhere but on a chart puts the chart tooltip away.
    dlg.addEventListener('pointerdown', function (e) {
      if (hideActive && !(e.target && e.target.closest && e.target.closest('.plot'))) hideActive();
    });
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
    document.getElementById('detail-view').addEventListener('change', function (e) {
      detailChoice = e.target.value;
      loadDetail(true);
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
    allHosts = data.hosts;
    badges = showBadges(data.hosts);
    list.replaceChildren.apply(list, groupHosts(data.hosts).map(function (g) { return hostItem(g.h, g.members); }));
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
      formatRate: formatRate, niceTicks: niceTicks, runs: runs, gapLimit: gapLimit, summarize: summarize, summaryText: summaryText, axisTime: axisTime,
      nearestIndex: nearestIndex, timeAt: timeAt, tooltipTitle: tooltipTitle, tooltipRows: tooltipRows, tooltipSpeech: tooltipSpeech, tooltipPosition: tooltipPosition,
      peerShares: peerShares, hostKey: hostKey, displayName: displayName, showBadges: showBadges, badgeText: badgeText, badgeTitle: badgeTitle, groupHosts: groupHosts,
      peerRange: peerRange, peerNote: peerNote, groupCoverage: groupCoverage, groupPairs: groupPairs, peerRangeRows: peerRangeRows, intervalWords: intervalWords, versionSummary: versionSummary, count: count };
    return;
  }
  setupDetail();
  load();
  setInterval(load, REFRESH_MS);
  setInterval(tick, TICK_MS);
})();
