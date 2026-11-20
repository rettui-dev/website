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

  // The count line of the banner. A proxy is the front door, not a node: nodes and proxies are
  // counted apart ("3 nodes up, 1 proxy up", "2 of 3 nodes up, proxy down"). The headline above
  // it still follows every entry point, the proxy included.
  function bannerCounts(hosts) {
    var list = Array.isArray(hosts) ? hosts : [];
    var proxies = list.filter(function (h) { return h.role === 'proxy'; });
    var nodes = list.filter(function (h) { return h.role !== 'proxy'; });
    function part(group, one, many) {
      var up = group.filter(function (h) { return h.status === 'up'; }).length;
      if (group.length === 1 && up === 0) return one + (group[0].status === 'down' ? ' down' : ' not checked yet');
      if (up === group.length) return up + ' ' + (up === 1 ? one : many) + ' up';
      return up + ' of ' + group.length + ' ' + many + ' up';
    }
    var out = [];
    if (nodes.length) out.push(part(nodes, 'node', 'nodes'));
    if (proxies.length) out.push(part(proxies, 'proxy', 'proxies'));
    return out.length ? out.join(', ') + '.' : 'No nodes.';
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  // A number with its unit stays one run in the value font (Fira Code); the words around it stay in the text font.
  var NUM_RE = /\d+(?:[,.:]\d+)*(?:\/\d+)?(?:[\u00a0 ]?(?:[KMGTP]iB|B|ms|s|m|h|d)(?:\/s)?(?![A-Za-z])|%|\/min)?/g;

  // Appends `text` to `parent`, each number-and-unit run in span.num. Only text nodes are made, never HTML.
  function addRuns(parent, text) {
    var s = String(text);
    var at = 0;
    var m;
    NUM_RE.lastIndex = 0;
    while ((m = NUM_RE.exec(s)) !== null) {
      if (m.index > at) parent.appendChild(document.createTextNode(s.slice(at, m.index)));
      parent.appendChild(el('span', 'num', m[0]));
      at = m.index + m[0].length;
    }
    if (at < s.length) parent.appendChild(document.createTextNode(s.slice(at)));
    return parent;
  }

  function elRuns(tag, cls, text) {
    return addRuns(el(tag, cls), text);
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

  // How a day of the 90 day bar looks: no data, or by the share of checks that were up.
  // The height changes with the colour, so the bar does not rely on colour alone.
  function dayLevel(p) {
    if (p === null || p === undefined || typeof p !== 'number' || !isFinite(p)) return 'none';
    // The server rounds a day down, so only a day with no failed check reads 100.
    if (p === 100) return 'ok';
    if (p >= 95) return 'warn';
    return 'bad';
  }

  // The date (UTC, as the server counts days) of cell i of a bar of n days that ends today.
  function dayDate(i, n, now) {
    return new Date(now - (n - 1 - i) * 86400000).toISOString().slice(0, 10);
  }

  function dayTitle(i, n, p, now) {
    var level = dayLevel(p);
    return dayDate(i, n, now) + ': ' + (level === 'none' ? 'no data' : p + '% up');
  }

  function percentWord(p) {
    return p === null || p === undefined ? 'no data' : p + '%';
  }

  // The words for the 90 day bar: the same facts as the colours, as text.
  function uptimeLabel(h) {
    var days = Array.isArray(h.days) ? h.days : [];
    var u = h.uptime90 || {};
    var withData = days.filter(function (p) { return dayLevel(p) !== 'none'; }).length;
    var lower = days.filter(function (p) { var l = dayLevel(p); return l === 'warn' || l === 'bad'; }).length;
    if (withData === 0) return 'Uptime over the last 90 days: no data yet';
    return 'Uptime over the last 90 days: ' + percentWord(u.percent90) + ', over the last 30 days: ' + percentWord(u.percent30) + '. ' +
      lower + (lower === 1 ? ' day' : ' days') + ' with downtime, ' + (days.length - withData) + ' without data';
  }

  // One cell per day, oldest first and today last, with the numbers in words beside it.
  function uptimeBar(h, now) {
    var days = Array.isArray(h.days) ? h.days : [];
    var wrap = el('div', 'uptime');
    var bar = el('div', 'days');
    bar.setAttribute('role', 'img');
    bar.setAttribute('aria-label', uptimeLabel(h));
    days.forEach(function (p, i) {
      var c = el('span', dayLevel(p));
      c.title = dayTitle(i, days.length, p, now);
      bar.appendChild(c);
    });
    wrap.appendChild(bar);
    var u = h.uptime90 || {};
    var note = u.percent90 === null || u.percent90 === undefined
      ? 'No uptime history yet.'
      : percentWord(u.percent30) + ' up over 30 days, ' + percentWord(u.percent90) + ' over 90 days.';
    wrap.appendChild(elRuns('p', 'bar-note', note));
    return wrap;
  }

  // "Down for 12m so far" or "Lasted 12m".
  function incidentSpan(i) {
    return i.ongoing ? 'Down for ' + duration(i.seconds) + ' so far' : 'Lasted ' + duration(i.seconds);
  }

  function incidentItem(i) {
    var li = el('li', 'incident ' + (i.ongoing ? 'ongoing' : 'resolved'));
    var head = el('span', 'incident-head');
    head.appendChild(el('span', 'host-name', i.name || i.host));
    if (i.name) head.appendChild(el('span', 'host-addr', i.host));
    var state = el('span', 'pill ' + (i.ongoing ? 'down' : 'up'));
    state.appendChild(el('span', null, i.ongoing ? GLYPH.down : GLYPH.up)).setAttribute('aria-hidden', 'true');
    state.appendChild(document.createTextNode(i.ongoing ? 'Ongoing' : 'Resolved'));
    head.appendChild(state);
    li.appendChild(head);
    var line = el('span', 'incident-line');
    line.appendChild(document.createTextNode('Started '));
    var t = el('time', null, new Date(i.start).toLocaleString());
    t.setAttribute('datetime', i.start);
    line.appendChild(t);
    line.appendChild(document.createTextNode('. '));
    addRuns(line, incidentSpan(i) + '.');
    li.appendChild(line);
    return li;
  }

  var MAX_INCIDENTS_SHOWN = 10;
  var incidentSig = null;

  function renderIncidents(data) {
    var list = data && Array.isArray(data.incidents) ? data.incidents : null;
    var ul = document.getElementById('incident-list');
    var empty = document.getElementById('incidents-empty');
    if (!ul || !empty) return;
    if (list === null) {
      if (incidentSig === null) empty.textContent = 'Incidents are not available right now.';
      return;
    }
    var sig = JSON.stringify(list);
    if (sig === incidentSig) return;
    incidentSig = sig;
    var shown = list.slice(0, MAX_INCIDENTS_SHOWN);
    ul.replaceChildren.apply(ul, shown.map(incidentItem));
    ul.hidden = shown.length === 0;
    empty.hidden = shown.length > 0;
    empty.textContent = 'No incidents in the last 90 days.';
    var more = document.getElementById('incidents-more');
    if (more) {
      more.hidden = list.length <= shown.length;
      more.textContent = 'Showing the latest ' + shown.length + ' of ' + list.length + ' incidents.';
    }
  }

  function loadIncidents() {
    var ctl = new AbortController();
    var timer = setTimeout(function () { ctl.abort(); }, TIMEOUT_MS);
    return fetch('/api/incidents', { cache: 'no-store', signal: ctl.signal })
      .then(function (r) {
        if (!r.ok) throw new Error('status ' + r.status);
        return r.json();
      })
      .then(renderIncidents)
      .catch(function () { renderIncidents(null); })
      .then(function () { clearTimeout(timer); });
  }

  // A time that the timer keeps current: "12s ago" counts up between fetches.
  function agoTime(iso) {
    var t = el('time');
    setAgo(t, ago(iso));
    if (iso) {
      t.setAttribute('datetime', iso);
      t.setAttribute('data-ago', iso);
      t.title = new Date(iso).toLocaleString();
    }
    return t;
  }

  // "29s ago": the figure in the value font, "ago" in words.
  function setAgo(t, text) {
    t.replaceChildren();
    addRuns(t, text);
  }

  function stat(label, value) {
    var s = el('span', null, label + ' ');
    s.appendChild(typeof value === 'string' ? elRuns('span', 'val', value) : value);
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

  // A small bar for the share of the disk in use: its fill and a text label.
  function meter(usedPercent, label, level) {
    var m = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    m.setAttribute('class', 'meter');
    m.setAttribute('width', '70');
    m.setAttribute('height', '8');
    m.setAttribute('viewBox', '0 0 70 8');
    m.setAttribute('role', 'img');
    m.setAttribute('aria-label', label);
    var bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    bg.setAttribute('class', 'meter-bg');
    bg.setAttribute('width', '70');
    bg.setAttribute('height', '8');
    bg.setAttribute('rx', '3');
    m.appendChild(bg);
    var fill = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    fill.setAttribute('class', 'meter-fill' + (level === 'full' ? ' full' : level === 'high' ? ' high' : ''));
    fill.setAttribute('width', String((70 * usedPercent) / 100));
    fill.setAttribute('height', '8');
    fill.setAttribute('rx', '3');
    m.appendChild(fill);
    return m;
  }

  // ---- Rows: what the list says about a node (pure helpers) ----

  // The few facts of the collapsed row, as [label, value]; what is unknown is left out.
  function summaryFacts(h) {
    var out = [];
    var d = h.stats && h.stats.data;
    if (d) {
      if (d.interfaces.clients !== null) out.push(['Clients', num(d.interfaces.clients)]);
      out.push(['Peers heard', num(d.peersHeard.total)]);
    }
    if (h.uptimePercent !== null && h.uptimePercent !== undefined) out.push(['Up', h.uptimePercent + '% over 24 h']);
    // Without stats the connect time is all there would be to open, so it is said here.
    if (!d && h.latencyMs !== null && h.latencyMs !== undefined) out.push(['Connect time', h.latencyMs + ' ms']);
    return out;
  }

  // The time of the latest successful check in the history the page has, or null.
  function lastUp(h) {
    for (var i = h.history.length - 1; i >= 0; i--) if (h.history[i].up) return new Date(h.history[i].t).toISOString();
    return null;
  }

  // What replaces the summary of a node that is down.
  function downText(h) {
    var up = lastUp(h);
    return 'Connection failed' + (h.error ? ': ' + h.error : '') + '. ' + (up ? 'Last up ' + ago(up) + '.' : 'No successful check lately.');
  }

  // The note of stats that are old: said in words, not by dimming.
  function staleNote(st) {
    return st && st.stale && st.fetchedAt ? 'Stats from ' + ago(st.fetchedAt) + ' (last fetch failed)' : null;
  }

  var BACKLOG = 'Messages stored on this node that some peer node has not received yet. The sum over peers counts a message once for each peer waiting for it. High right after peering starts and should fall as peers catch up.';

  // True when the backlog to send to peers cannot be real: a message waits at most once per peer,
  // so more than stored messages x peered nodes means the numbers are wrong or stuck. A plain backlog,
  // even a large one, is normal. Only the current sample is used here (the row has no history).
  function backlogAbnormal(p) {
    if (!p || !known(p.storedMessages)) return false;
    // Each stored message counts once, so more than the store cannot be real.
    if (known(p.unhandledDistinct)) return p.unhandledDistinct > p.storedMessages;
    // Only the sum over peers is known: it can reach stored messages x peers.
    if (!known(p.unhandledMessages) || !(p.unhandledMessages > 0) || !known(p.peersTotal)) return false;
    return p.unhandledMessages > p.storedMessages * p.peersTotal;
  }

  // The backlog as [label, value] pairs. With the distinct count: how many stored messages some peer
  // still waits for, and the sum over peers as a second line. Without it (older nodes): the sum, labelled as such.
  // A group has no distinct count that adds up, so it passes none and gets the sum.
  function backlogPairs(p) {
    var out = [];
    if (known(p.unhandledDistinct)) {
      out.push(['Messages waiting for peers', num(p.unhandledDistinct) + (known(p.storedMessages) ? ' of ' + num(p.storedMessages) + ' stored' : '')]);
      if (known(p.unhandledMessages)) out.push(['Total across peers', num(p.unhandledMessages)]);
    } else if (known(p.unhandledMessages)) {
      out.push(['Waiting to send to peers (summed over peers)', num(p.unhandledMessages)]);
    }
    return out;
  }

  // Things worth a line in the collapsed row, as {kind, text}; nothing when all is well.
  // Disk uses the level the server worked out, so words and numbers agree.
  function warnings(h) {
    var out = [];
    var st = h.stats;
    if (!st || !st.data || st.stale) return out;
    var d = st.data;
    if (d.disk && d.disk.usedPercent !== null && d.disk.usedPercent !== undefined) {
      // "about" unless the exact figures are published: the number is rounded to 5.
      var disk = 'Disk ' + (known(d.disk.fsFreeBytes) ? '' : 'about ') + d.disk.usedPercent + '% used';
      if (d.disk.level === 'full') out.push({ kind: 'full', text: disk + ', almost full' });
      else if (d.disk.level === 'high') out.push({ kind: 'high', text: disk });
    }
    var q = d.announceQueue;
    if (q && q.full === true) {
      out.push({ kind: 'full', title: 'An interface of this node has as many announces waiting to go out as Reticulum keeps; new ones are dropped.', text: 'Announce queue full' + (known(q.queued) ? ': ' + num(q.queued) + ' waiting' : '') });
    }
    var p = d.propagation;
    if (p && known(p.peersAlive) && known(p.peersTotal) && p.peersTotal > 0 && p.peersAlive * 2 < p.peersTotal) {
      out.push({ kind: 'high', text: 'Peered ' + num(p.peersAlive) + '/' + num(p.peersTotal) + ' alive' });
    }
    if (backlogAbnormal(p)) {
      var n = known(p.unhandledDistinct) ? p.unhandledDistinct : p.unhandledMessages;
      out.push({
        kind: 'high', title: BACKLOG,
        text: known(p.unhandledDistinct)
          ? 'Messages waiting for peers: ' + num(n) + ', more than the ' + num(p.storedMessages) + ' stored'
          : 'Waiting to send to peers: ' + num(n) + (n === 1 ? ' message' : ' messages') + ', more than the store and peers explain'
      });
    }
    return out;
  }

  // Keeps a number and its unit on one line.
  function nb(text) { return String(text).replace(/ /g, '\u00a0'); }

  // The facts of the expanded row, in three groups. A group with nothing in it is not drawn.
  function networkFacts(h) {
    var out = [];
    var d = h.stats && h.stats.data;
    if (d) {
      out.push(['Interfaces', d.interfaces.online + '/' + d.interfaces.total + ' online']);
      out.push(['Traffic since start', 'In\u00a0' + nb(bytes(d.interfaces.rxBytes)) + ', out\u00a0' + nb(bytes(d.interfaces.txBytes))]);
      out.push(['Announces', num(d.announcesLastMinute) + '/min']);
      if (d.announceQueue && known(d.announceQueue.queued)) out.push(['Announce queue', num(d.announceQueue.queued) + ' waiting' + (known(d.announceQueue.limit) ? ' of ' + num(d.announceQueue.limit) : '')]);
      out.push(['Node running', duration(d.uptimeSeconds)]);
    }
    if (d && h.latencyMs !== null && h.latencyMs !== undefined) out.push(['Connect time', h.latencyMs + ' ms']);
    return out;
  }

  function storeFacts(p) {
    var out = [];
    if (!p) return out;
    if (known(p.storedMessages)) {
      var s = num(p.storedMessages) + (p.storedMessages === 1 ? ' message' : ' messages');
      if (known(p.storedBytes)) {
        s += ', ' + bytes(p.storedBytes);
        var share = percentText(p.storedBytes, p.storageLimitBytes);
        if (share) s += ' of ' + bytes(p.storageLimitBytes) + ' (' + share + ')';
      }
      out.push(['Stored', s]);
    }
    if (known(p.peersAlive) && known(p.peersTotal)) out.push(['Peered', num(p.peersAlive) + ' of ' + num(p.peersTotal) + ' alive']);
    return out.concat(backlogPairs(p));
  }

  // The disk as facts: how full, and free of total only when the operator publishes the figures.
  function diskFacts(d) {
    var out = [];
    if (!d) return out;
    if (known(d.usedPercent)) {
      var exact = known(d.fsFreeBytes);
      out.push(['Disk', (exact ? '' : 'about ') + d.usedPercent + '% used' + (d.level === 'full' ? ', almost full' : '')]);
    }
    if (known(d.fsFreeBytes) && d.fsTotalBytes > 0) out.push(['Free', bytes(d.fsFreeBytes) + ' of ' + bytes(d.fsTotalBytes)]);
    return out;
  }

  // ---- Login: what a visitor without one does not see (pure helpers) ----

  var LOCK_WORDS = { storage: 'message store', peers: 'peered nodes', disk: 'disk', versions: 'versions' };

  // The sections of a row that need a login, besides the details view; none once logged in.
  function rowLocks(h) {
    if (!h.locked || !h.locked.length || (!h.stats && !h.group)) return [];
    return h.locked.filter(function (k) { return Object.prototype.hasOwnProperty.call(LOCK_WORDS, k); });
  }

  // "Message store, disk and versions need a login." or null.
  function lockText(locked) {
    var words = (locked || []).filter(function (k) { return LOCK_WORDS[k]; }).map(function (k) { return LOCK_WORDS[k]; });
    if (!words.length) return null;
    var list = words.length === 1 ? words[0] : words.slice(0, -1).join(', ') + ' and ' + words[words.length - 1];
    return list.charAt(0).toUpperCase() + list.slice(1) + (words.length === 1 && words[0] !== 'versions' && words[0] !== 'peered nodes' ? ' needs' : ' need') + ' a login.';
  }

  function detailsLocked(h) { return !!(h.locked && h.locked.indexOf('details') !== -1); }

  // ---- Groups: the one line of a proxy card (pure helpers) ----

  // "3 of 3 nodes up" and the numbers that add up, as plain strings.
  function groupFacts(h, members) {
    var g = h.group;
    var out = [];
    var up = members.filter(function (m) { return m.status === 'up'; }).length;
    out.push(up + ' of ' + members.length + ' nodes up');
    if (g && g.data) {
      var d = g.data;
      if (d.interfaces.clients !== null) out.push(num(d.interfaces.clients) + (d.interfaces.clients === 1 ? ' client' : ' clients'));
      out.push((d.peersHeard.exact ? num(d.peersHeard.union.total) : peerRange(d.peersHeard.max.total, d.peersHeard.sum.total)) + ' peers heard');
      out.push(num(d.announcesLastMinute) + ' announces/min');
    }
    return out;
  }

  // Only when some nodes did not report: who, in words.
  function partialNote(g, names) {
    if (!g || !g.partial) return null;
    var text = g.reporting + ' of ' + g.nodes + ' nodes reporting.';
    if (g.missing.length) text += ' Not reporting: ' + g.missing.map(function (k) { return names && names[k] ? names[k] : k; }).join(', ');
    return text;
  }

  // The roll-up warning of a group: its fullest disk, when that is worth a line.
  function groupWarning(g, names) {
    var d = g && g.data && g.data.disk;
    if (!d || !d.worst || d.worst.level === 'ok') return null;
    var who = names && names[d.worst.node] ? names[d.worst.node] : d.worst.node;
    if (d.lowestFree && d.lowestFree.node === d.worst.node) {
      return { kind: d.worst.level, text: 'Least disk free: ' + bytes(d.lowestFree.freeBytes) + ' of ' + bytes(d.lowestFree.totalBytes) + ' (' + d.lowestFree.percent + '%) on ' + who };
    }
    return { kind: d.worst.level, text: 'Fullest disk: ' + who + ' about ' + d.worst.usedPercent + '% used' + (d.worst.level === 'full' ? ', almost full' : '') };
  }

  // ---- Rows: drawing ----

  var rowCache = {};
  var allHosts = [];
  // Open rows, by host (and "#self" for the proxy's own numbers), kept across refreshes.
  var openRows = {};
  var helpOpen = {};

  function idOf(prefix, key) { return prefix + '-' + key.replace(/[^a-z0-9]/gi, '-'); }

  function glyph(kind) {
    return el('span', 'glyph', kind === 'full' ? '✕ ' : '▲ ');
  }

  function warnLines(list) {
    var box = el('div', 'warnings');
    list.forEach(function (w) {
      var p = el('p', 'warn ' + w.kind);
      if (w.title) p.title = w.title;
      var g = glyph(w.kind);
      g.setAttribute('aria-hidden', 'true');
      p.appendChild(g);
      addRuns(p, w.text);
      box.appendChild(p);
    });
    return box;
  }

  function factsLine(pairs, cls) {
    var line = el('div', 'summary ' + (cls || ''));
    pairs.forEach(function (p) { line.appendChild(stat(p[0], p[1])); });
    return line;
  }

  // The value of a fact. A version is one run of code; the rest has its numbers picked out.
  function factsValue(pair) {
    return pair[0] === 'Running' ? el('dd', 'id', pair[1]) : elRuns('dd', null, pair[1]);
  }

  function factsList(title, pairs, extra) {
    if (!pairs.length && !extra) return null;
    var sec = el('section', 'more-sec');
    sec.appendChild(el('h2', null, title));
    var dl = el('dl', 'facts');
    pairs.forEach(function (p) {
      dl.appendChild(el('dt', null, p[0]));
      dl.appendChild(factsValue(p));
    });
    sec.appendChild(dl);
    if (extra) sec.appendChild(extra);
    return sec;
  }

  // The expanded part of a row: sections with data only, and the way to the graphs.
  function moreBody(h, opts) {
    var body = el('div', 'more-body');
    var d = h.stats && h.stats.data;
    var parts = [];
    var label = h.status === 'down' && d ? ' (last known)' : '';
    var net = opts.itself ? networkFacts({ stats: h.stats, latencyMs: null }) : networkFacts(h);
    if (opts.group && d && !(h.group && h.group.countOwn)) {
      // The numbers of the proxy itself are in its own row below; keep only what is not repeated.
      d = null;
      net = h.latencyMs !== null && h.latencyMs !== undefined ? [['Connect time', h.latencyMs + ' ms']] : [];
    }
    parts.push(factsList('Network' + label, net));
    parts.push(factsList('Message store' + label, storeFacts(d && d.propagation)));
    var used = d && d.disk ? d.disk.usedPercent : null;
    var bar = null;
    if (known(used)) {
      bar = el('div', 'meter-wrap');
      bar.appendChild(meter(used, (d.disk.fsFreeBytes === null || d.disk.fsFreeBytes === undefined ? 'About ' : '') + used + '% of the disk in use', d.disk.level));
    }
    parts.push(factsList('Disk' + label, diskFacts(d && d.disk), bar));
    parts.forEach(function (x) { if (x) body.appendChild(x); });
    var locks = opts.itself ? [] : rowLocks(h);
    var lockedDetails = h.hasDetail && !opts.itself && detailsLocked(h);
    if (locks.length || lockedDetails) body.appendChild(lockBox(h, locks, lockedDetails));
    // The proxy's own row has no button of its own: the group's More has it.
    if (h.hasDetail && !opts.itself && !lockedDetails) {
      var full = el('button', 'detail-btn', 'Full details');
      full.type = 'button';
      full.setAttribute('data-host', hostKey(h));
      full.setAttribute('data-role', 'details');
      full.setAttribute('aria-label', 'Full details for ' + displayName(h));
      full.addEventListener('click', function () { openDetail(hostKey(h)); });
      body.appendChild(full);
    }
    return body;
  }

  // What a row keeps for logged-in users, and the way to log in. One button
  // does both: with the details locked it opens them after the login.
  function lockBox(h, locks, lockedDetails) {
    var box = el('div', 'lock-box');
    var text = lockText(locks);
    if (lockedDetails) text = (text ? text.replace(/\.$/, ', ') : '') + (text ? 'and so do the full details.' : 'Full details need a login.');
    box.appendChild(el('p', 'lock-text', text));
    var b = el('button', 'login-btn', lockedDetails ? 'Log in for full details' : 'Log in to see more');
    b.type = 'button';
    b.setAttribute('data-host', hostKey(h));
    b.setAttribute('data-role', 'login');
    b.setAttribute('aria-label', (lockedDetails ? 'Log in for full details of ' : 'Log in to see more about ') + displayName(h));
    b.addEventListener('click', function () { openLogin(b, lockedDetails ? hostKey(h) : null); });
    box.appendChild(b);
    return box;
  }

  // The More or Less button and the part it opens. Open rows stay open on refresh;
  // within a group only one member is open at a time.
  function expander(h, opts, groupKeys) {
    var key = opts.itself ? hostKey(h) + '#self' : hostKey(h);
    var id = idOf(opts.itself ? 'more-self' : 'more', hostKey(h));
    var body = moreBody(h, opts);
    // Nothing to open: no button, rather than an empty panel.
    if (!body.firstChild) return null;
    body.id = id;
    var open = openRows[key] === true;
    body.hidden = !open;
    var who = opts.itself ? displayName(h) + ' itself' : displayName(h);
    var b = el('button', 'more-btn', 'More ');
    var chev = el('span', 'chev', open ? '\u25B4' : '\u25BE');
    chev.setAttribute('aria-hidden', 'true');
    b.appendChild(chev);
    b.type = 'button';
    // One name, "More about X": the state is in aria-expanded.
    b.setAttribute('aria-label', 'More about ' + who);
    b.setAttribute('aria-expanded', open ? 'true' : 'false');
    b.setAttribute('aria-controls', id);
    b.setAttribute('data-host', key);
    b.setAttribute('data-role', 'more');
    b.addEventListener('click', function () {
      var now = body.hidden;
      if (now && groupKeys) {
        // One member at a time: close the others of this group.
        groupKeys.forEach(function (k) { if (k !== key) openRows[k] = false; });
        var others = document.querySelectorAll('[data-group="' + groupKeys.groupId + '"] .more-btn');
        for (var i = 0; i < others.length; i++) {
          if (others[i] !== b && others[i].getAttribute('aria-expanded') === 'true') others[i].click();
        }
      }
      body.hidden = !now;
      openRows[key] = now;
      b.setAttribute('aria-expanded', now ? 'true' : 'false');
      chev.textContent = now ? '\u25B4' : '\u25BE';
    });
    return { button: b, body: body };
  }

  function statusPill(h) {
    var pill = el('span', 'pill ' + h.status);
    var status = WORD[h.status] ? h.status : 'unknown';
    pill.appendChild(el('span', null, GLYPH[status])).setAttribute('aria-hidden', 'true');
    pill.appendChild(document.createTextNode(WORD[status]));
    return pill;
  }

  function checkBar(h) {
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
    return bar;
  }

  // The collapsed row of a node: name, status, one line, warnings only when needed.
  // opts: {itself} for the numbers of a proxy shown as a member, {groupKeys} for members.
  function hostItem(h, opts) {
    opts = opts || {};
    var li = el('li', 'host' + (h.role === 'proxy' ? ' proxy' : '') + (h.proxiedBy ? ' member' : '') + (opts.itself ? ' itself' : ''));
    li.setAttribute('data-host', hostKey(h));
    var head = el('div', 'host-head');
    var title = el('span', 'host-title');
    title.appendChild(el('span', 'host-name', opts.itself ? displayName(h) + ' itself' : displayName(h)));
    if (h.name && !opts.itself) title.appendChild(el('span', 'host-addr', hostKey(h)));
    if (h.role === 'proxy' && !opts.itself) {
      var badge = el('span', 'badge proxy', 'Proxy');
      badge.title = badgeTitle(h, allHosts);
      title.appendChild(badge);
    }
    head.appendChild(title);
    if (!opts.itself) head.appendChild(statusPill(h));
    li.appendChild(head);

    var st = h.stats;
    if (!opts.itself && h.status === 'down') {
      li.appendChild(elRuns('p', 'summary down-text', downText(h)));
    } else if (!opts.itself && h.status === 'unknown') {
      li.appendChild(el('p', 'summary', 'Not checked yet.'));
    } else {
      var facts = opts.itself ? summaryFacts({ stats: st, uptimePercent: null }) : summaryFacts(h);
      var line = factsLine(facts);
      if (!opts.itself) {
        var when = agoTime(h.lastChecked);
        when.setAttribute('data-for', hostKey(h));
        line.appendChild(stat('checked', when));
      }
      li.appendChild(line);
    }
    if (st && !st.data) {
      var un = el('p', 'warn high');
      var g = glyph('high');
      g.setAttribute('aria-hidden', 'true');
      un.appendChild(g);
      un.appendChild(document.createTextNode('Stats unavailable.'));
      li.appendChild(un);
    }
    var note = staleNote(st);
    if (note) li.appendChild(elRuns('p', 'note stale-note', note));
    var w = warnings(h);
    if (w.length) li.appendChild(warnLines(w));
    if (!opts.itself) li.appendChild(checkBar(h));
    if (!opts.itself && Array.isArray(h.days)) li.appendChild(uptimeBar(h, Date.now()));
    var x = expander(h, opts, opts.groupKeys);
    if (x) {
      var actions = el('div', 'row-actions');
      actions.appendChild(x.button);
      li.appendChild(actions);
      li.appendChild(x.body);
    }
    return li;
  }

  // One card for a proxy: one header, one line of numbers that add up, then the
  // nodes behind it. The proxy's own numbers are a member-style row unless they
  // are already part of the group (count_own).
  function groupCard(h, members) {
    var g = h.group;
    var li = el('li', 'host proxy group-card');
    li.setAttribute('data-host', hostKey(h));
    var head = el('div', 'host-head');
    var title = el('span', 'host-title');
    title.appendChild(el('span', 'host-name', displayName(h)));
    if (h.name) title.appendChild(el('span', 'host-addr', hostKey(h)));
    var badge = el('span', 'badge proxy', 'Proxy');
    badge.title = badgeTitle(h, allHosts);
    title.appendChild(badge);
    title.appendChild(elRuns('span', 'passes', 'passes visitors to ' + g.nodes + (g.nodes === 1 ? ' node' : ' nodes')));
    head.appendChild(title);
    head.appendChild(statusPill(h));
    li.appendChild(head);

    var para = null;
    var names = {};
    allHosts.forEach(function (x) { names[hostKey(x)] = displayName(x); });
    var line = el('div', 'summary');
    var peers = g.data && g.data.peersHeard;
    groupFacts(h, members).forEach(function (f) {
      var span = elRuns('span', null, f);
      line.appendChild(span);
      // The explanation sits with the number it explains, on the same line.
      if (peers && / peers heard$/.test(f)) {
        if (peers.exact) {
          span.appendChild(el('span', 'hint', ' (de-duplicated)'));
        } else {
          var helpId = idOf('help', hostKey(h));
          var help = el('button', 'help-btn', '?');
          help.type = 'button';
          help.setAttribute('aria-label', 'Why peers heard is a range');
          help.setAttribute('aria-expanded', helpOpen[hostKey(h)] ? 'true' : 'false');
          help.setAttribute('aria-controls', helpId);
          help.setAttribute('data-host', hostKey(h));
          help.setAttribute('data-role', 'help');
          para = elRuns('p', 'note help-text', peerNote(peers));
          para.id = helpId;
          para.hidden = !helpOpen[hostKey(h)];
          help.addEventListener('click', function () {
            para.hidden = !para.hidden;
            helpOpen[hostKey(h)] = !para.hidden;
            help.setAttribute('aria-expanded', para.hidden ? 'false' : 'true');
          });
          span.appendChild(document.createTextNode(' '));
          span.appendChild(help);
        }
      }
    });
    li.appendChild(line);
    if (para) li.appendChild(para);

    var warn = [];
    var gw = groupWarning(g, names);
    // When the fullest disk is in a row below that already says so, once is enough.
    var shown = gw && members.some(function (m) {
      return hostKey(m) === g.data.disk.worst.node && warnings(m).some(function (w) { return w.text.indexOf('Disk') === 0; });
    });
    if (gw && !shown) warn.push(gw);
    if (warn.length) li.appendChild(warnLines(warn));
    var pn = partialNote(g, names);
    if (pn) {
      var p = el('p', 'warn high');
      var gl = glyph('high');
      gl.setAttribute('aria-hidden', 'true');
      p.appendChild(gl);
      addRuns(p, pn);
      li.appendChild(p);
    }
    li.appendChild(checkBar(h));
    // The proxy's own connection details and the way to the combined graphs.
    var x = expander(h, { group: true }, null);
    if (x) {
      var actions = el('div', 'row-actions');
      actions.appendChild(x.button);
      li.appendChild(actions);
      li.appendChild(x.body);
    }

    var rows = [];
    var own = h.stats && h.stats.data && !g.countOwn;
    var groupKeys = [];
    members.forEach(function (m) { groupKeys.push(hostKey(m)); });
    if (own) groupKeys.push(hostKey(h) + '#self');
    groupKeys.groupId = idOf('grp', hostKey(h));
    if (own) rows.push(hostItem(h, { itself: true, groupKeys: groupKeys }));
    members.forEach(function (m) { rows.push(hostItem(m, { groupKeys: groupKeys })); });
    if (rows.length) {
      var ul = el('ul', 'members');
      ul.setAttribute('data-group', groupKeys.groupId);
      ul.setAttribute('aria-label', 'Nodes behind ' + displayName(h));
      rows.forEach(function (r) { ul.appendChild(r); });
      li.appendChild(ul);
    }
    return li;
  }

  // ---- Propagation node and disk (pure helpers) ----

  // "34%" of a total; one decimal under 10%; null without a usable total.
  function percentText(n, total) {
    if (n === null || n === undefined || !(total > 0)) return null;
    var p = (n / total) * 100;
    return (p < 10 ? Math.round(p * 10) / 10 : Math.round(p)) + '%';
  }

  function known(v) { return v !== null && v !== undefined; }

  // The propagation numbers as [label, value] pairs. Anything the node did not
  // send is left out. `p` is stats.data.propagation, or a group's sums.
  function propagationPairs(p) {
    var pairs = [];
    if (!p) return pairs;
    if (known(p.storedMessages)) {
      var stored = num(p.storedMessages) + (p.storedMessages === 1 ? ' message' : ' messages');
      if (known(p.storedBytes)) {
        stored += ', ' + bytes(p.storedBytes);
        var share = percentText(p.storedBytes, p.storageLimitBytes);
        if (share) stored += ' (' + share + ' of ' + bytes(p.storageLimitBytes) + ')';
      }
      pairs.push(['Stored', stored]);
    } else if (known(p.storedBytes)) {
      pairs.push(['Stored', bytes(p.storedBytes)]);
    }
    if (known(p.peersAlive) || known(p.peersTotal)) {
      var peers = (known(p.peersAlive) ? num(p.peersAlive) : '?') + '/' + (known(p.peersTotal) ? num(p.peersTotal) : '?') + ' alive';
      var kinds = [];
      if (known(p.peersStatic)) kinds.push(num(p.peersStatic) + ' static');
      if (known(p.peersAuto)) kinds.push(num(p.peersAuto) + ' auto');
      if (kinds.length) peers += ' (' + kinds.join(', ') + ')';
      if (known(p.peerLimit)) peers += ', limit ' + num(p.peerLimit);
      pairs.push(['Peered nodes', peers]);
    }
    if (p.autopeer === true || p.autopeer === false) {
      pairs.push(['Auto-peering', p.autopeer ? 'on' + (known(p.autopeerDepth) ? ' (depth ' + p.autopeerDepth + ')' : '') : 'off']);
    }
    if (known(p.messagesSentToPeers) || known(p.messagesReceivedFromPeers)) {
      pairs.push(['Peer traffic', '↑ ' + (known(p.messagesSentToPeers) ? num(p.messagesSentToPeers) : '?') + ' sent ↓ ' + (known(p.messagesReceivedFromPeers) ? num(p.messagesReceivedFromPeers) : '?') + ' received']);
    }
    return pairs.concat(backlogPairs(p));
  }

  // The share of the disk in use, 0 to 100: as published (rounded unless the operator allows more), or null.
  function diskUsedPercent(d) {
    if (!d) return null;
    if (known(d.usedPercent)) return d.usedPercent;
    if (!known(d.fsFreeBytes) || !(d.fsTotalBytes > 0)) return null;
    return Math.min(Math.max(Math.round((1 - d.fsFreeBytes / d.fsTotalBytes) * 100), 0), 100);
  }

  // The disk numbers as [label, value] pairs (the Details view).
  function diskPairs(d) {
    var pairs = [];
    if (!d) return pairs;
    if (known(d.dataBytes)) pairs.push(['Data size', bytes(d.dataBytes)]);
    return pairs.concat(diskFacts(d));
  }

  // A group's message store numbers: sums over the nodes.
  function groupPropagationPairs(g) {
    if (!g || !g.data || !g.data.propagation) return [];
    var p = g.data.propagation;
    return propagationPairs({
      storedMessages: p.storedMessages, storedBytes: p.storedBytes, storageLimitBytes: p.storageLimitBytes, peersAlive: p.peersAlive, peersTotal: p.peersTotal,
      peersStatic: p.peersStatic, peersAuto: p.peersAuto, messagesSentToPeers: p.messagesSentToPeers, messagesReceivedFromPeers: p.messagesReceivedFromPeers,
      unhandledMessages: p.unhandledMessages
    });
  }

  // A group's disk numbers: the data of all nodes, and the fullest disk.
  function groupDiskPairs(g) {
    var pairs = [];
    var d = g && g.data ? g.data.disk : null;
    if (!d) return pairs;
    if (known(d.dataBytes)) pairs.push(['Data size', bytes(d.dataBytes)]);
    if (d.lowestFree) pairs.push(['Least disk free', d.lowestFree.percent + '% (' + bytes(d.lowestFree.freeBytes) + ' of ' + bytes(d.lowestFree.totalBytes) + ')']);
    else if (d.worst) pairs.push(['Fullest disk', d.worst.usedPercent + '% used']);
    return pairs;
  }

  // A group's storage numbers: sums, and the fullest disk.
  function groupStoragePairs(g) {
    return groupPropagationPairs(g).concat(groupDiskPairs(g));
  }

  // ---- Proxies and groups (pure helpers) ----

  function hostKey(h) { return h.host + ':' + h.port; }

  // The name to show: the configured display name, else the address.
  function displayName(h) { return h.name || hostKey(h); }

  // Only proxies get a badge.
  function badgeText(h) { return h.role === 'proxy' ? 'Proxy' : null; }

  // The title and screen reader words of the badge; null for a node that is not a proxy.
  function badgeTitle(h) {
    if (h.role !== 'proxy') return null;
    var n = h.proxy ? h.proxy.for.length : 0;
    return 'Proxy for ' + n + (n === 1 ? ' node' : ' nodes');
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
    return low === high ? num(low) : num(low) + '\u00a0to\u00a0' + num(high);
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
    if (o.band && o.lines.length === 2) {
      // The range between two lines, as a soft fill under them.
      var hi = o.lines[0].points;
      var lo = o.lines[1].points;
      var gap = gapLimit(hi);
      var seg = [];
      var flush = function () {
        if (seg.length > 1) {
          var up = seg.map(function (i, n) { return (n ? 'L' : 'M') + x(hi[i][0]).toFixed(1) + ' ' + y(hi[i][1]).toFixed(1); }).join('');
          var down = seg.slice().reverse().map(function (i) { return 'L' + x(lo[i][0]).toFixed(1) + ' ' + y(lo[i][1]).toFixed(1); }).join('');
          chart.appendChild(svg('path', { d: up + down + 'Z' }, 'band'));
        }
        seg = [];
      };
      for (var bi = 0; bi < hi.length && bi < lo.length; bi++) {
        var okPair = typeof hi[bi][1] === 'number' && typeof lo[bi][1] === 'number';
        if (okPair && seg.length && gap > 0 && hi[bi][0] - hi[seg[seg.length - 1]][0] > gap) flush();
        if (okPair) seg.push(bi); else flush();
      }
      flush();
    }
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
      (o.extra || []).forEach(function (l) { rows = rows.concat(tooltipRows([l], index, l.fmt)); });
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
  var detailKey = '';
  var detailTimer = null;
  var resizeTimer = null;

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
    var cs = window.getComputedStyle(body);
    var inner = body.clientWidth - (parseFloat(cs.paddingLeft) || 0) - (parseFloat(cs.paddingRight) || 0);
    return inner > 0 ? inner : 320;
  }

  function emptyState(d, ser) {
    var empty = el('p', 'empty', 'Collecting data, graphs fill in over time.');
    var what = d.view === 'combined' ? 'complete' : '';
    empty.appendChild(elRuns('span', 'muted', ' ' + ser.sampleCount + (what ? ' ' + what : '') + (ser.sampleCount === 1 ? ' sample' : ' samples') + ' so far in the ' + RANGE_WORDS[d.range] + '; one is taken about every ' + intervalWords(d.sampleIntervalSeconds) + '.'));
    return empty;
  }

  function factsBlock(pairs) {
    var dl = el('dl', 'facts');
    pairs.forEach(function (p) {
      dl.appendChild(el('dt', null, p[0]));
      dl.appendChild(factsValue(p));
    });
    return dl;
  }

  // What needs a look, as the warning lines of the list row. Nothing when all is well.
  function attentionSection(d) {
    var list = [];
    var note = null;
    if (d.view === 'combined') {
      var names = {};
      d.members.forEach(function (m) { names[m.host] = m.name || m.host; });
      var gw = groupWarning(d.group, names);
      if (gw) list.push(gw);
      note = partialNote(d.group, names);
    } else if (d.stats) {
      list = warnings({ stats: d.stats });
    }
    if (!list.length && !note) return null;
    var s = section('Needs attention');
    s.appendChild(warnLines(list));
    if (note) s.appendChild(elRuns('p', 'note', note));
    return s;
  }

  // The running version and the current numbers of one node, as facts.
  function nowSection(d) {
    var s = section('Now');
    var cur = d.stats && d.stats.data ? d.stats.data : null;
    var pairs = [['Node running', d.version.uptimeSeconds === null ? 'unknown' : duration(d.version.uptimeSeconds)]];
    // Without a login the version may be one of the locked sections: then it is left out, not "unknown".
    if (!d.locked || d.locked.indexOf('versions') === -1) pairs.unshift(['Running', d.version.current || 'unknown']);
    if (cur) {
      pairs.push(['Interfaces', cur.interfaces.online + '/' + cur.interfaces.total + ' online']);
      if (cur.interfaces.clients !== null) pairs.push(['Clients', num(cur.interfaces.clients)]);
      pairs = pairs.concat(storeFacts(cur.propagation));
    }
    s.appendChild(factsBlock(pairs));
    var stale = staleNote(d.stats);
    if (stale) s.appendChild(elRuns('p', 'note', stale));
    return s;
  }

  function versionsSeen(d) {
    if (!d.version.history.length) return null;
    var s = section('Versions seen');
    var ul = el('ul', 'versions');
    d.version.history.slice().reverse().forEach(function (v) {
      var li = el('li');
      li.appendChild(el('span', 'num', v.version));
      li.appendChild(el('span', 'muted', ' since '));
      li.appendChild(el('span', 'muted num', when(v.firstSeen)));
      ul.appendChild(li);
    });
    s.appendChild(ul);
    var note = lastData ? versionSummary(lastData.hosts) : null;
    if (note) s.appendChild(el('p', 'note', note));
    return s;
  }

  // The nodes of a combined view: what each runs, and what is left out.
  function membersSection(d) {
    var s = section('Nodes');
    var g = d.group;
    var names = {};
    d.members.forEach(function (m) { names[m.host] = m.name || m.host; });
    if (g) s.appendChild(elRuns('p', 'total', groupCoverage(g, names) + '.'));
    var ul = el('ul', 'versions');
    d.members.forEach(function (m) {
      var li = el('li', null, m.name || m.host);
      var noVersion = d.locked && d.locked.indexOf('versions') !== -1;
      var facts = [];
      if (!noVersion) facts.push(m.version ? 'runs ' + m.version : 'version unknown');
      if (m.uptimeSeconds !== null) facts.push('running ' + duration(m.uptimeSeconds));
      if (!m.hasHistory) facts.push('no stats URL so not in the graphs');
      if (facts.length) li.appendChild(elRuns('span', 'muted', ' ' + facts.join(', ')));
      ul.appendChild(li);
    });
    s.appendChild(ul);
    var note = versionSummary(d.members.map(function (m) { return { host: m.name || m.host, stats: m.version ? { data: { rettuiVersion: m.version } } : null }; }));
    if (note) s.appendChild(el('p', 'note', note));
    return s;
  }

  // In the details: what is left out until the visitor logs in.
  function lockSection(d) {
    var text = lockText(d.locked);
    if (!text) return null;
    var s = section('Needs a login');
    s.appendChild(el('p', 'lock-text', text));
    var b = el('button', 'login-btn', 'Log in to see more');
    b.type = 'button';
    b.setAttribute('data-role', 'login');
    b.addEventListener('click', function () { openLogin(b, null); });
    s.appendChild(b);
    return s;
  }

  function overviewTab(d) {
    var parts = [attentionSection(d), lockSection(d)];
    if (d.view === 'combined') {
      parts.push(membersSection(d));
    } else {
      parts.push(nowSection(d));
      parts.push(versionsSeen(d));
    }
    return parts.filter(function (x) { return x; });
  }

  // "Total" by default; the three kinds on request.
  var peersByKind = false;

  function peerBreakdown(rows, total, width, texts) {
    var box = el('div', 'peer-breakdown');
    box.appendChild(peerBar(rows, total, width));
    var ul = el('ul', 'shares');
    rows.forEach(function (r, i) {
      var li = el('li');
      var sw = svg('svg', { width: 12, height: 12, viewBox: '0 0 12 12', 'aria-hidden': 'true', focusable: 'false' }, 'swatch-box');
      sw.appendChild(svg('rect', { x: 0, y: 0, width: 12, height: 12, rx: 2 }, 'fill ' + SHARE_CLASS[r.key]));
      li.appendChild(sw);
      li.appendChild(el('span', 'share-label', r.label));
      li.appendChild(el('b', null, texts ? texts[i] : num(r.count)));
      li.appendChild(el('span', 'muted num', r.percent + '%'));
      ul.appendChild(li);
    });
    box.appendChild(ul);
    return box;
  }

  function peersTab(d, ser, width, collecting) {
    var combined = d.view === 'combined';
    var s = section('Peers heard');
    var g = d.group && d.group.data ? d.group.data.peersHeard : null;
    var cur = combined ? g : d.stats && d.stats.data ? d.stats.data.peersHeard : null;
    if (cur && !combined) {
      s.appendChild(elRuns('p', 'total', num(cur.total) + ' peers heard now'));
      s.appendChild(peerBreakdown(peerShares(cur), cur.total, width));
    } else if (cur) {
      var rows = peerRangeRows(cur);
      s.appendChild(elRuns('p', 'total', (cur.exact ? num(cur.union.total) + ' peers heard now (de-duplicated)' : peerRange(cur.max.total, cur.sum.total) + ' peers heard now')));
      s.appendChild(peerBreakdown(rows.map(function (r) { return { key: r.key, label: r.label, count: r.count, percent: r.percent }; }), cur.exact ? cur.union.total : cur.sum.total, width, rows.map(function (r) { return r.text; })));
      s.appendChild(elRuns('p', 'note', peerNote(cur) + (cur.exact ? ' The graph below is still a range: past values were not de-duplicated.' : ' The bar and percentages use the sum.')));
    } else {
      s.appendChild(el('p', 'note', combined ? 'No node of this group has reported stats.' : 'Stats unavailable.'));
    }
    var out = [s];
    if (collecting) return out;
    var cs = section('Peers heard over time');
    if (combined) {
      cs.appendChild(lineChart({
        title: 'Peers heard over time', range: d.range, from: ser.from, to: ser.to, width: width, fmt: count, band: true,
        lines: [
          { label: 'Most (sum of nodes)', cls: 'c4', points: ser.peers.total },
          { label: 'Fewest (largest node)', cls: 'c1 d1', points: ser.peersLow.total }
        ]
      }));
    } else {
      var toggle = el('button', 'toggle-btn', 'Show by kind');
      toggle.type = 'button';
      toggle.setAttribute('aria-pressed', peersByKind ? 'true' : 'false');
      toggle.addEventListener('click', function () {
        peersByKind = !peersByKind;
        renderDetail(true);
      });
      cs.appendChild(toggle);
      cs.appendChild(lineChart({
        title: 'Peers heard over time', range: d.range, from: ser.from, to: ser.to, width: width, fmt: count,
        lines: peersByKind
          ? [{ label: 'LXMF', cls: 'c1', points: ser.peers.lxmf }, { label: 'NomadNet', cls: 'c2 d1', points: ser.peers.nomad }, { label: 'Propagation', cls: 'c3 d2', points: ser.peers.propagation }]
          : [{ label: 'Total', cls: 'c4', points: ser.peers.total }]
      }));
    }
    out.push(cs);
    return out;
  }

  function chartSection(title, d, ser, width, fmt, lines, extra) {
    var sec = section(title);
    sec.appendChild(lineChart({ title: title, range: d.range, from: ser.from, to: ser.to, width: width, fmt: fmt, lines: lines, extra: extra }));
    return sec;
  }

  function trafficTab(d, ser, width) {
    var out = [
      chartSection('Network usage', d, ser, width, formatRate, [{ label: 'In', cls: 'c1', points: ser.bytesIn }, { label: 'Out', cls: 'c3 d1', points: ser.bytesOut }]),
      chartSection('Announces per minute', d, ser, width, count, [{ label: 'Announces', cls: 'c4', points: ser.announces }])
    ];
    // No client count, no chart: say nothing rather than draw an empty one.
    if (summarize(ser.clients)) out.splice(1, 0, chartSection('Clients', d, ser, width, count, [{ label: 'Clients', cls: 'c2', points: ser.clients }]));
    return out;
  }

  function perMinute(v) { return count(v) + '/min'; }

  function hasStorage(d) {
    if (d.series.propagation) return true;
    if (d.view === 'combined') return !!(d.group && d.group.data && d.group.data.propagation);
    return !!(d.stats && d.stats.data && d.stats.data.propagation);
  }

  function hasDisk(d) {
    if (d.series.disk) return true;
    if (d.view === 'combined') return !!(d.group && d.group.data && d.group.data.disk);
    return !!(d.stats && d.stats.data && d.stats.data.disk);
  }

  // ---- The table of a propagation node's peers (Storage tab) ----

  // A span in plain words: "12 min", "3 h", "2 days". Under a minute it is "under 1 min".
  function peerSpan(sec) {
    if (!(sec >= 60)) return 'under 1 min';
    if (sec < 3600) return Math.floor(sec / 60) + ' min';
    if (sec < 86400) return Math.floor(sec / 3600) + ' h';
    var days = Math.floor(sec / 86400);
    return days + (days === 1 ? ' day' : ' days');
  }

  // When a peer last synced: "never", "12 min ago", or "-" when the node does not say.
  function peerSyncText(row) {
    if (!row.hasSync) return '-';
    return row.lastSyncSecondsAgo === null ? 'never' : peerSpan(row.lastSyncSecondsAgo) + ' ago';
  }

  // When the next try is: "now" when it is due, "in 5 min", or "-" when the node does not say.
  function peerNextText(row) {
    if (!row.hasSync) return '-';
    return !row.nextAttemptInSeconds ? 'now' : 'in ' + peerSpan(row.nextAttemptInSeconds);
  }

  var PEER_STATES = { idle: 'Idle', link_establishing: 'Connecting', link_ready: 'Connected', request_sent: 'Waiting for an answer', receiving: 'Receiving', response_received: 'Got an answer', resource_transfer: 'Transferring' };

  // The state in words, never by colour alone: "Alive, idle", "Not alive, connecting".
  function peerStateText(row) {
    var alive = row.alive === true ? 'Alive' : row.alive === false ? 'Not alive' : null;
    var st = null;
    if (row.state) st = Object.prototype.hasOwnProperty.call(PEER_STATES, row.state) ? PEER_STATES[row.state] : row.state.replace(/_/g, ' ');
    if (alive && st) return alive + ', ' + st.charAt(0).toLowerCase() + st.slice(1);
    return alive || st || '-';
  }

  // "Static" or "Auto", with how far away it is.
  function peerTypeText(row) {
    var kind = row.static === true ? 'Static' : row.static === false ? 'Auto' : null;
    var depth = known(row.depth) ? 'depth ' + row.depth : null;
    if (kind && depth) return kind + ', ' + depth;
    return kind || depth || '-';
  }

  // What is wrong with a peer, as words: [] when nothing is, or the node does not say.
  function peerProblems(row) {
    var out = [];
    if (row.hasSync && row.lastSyncSecondsAgo === null) out.push('Never synced');
    if (row.syncFailures > 0) out.push('Failing: ' + row.syncFailures + (row.syncFailures === 1 ? ' try' : ' tries'));
    return out;
  }

  // The name, or the first 8 characters of the address.
  function peerShortAddress(address) { return address.slice(0, 8) + '…'; }
  function peerLabel(row) { return row.name || peerShortAddress(row.address); }

  // The rows to show: all, or only those with a problem (their order is kept).
  function peerVisible(rows, onlyProblems) {
    return onlyProblems ? rows.filter(function (r) { return peerProblems(r).length > 0; }) : rows;
  }

  // "12 peers: 9 alive, 3 static, 2 never synced". total is how many the node listed:
  // when the table has fewer rows, the line says how many of them it shows.
  function peerSummaryLine(rows, total) {
    var alive = 0;
    var fixed = 0;
    var never = 0;
    var synced = false;
    rows.forEach(function (r) {
      if (r.alive === true) alive++;
      if (r.static === true) fixed++;
      if (r.hasSync) synced = true;
      if (r.hasSync && r.lastSyncSecondsAgo === null) never++;
    });
    var shown = rows.length;
    var lead = known(total) && total > shown ? shown + ' of ' + total + ' peers shown' : shown + (shown === 1 ? ' peer' : ' peers');
    var parts = [alive + ' alive', fixed + ' static'];
    if (synced) parts.push(never + ' never synced');
    return lead + ': ' + parts.join(', ');
  }

  var PEER_FAILURES = {
    no_link: 'No link', no_answer: 'No answer', refused_invalid_data: 'Refused the data', bad_key: 'Bad peering key', no_access: 'No access',
    busy: 'Busy', timeout: 'Timed out', bad_answer: 'Unexpected answer', io: 'Send error'
  };

  // Why the last try failed, in words: "-" when it did not fail or the node does not say.
  function peerFailureText(row) {
    if (!row.lastFailure) return '-';
    return Object.prototype.hasOwnProperty.call(PEER_FAILURES, row.lastFailure) ? PEER_FAILURES[row.lastFailure] : row.lastFailure.replace(/_/g, ' ');
  }

  var PEER_COLUMNS = [
    { key: 'name', label: 'Name' }, { key: 'type', label: 'Type' }, { key: 'state', label: 'State' }, { key: 'sync', label: 'Last sync', needs: 'sync' },
    { key: 'offered', label: 'Offered' }, { key: 'waiting', label: 'Waiting' }, { key: 'failures', label: 'Failures', needs: 'sync' }, { key: 'why', label: 'Last failure', needs: 'sync' },{ key: 'next', label: 'Next attempt', needs: 'sync' }
  ];

  // The columns to show: those the node's rows have the numbers for.
  function peerColumns(rows) {
    var synced = rows.some(function (r) { return r.hasSync; });
    return PEER_COLUMNS.filter(function (c) { return !c.needs || synced; });
  }

  function peerCell(row, key) {
    if (key === 'type') return peerTypeText(row);
    if (key === 'state') return peerStateText(row);
    if (key === 'sync') return peerSyncText(row);
    if (key === 'offered') return known(row.messagesOffered) ? num(row.messagesOffered) : '-';
    if (key === 'waiting') return known(row.unhandled) ? num(row.unhandled) : '-';
    if (key === 'failures') return known(row.syncFailures) ? num(row.syncFailures) : '-';
    if (key === 'why') return peerFailureText(row);
    if (key === 'next') return peerNextText(row);
    return peerLabel(row);
  }

  var peersOnlyProblems = false;

  // The Peers section of a node's Details: a summary line, a switch, and the table.
  function peerTableSection(d) {
    var rows = d.stats && d.stats.peerRows;
    if (!rows || !rows.length) return null;
    var total = d.stats.peerSummary ? d.stats.peerSummary.listed : rows.length;
    var s = section('Propagation peers');
    s.appendChild(elRuns('p', 'total', peerSummaryLine(rows, total)));
    var anyProblem = peerVisible(rows, true).length > 0;
    // The switch stays while it is on, so that it can be turned off again.
    if (anyProblem || peersOnlyProblems) {
      var toggle = el('button', 'toggle-btn', 'Show only peers with a problem');
      toggle.type = 'button';
      toggle.setAttribute('aria-pressed', peersOnlyProblems ? 'true' : 'false');
      toggle.addEventListener('click', function () {
        peersOnlyProblems = !peersOnlyProblems;
        renderDetail(true);
      });
      s.appendChild(toggle);
    }
    var shown = peerVisible(rows, peersOnlyProblems);
    if (!shown.length) {
      s.appendChild(el('p', 'note', 'No peer has a problem.'));
      return s;
    }
    var cols = peerColumns(rows);
    var table = el('table', 'peer-table');
    table.appendChild(el('caption', null, 'Peered nodes of this propagation node' + (peersOnlyProblems ? ', only those with a problem' : '')));
    var head = el('tr');
    cols.forEach(function (c) {
      var th = el('th', null, c.label);
      th.scope = 'col';
      head.appendChild(th);
    });
    table.appendChild(el('thead')).appendChild(head);
    var tbody = el('tbody');
    shown.forEach(function (r) {
      var tr = el('tr');
      cols.forEach(function (c) {
        var cell;
        if (c.key === 'name') {
          cell = el('th', 'peer-name');
          cell.scope = 'row';
          var label = el('span', r.name ? null : 'peer-addr', peerLabel(r));
          label.title = r.address;
          cell.appendChild(label);
          peerProblems(r).forEach(function (w) { cell.appendChild(el('span', 'peer-flag', w)); });
        } else {
          cell = el('td', c.key === 'offered' || c.key === 'waiting' || c.key === 'failures' ? 'num' : null, peerCell(r, c.key));
        }
        cell.setAttribute('data-label', c.label);
        tr.appendChild(cell);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    s.appendChild(table);
    var note = 'Times are as of the last stats check' + (d.stats.fetchedAt ? ' (' + ago(d.stats.fetchedAt) + ')' : '') + '. Hover or long-press a name for the full address.';
    s.appendChild(el('p', 'note', note));
    if (total > rows.length) s.appendChild(el('p', 'note', 'Only the first ' + rows.length + ' of ' + total + ' peers are listed: static peers first, then the most recently synced.'));
    return s;
  }

  function storageTab(d, ser, width, collecting) {
    var out = [];
    var facts = section('Message store');
    var pairs = d.view === 'combined' ? groupPropagationPairs(d.group) : propagationPairs(d.stats && d.stats.data ? d.stats.data.propagation : null);
    if (pairs.length) facts.appendChild(factsBlock(pairs));
    if (d.view !== 'combined' && d.stats && d.stats.peerSummary) {
      facts.appendChild(elRuns('p', 'note', 'Peered nodes it lists: ' + d.stats.peerSummary.listed + ' (' + d.stats.peerSummary.alive + ' alive, ' + d.stats.peerSummary.unhandled + ' messages waiting to send to them).'));
    }
    out.push(facts);
    var peerTable = d.view === 'combined' ? null : peerTableSection(d);
    if (peerTable) out.push(peerTable);
    var p = ser.propagation;
    if (!p || collecting) return out;
    // The size is in the tooltip, so one graph carries both.
    out.push(chartSection('Stored messages', d, ser, width, count, [{ label: 'Messages', cls: 'c1', points: p.storedMessages }], [{ label: 'Size', cls: 'c2', fmt: bytes, points: p.storedBytes }]));
    out.push(chartSection('Peered nodes', d, ser, width, count, [{ label: 'Alive', cls: 'c2', points: p.peersAlive }, { label: 'Total', cls: 'c4 d1', points: p.peersTotal }]));
    // The flow only means something on a node that relays messages.
    if (p.sentPerMinute && summarize(p.sentPerMinute.concat(p.receivedPerMinute || []))) {
      out.push(chartSection('Peer message flow', d, ser, width, perMinute, [{ label: 'To peers', cls: 'c1', points: p.sentPerMinute }, { label: 'From peers', cls: 'c3 d1', points: p.receivedPerMinute }]));
    }
    return out;
  }

  function diskTab(d, ser, width, collecting) {
    var out = [];
    var facts = section('Disk');
    var pairs = d.view === 'combined' ? groupDiskPairs(d.group) : diskPairs(d.stats && d.stats.data ? d.stats.data.disk : null);
    if (pairs.length) facts.appendChild(factsBlock(pairs));
    else facts.appendChild(el('p', 'note', 'No disk numbers.'));
    out.push(facts);
    // The free space graph is drawn only when the operator publishes exact figures.
    var k = ser.disk;
    if (k && !collecting) out.push(chartSection('Free disk space', d, ser, width, bytes, [{ label: d.view === 'combined' ? 'Free (node with the least)' : 'Free', cls: 'c2', points: k.fsFreeBytes }]));
    return out;
  }

  var detailTab = 'overview';
  var TAB_LABEL = { overview: 'Overview', traffic: 'Traffic', peers: 'Peers', storage: 'Storage', disk: 'Disk' };

  function detailTabs(d) {
    var out = ['overview', 'traffic', 'peers'];
    if (hasStorage(d)) out.push('storage');
    if (hasDisk(d)) out.push('disk');
    return out;
  }

  function selectTab(key, focus) {
    detailTab = key;
    renderDetail(true);
    if (focus) {
      var t = document.getElementById('tab-' + key);
      if (t) t.focus();
    }
  }

  // The tabs (wide screens) and the Section choice (phones) are two views of one state.
  // They are only rebuilt when the set changes, so the focus survives the refresh.
  var shownTabs = '';

  function syncTabs(keys) {
    var list = document.getElementById('detail-tabs');
    var select = document.getElementById('detail-section');
    if (keys.join() !== shownTabs) {
      shownTabs = keys.join();
      list.replaceChildren();
      select.replaceChildren();
      keys.forEach(function (k, i) {
        var t = el('button', 'tab', TAB_LABEL[k]);
        t.type = 'button';
        t.id = 'tab-' + k;
        t.setAttribute('role', 'tab');
        t.setAttribute('aria-controls', 'detail-body');
        t.addEventListener('click', function () { selectTab(k, false); });
        t.addEventListener('keydown', function (e) {
          var to = null;
          if (e.key === 'ArrowRight') to = keys[(i + 1) % keys.length];
          else if (e.key === 'ArrowLeft') to = keys[(i + keys.length - 1) % keys.length];
          else if (e.key === 'Home') to = keys[0];
          else if (e.key === 'End') to = keys[keys.length - 1];
          if (to === null) return;
          e.preventDefault();
          selectTab(to, true);
        });
        list.appendChild(t);
        var o = el('option', null, TAB_LABEL[k]);
        o.value = k;
        select.appendChild(o);
      });
    }
    var tabs = list.children;
    for (var i = 0; i < tabs.length; i++) {
      var on = tabs[i].id === 'tab-' + detailTab;
      tabs[i].setAttribute('aria-selected', on ? 'true' : 'false');
      tabs[i].tabIndex = on ? 0 : -1;
    }
    select.value = detailTab;
  }

  // inPlace: a choice was made in the dialog, so keep what has the focus where it is.
  function renderDetail(inPlace) {
    var body = document.getElementById('detail-body');
    var d = detailData;
    if (!d) return;
    var keys = detailTabs(d);
    if (keys.indexOf(detailTab) === -1) detailTab = 'overview';
    syncTabs(keys);
    body.setAttribute('aria-labelledby', 'tab-' + detailTab);
    var width = bodyWidth();
    var ser = d.series;
    var collecting = ser.sampleCount < 2;
    var parts = [];
    if (detailTab === 'overview') parts = overviewTab(d);
    else {
      // Only the charts of the open tab are drawn.
      if (collecting) parts.push(emptyState(d, ser));
      if (detailTab === 'traffic') parts = parts.concat(collecting ? [] : trafficTab(d, ser, width));
      else if (detailTab === 'peers') parts = parts.concat(peersTab(d, ser, width, collecting));
      else if (detailTab === 'storage') parts = parts.concat(storageTab(d, ser, width, collecting));
      else if (detailTab === 'disk') parts = parts.concat(diskTab(d, ser, width, collecting));
    }
    // The redraw replaces the charts: remember which focusable thing had the focus.
    var stops = body.querySelectorAll('[tabindex="0"], button');
    var at = -1;
    for (var i = 0; i < stops.length; i++) if (stops[i] === document.activeElement) at = i;
    body.replaceChildren.apply(body, parts);
    if (at >= 0) {
      var again = body.querySelectorAll('[tabindex="0"], button');
      if (again[at]) again[at].focus();
    }
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
      detailKey = '';
      var wait = el('p', 'note', 'Loading...');
      wait.setAttribute('role', 'status');
      body.replaceChildren(wait);
    }
    var ctl = new AbortController();
    var timer = setTimeout(function () { ctl.abort(); }, TIMEOUT_MS);
    fetch('/api/stats?host=' + encodeURIComponent(detailChoice === 'combined' ? detailHost : detailChoice) + '&range=' + detailRange + (detailChoice === 'combined' ? '&view=combined' : ''), { cache: 'no-store', signal: ctl.signal })
      .then(function (r) {
        if (r.status === 401) {
          // The login ended (or was never there): say so, and offer it.
          if (seq !== detailSeq) return null;
          detailData = null;
          detailKey = '';
          var p = el('p', 'note', 'The details need a login. ');
          var b = el('button', 'login-btn', 'Log in');
          b.type = 'button';
          b.setAttribute('data-role', 'login');
          b.addEventListener('click', function () { openLogin(b, null); });
          p.appendChild(b);
          body.replaceChildren(p);
          return null;
        }
        if (!r.ok) throw new Error('status ' + r.status);
        return r.json();
      })
      .then(function (data) {
        if (seq !== detailSeq || data === null) return;
        // The same numbers again (only the time of the answer differs): leave the page as it is.
        var key = JSON.stringify(data, function (k, v) { return k === 'generatedAt' ? undefined : v; });
        var same = detailData !== null && key === detailKey;
        detailKey = key;
        detailData = data;
        if (!same) renderDetail();
      })
      .catch(function () {
        if (seq !== detailSeq || detailData) return;
        var retry = el('button', null, 'Try again');
        retry.type = 'button';
        retry.addEventListener('click', function () { loadDetail(true); });
        var p = el('p', 'note', 'Could not load the details. ');
        p.setAttribute('role', 'status');
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
    detailTab = 'overview';
    shownTabs = '';
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
      // The row may have been rebuilt: find its button again, among the visible ones.
      var buttons = document.querySelectorAll('.detail-btn, .more-btn');
      for (var i = 0; i < buttons.length; i++) {
        var b = buttons[i];
        if (b.getAttribute('data-host') === detailHost && b.offsetParent !== null && b.getAttribute('data-role') === 'details') {
          b.focus();
          return;
        }
      }
      for (var j = 0; j < buttons.length; j++) {
        if (buttons[j].getAttribute('data-host') === detailHost && buttons[j].offsetParent !== null) { buttons[j].focus(); return; }
      }
    });
    document.getElementById('detail-view').addEventListener('change', function (e) {
      detailChoice = e.target.value;
      detailTab = 'overview';
      loadDetail(true);
    });
    // On a phone the view and range scroll with the page; the header keeps only what is needed to move.
    var controls = dlg.querySelector('.detail-controls');
    var top = dlg.querySelector('.detail-top');
    var phone = window.matchMedia ? window.matchMedia('(max-width: 600px)') : null;
    function place() {
      if (phone && phone.matches) dlg.insertBefore(controls, document.getElementById('detail-body'));
      else top.insertBefore(controls, document.getElementById('detail-tabs'));
    }
    place();
    if (phone && phone.addEventListener) phone.addEventListener('change', place);
    document.getElementById('detail-section').addEventListener('change', function (e) { selectTab(e.target.value, false); });
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

  // ---- Login ----

  var loginDlg = null;
  var loginOpener = null;
  // The node whose details to open once the login works.
  var loginThen = null;
  var loginBusy = false;

  function setAccount(viewer) {
    var box = document.getElementById('account');
    if (!box) return;
    // Without users there is no login at all: the line stays hidden.
    if (!viewer) {
      box.hidden = true;
      return;
    }
    var text = viewer.name ? 'Logged in as ' + viewer.name + '.' : 'Some numbers are only shown after a login.';
    setText('account-text', text);
    var b = document.getElementById('account-btn');
    var label = viewer.name ? 'Log out' : 'Log in';
    if (b.textContent !== label) b.textContent = label;
    b.setAttribute('data-state', viewer.name ? 'in' : 'out');
    box.hidden = false;
  }

  function loginError(text) {
    var e = document.getElementById('login-error');
    e.textContent = text;
    var bad = text ? 'true' : 'false';
    document.getElementById('login-name').setAttribute('aria-invalid', bad);
    document.getElementById('login-password').setAttribute('aria-invalid', bad);
  }

  function openLogin(opener, detailFor) {
    if (!loginDlg) return;
    loginOpener = opener || null;
    loginThen = detailFor || null;
    loginError('');
    document.getElementById('login-password').value = '';
    if (!loginDlg.open) loginDlg.showModal();
    var name = document.getElementById('login-name');
    (name.value ? document.getElementById('login-password') : name).focus();
  }

  // After the dialog closes, the focus goes back where it came from, or to the account button.
  function refocus(el) {
    if (el && el.isConnected && el.offsetParent !== null) el.focus();
    else {
      var b = document.getElementById('account-btn');
      if (b && b.offsetParent !== null) b.focus();
    }
  }

  function submitLogin(e) {
    e.preventDefault();
    if (loginBusy) return;
    var name = document.getElementById('login-name');
    var pass = document.getElementById('login-password');
    if (!name.value.trim() || !pass.value) {
      loginError('Enter your name and password.');
      (name.value.trim() ? pass : name).focus();
      return;
    }
    var submit = document.getElementById('login-submit');
    loginBusy = true;
    submit.disabled = true;
    submit.textContent = 'Logging in...';
    loginError('');
    var ok = false;
    fetch('/login', { method: 'POST', body: new URLSearchParams({ name: name.value, password: pass.value }), credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (body) { return { status: r.status, body: body }; });
      })
      .then(function (r) {
        if (r.status === 200 && r.body.ok) {
          ok = true;
          pass.value = '';
          var then = loginThen;
          loginThen = null;
          loginOpener = null;
          loginDlg.close();
          setText('account-live', 'Logged in as ' + r.body.name + '.');
          return load().then(function () {
            if (dlg && dlg.open) {
              loadDetail(true);
              document.getElementById('detail-body').focus();
            } else if (then) openDetail(then);
            else refocus(null);
          });
        }
        loginError(r.body && r.body.error ? r.body.error : 'Could not log in. Try again.');
      })
      .catch(function () { loginError('Could not reach the server. Try again.'); })
      .then(function () {
        loginBusy = false;
        submit.disabled = false;
        submit.textContent = 'Log in';
        if (!ok && loginDlg.open) {
          pass.value = '';
          pass.focus();
        }
      });
  }

  function logout() {
    fetch('/logout', { method: 'POST', body: new URLSearchParams(), credentials: 'same-origin', cache: 'no-store' })
      .then(function () {
        setText('account-live', 'Logged out.');
        if (dlg && dlg.open) dlg.close();
        return load();
      })
      .catch(function () { setText('account-live', 'Could not log out. Try again.'); });
  }

  function setupLogin() {
    loginDlg = document.getElementById('login');
    if (!loginDlg || typeof loginDlg.showModal !== 'function') return;
    document.getElementById('login-form').addEventListener('submit', submitLogin);
    document.getElementById('login-cancel').addEventListener('click', function () { loginDlg.close(); });
    loginDlg.addEventListener('click', function (e) { if (e.target === loginDlg) loginDlg.close(); });
    loginDlg.addEventListener('close', function () {
      var back = loginOpener;
      loginOpener = null;
      loginThen = null;
      if (back) refocus(back);
    });
    document.getElementById('account-btn').addEventListener('click', function (e) {
      if (e.currentTarget.getAttribute('data-state') === 'in') logout();
      else openLogin(e.currentTarget, null);
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
    var banner = document.getElementById('banner-sub');
    banner.replaceChildren();
    addRuns(banner, bannerCounts(lastData.hosts) + ' ');
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
    setAccount(data.viewer);
    document.body.classList.remove('stale');
    document.getElementById('banner').className = 'banner ' + data.overall;
    setText('banner-title', TITLE[data.overall] || TITLE.unknown);
    sub();
    // The spoken version changes only when the verdict or the count does.
    setText('banner-live', (TITLE[data.overall] || TITLE.unknown) + '. ' + bannerCounts(data.hosts));
    var list = document.getElementById('hosts');
    allHosts = data.hosts;
    if (globalThis.netmapView) globalThis.netmapView.update(data.hosts);
    // Keep the keyboard focus on the same button if its row is rebuilt.
    var active = document.activeElement;
    var fHost = active && list.contains(active) ? active.getAttribute('data-host') : null;
    var fRole = fHost ? active.getAttribute('data-role') : null;
    var next = {};
    var items = groupHosts(data.hosts).map(function (g) {
      var key = hostKey(g.h);
      // A row whose data did not change is left alone, with its open state and focus.
      var sig = JSON.stringify([g.h, g.members], function (k, v) {
        if (k === 'lastChecked') return undefined;
        if (k === 'fetchedAt' && !(this && this.stale)) return undefined;
        return v;
      });
      var old = rowCache[key];
      if (old && old.sig === sig && old.li.parentNode === list) {
        next[key] = old;
        [g.h].concat(g.members).forEach(function (m) {
          var t = old.li.querySelector('time[data-for="' + hostKey(m) + '"]');
          if (t && m.lastChecked) {
            t.setAttribute('data-ago', m.lastChecked);
            t.setAttribute('datetime', m.lastChecked);
          }
        });
        return old.li;
      }
      var li = g.h.group ? groupCard(g.h, g.members) : hostItem(g.h, {});
      next[key] = { sig: sig, li: li };
      return li;
    });
    rowCache = next;
    var same = items.length === list.children.length && items.every(function (li, i) { return list.children[i] === li; });
    if (!same) {
      if (items.length === list.children.length) {
        // Only the rows that changed are swapped.
        for (var n = 0; n < items.length; n++) if (list.children[n] !== items[n]) list.children[n].replaceWith(items[n]);
      } else {
        list.replaceChildren.apply(list, items);
      }
      if (fHost && fRole) {
        var btns = list.querySelectorAll('button[data-role="' + fRole + '"]');
        for (var i = 0; i < btns.length; i++) {
          if (btns[i].getAttribute('data-host') === fHost) { btns[i].focus(); break; }
        }
      }
    }
    tick();
    if (data.hosts.length > 0) list.setAttribute('aria-label', 'Entry points');
    else list.removeAttribute('aria-label');
  }

  function fail() {
    failed = true;
    if (lastData) {
      // Keep the old numbers and say how old they are.
      document.body.classList.add('stale');
      setText('banner-live', 'Could not reach the status service. Showing older data.');
    } else {
      document.getElementById('banner').className = 'banner unknown';
      setText('banner-title', 'Status unavailable');
      setText('banner-live', 'Status unavailable. Could not reach the status service.');
    }
    sub();
  }

  // Keeps the "N s ago" texts moving between fetches.
  function tick() {
    var times = document.querySelectorAll('time[data-ago]');
    for (var i = 0; i < times.length; i++) {
      var text = ago(times[i].getAttribute('data-ago'));
      if (times[i].textContent !== text) setAgo(times[i], text);
    }
  }

  function load() {
    var ctl = new AbortController();
    var timer = setTimeout(function () { ctl.abort(); }, TIMEOUT_MS);
    return fetch('/api/status', { cache: 'no-store', signal: ctl.signal })
      .then(function (r) {
        if (!r.ok) throw new Error('status ' + r.status);
        return r.json();
      })
      .then(render)
      .catch(fail)
      .then(function () { clearTimeout(timer); })
      .then(loadIncidents);
  }

  if (typeof document === 'undefined') {
    // Loaded by the tests: expose the pure parts only.
    globalThis.statusLogic = { ago: ago, barLabel: barLabel, bytes: bytes, duration: duration, nodeStatPairs: nodeStatPairs,
      formatRate: formatRate, niceTicks: niceTicks, runs: runs, gapLimit: gapLimit, summarize: summarize, summaryText: summaryText, axisTime: axisTime,
      nearestIndex: nearestIndex, timeAt: timeAt, tooltipTitle: tooltipTitle, tooltipRows: tooltipRows, tooltipSpeech: tooltipSpeech, tooltipPosition: tooltipPosition,
      peerShares: peerShares, percentText: percentText, propagationPairs: propagationPairs, diskPairs: diskPairs, diskUsedPercent: diskUsedPercent, groupStoragePairs: groupStoragePairs, groupPropagationPairs: groupPropagationPairs, groupDiskPairs: groupDiskPairs, hostKey: hostKey, displayName: displayName, summaryFacts: summaryFacts, lastUp: lastUp, downText: downText, staleNote: staleNote, warnings: warnings, backlogAbnormal: backlogAbnormal, backlogPairs: backlogPairs, networkFacts: networkFacts, storeFacts: storeFacts, diskFacts: diskFacts, groupFacts: groupFacts, partialNote: partialNote, groupWarning: groupWarning, badgeText: badgeText, badgeTitle: badgeTitle, groupHosts: groupHosts, bannerCounts: bannerCounts,
      peerRange: peerRange, peerNote: peerNote, groupCoverage: groupCoverage, groupPairs: groupPairs, peerRangeRows: peerRangeRows, intervalWords: intervalWords, versionSummary: versionSummary, count: count,
      peerSpan: peerSpan, peerSyncText: peerSyncText, peerNextText: peerNextText, peerFailureText: peerFailureText, peerStateText: peerStateText, peerTypeText: peerTypeText, peerProblems: peerProblems,
      peerShortAddress: peerShortAddress, peerLabel: peerLabel, peerVisible: peerVisible, peerSummaryLine: peerSummaryLine, peerColumns: peerColumns, peerCell: peerCell,
      rowLocks: rowLocks, lockText: lockText, detailsLocked: detailsLocked,
      dayLevel: dayLevel, dayDate: dayDate, dayTitle: dayTitle, uptimeLabel: uptimeLabel, incidentSpan: incidentSpan };
    return;
  }
  setupDetail();
  setupLogin();
  load();
  setInterval(load, REFRESH_MS);
  setInterval(tick, TICK_MS);
})();
