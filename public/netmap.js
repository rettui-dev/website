// The backbone map on the status page, drawn as inline SVG from the data of /api/status. Each proxy is
// a frame around the nodes it passes visitors to, with the links between those nodes as arrows and
// the external peers below. When that does not fit (a narrow screen, too many nodes or too many
// crossing links) the map shows one node at a time instead, picked with a row of buttons. The layout
// is pure (see netmapLogic, used by the tests); the drawing sets text with textContent only.
(function () {
  var WORD = { up: 'Up', down: 'Down', unknown: 'Unknown', external: 'External' };
  var GLYPH = { up: '●', down: '✕', unknown: '?', external: '↗' };
  // Each box has one more line under its facts: the address, in small type.
  var BOX_H = 88;
  // A proxy drawn as a box (in the one-node view) has one more line, its tag, and a double border.
  var PROXY_H = 104;
  var EXT_H = 68;
  var MAX_BOX_W = 176;
  var MIN_BOX_W = 104;
  var PAD = 8;
  var LINE_H = 15;
  var CHAR_W = 6.8;
  var MIN_WIDTH = 280;

  // When the whole map gives way to the one-node view: below this width, with more nodes than this in
  // one frame or row, or when the links that skip a node need more lanes than this.
  var FOCUS_BELOW = 640;
  var MAX_ROW_NODES = 8;
  var MAX_LANES = 4;

  // The frame: from its outer line to the row of nodes, the height of its header, and the room under
  // the row before the frame closes.
  var FRAME_INSET = 20;
  var HEADER_H = 118;
  var FRAME_FOOT = 24;
  // Nodes in a row: the gap between neighbours holds a short arrow, so it is never narrower than this.
  var MIN_GAP = 24;
  var MAX_GAP = 140;
  // Links that skip a node run above the row: lane l is LANE_BASE + LANE_STEP l above the boxes.
  var LANE_BASE = 22;
  var LANE_STEP = 18;
  var PORT = 22;
  var PORT_STEP = 10;
  // Lines to external peers that have to turn run in lanes under the frame, this far apart.
  var BUS_STEP = 10;
  var EXT_GAP = 12;
  var GROUP_GAP = 28;
  var LOOSE_HEAD = 24;

  // The one-node view: the node in the middle, and at most this many neighbours on each side.
  var FOCUS_W = 240;
  var FOCUS_H = 124;
  var MAX_SIDE = 8;
  var PHONE_SIDE = 6;
  var MAX_PROXIES = 3;
  var MAX_EXTERNALS = 8;
  var MAX_PILLS = 64;

  // What the map takes from /api/status at most: the rest is left out, so a huge answer cannot make
  // the page slow. Names are cut to MAX_NAME characters once, here, for every place that shows them.
  var MAX_HOSTS = 64;
  var MAX_UPSTREAMS = 8;
  var MAX_MEMBERS = 64;
  var MAX_NAME = 64;
  var MAX_ADDRESS = 128;
  var STATES = { up: true, down: true, unknown: true };

  // Lookups by a host key use objects with no prototype, so a key such as "toString" is only a key.
  function hostKey(h) { return h.host + ':' + h.port; }
  function displayName(h) { return h.name || clip(hostKey(h), MAX_NAME); }
  // n may be a number or a number already formatted as text ("1", "1,200").
  function plural(n, one, many) { return n + ' ' + (n === 1 || n === '1' ? one : many); }

  function num(n) {
    return n.toLocaleString === undefined ? String(n) : n.toLocaleString('en-US');
  }

  // Cuts text to at most max characters, with an ellipsis; never an empty line.
  function clip(text, max) {
    var t = String(text);
    if (max < 2) max = 2;
    return t.length <= max ? t : t.slice(0, max - 1) + '…';
  }

  // Breaks text into at most maxLines lines of at most max characters, at spaces where it can
  // (a longer word is cut); what does not fit ends in an ellipsis.
  function wrap(text, max, maxLines) {
    max = Math.max(1, Math.floor(max) || 1);
    maxLines = Math.max(1, Math.floor(maxLines) || 1);
    var words = [];
    String(text).split(/\s+/).filter(Boolean).forEach(function (w) {
      for (; w.length > max; w = w.slice(max)) words.push(w.slice(0, max));
      words.push(w);
    });
    var lines = [];
    var cur = '';
    var used = 0;
    for (; used < words.length; used++) {
      var next = cur ? cur + ' ' + words[used] : words[used];
      if (next.length <= max) { cur = next; continue; }
      if (lines.length === maxLines - 1) break;
      lines.push(cur);
      cur = words[used];
    }
    lines.push(cur);
    if (used < words.length) lines[lines.length - 1] = clip(lines[lines.length - 1] + ' ' + words.slice(used).join(' '), max);
    return lines;
  }

  function clients(h) {
    var s = h.stats;
    if (!s || s.stale || !s.data || !s.data.interfaces) return null;
    var c = s.data.interfaces.clients;
    return typeof c === 'number' && isFinite(c) ? c : null;
  }

  function isObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
  function plainText(v, max) {
    if (typeof v !== 'string') return null;
    var t = v.trim();
    return t ? clip(t, max) : null;
  }

  // The hosts of /api/status as the map uses them: plain objects with a host and a port, each key
  // once, at most MAX_HOSTS; a state it does not know is unknown, and names are text, cut short.
  // Anything else in an entry is dropped, so nothing from the network reaches a class or a label
  // unchecked.
  function cleanHosts(hosts) {
    var out = [];
    var seen = Object.create(null);
    (Array.isArray(hosts) ? hosts : []).forEach(function (h) {
      if (out.length >= MAX_HOSTS || !isObject(h) || typeof h.host !== 'string' || !h.host || h.host.length > 253) return;
      var port = typeof h.port === 'number' && h.port % 1 === 0 && h.port >= 0 && h.port <= 65535 ? h.port
        : typeof h.port === 'string' && /^\d{1,5}$/.test(h.port) ? h.port : null;
      if (port === null) return;
      var key = h.host + ':' + port;
      if (seen[key]) return;
      seen[key] = true;
      var proxy = h.role === 'proxy';
      var members = proxy && isObject(h.proxy) && Array.isArray(h.proxy.for)
        ? h.proxy.for.filter(function (m) { return typeof m === 'string'; }).slice(0, MAX_MEMBERS) : null;
      var ups = (Array.isArray(h.upstreams) ? h.upstreams : []).filter(function (u) { return isObject(u) && plainText(u.name, MAX_NAME) !== null; })
        .slice(0, MAX_UPSTREAMS).map(function (u) { return { name: plainText(u.name, MAX_NAME), address: plainText(u.address, MAX_ADDRESS), online: u.online === true || u.online === false ? u.online : null }; });
      out.push({
        host: h.host, port: port, name: plainText(h.name, MAX_NAME), status: STATES[h.status] === true ? h.status : 'unknown',
        role: proxy ? 'proxy' : 'node', proxy: members ? { for: members } : null, proxiedBy: typeof h.proxiedBy === 'string' ? h.proxiedBy : null,
        latencyMs: typeof h.latencyMs === 'number' && isFinite(h.latencyMs) ? h.latencyMs : null,
        uptime90: isObject(h.uptime90) && typeof h.uptime90.percent90 === 'number' && isFinite(h.uptime90.percent90) ? { percent90: h.uptime90.percent90 } : null,
        stats: isObject(h.stats) ? h.stats : null, upstreams: ups, links: Array.isArray(h.links) ? h.links : []
      });
    });
    return out;
  }

  // What a link says about itself, in parentheses after a node's name in the text alternatives.
  function qualifiers(e, unknown) {
    var q = [];
    if (e.enabled === false) q.push('turned off');
    if (e.conflict === 'not_found') q.push('declared; not found in the node\'s config');
    else {
      if (e.source === 'declared' && !unknown) q.push('declared');
      if (e.conflict === 'direction') q.push('the operator declared the other direction');
    }
    return q.join(', ');
  }

  function qualified(name, q) { return q ? name + ' (' + q + ')' : name; }

  // The links between nodes, one edge per pair of nodes: {from, to, kind: 'link', dir: 'dials' |
  // 'unknown', mutual, enabled, source, conflict, back}. Two nodes that dial each other are one
  // edge (back is the other direction's facts); a pair linked in an unknown direction is one edge.
  // Targets that are not on the page, links to the node itself and anything malformed are skipped.
  function linkEdges(list, byId) {
    var order = Object.create(null);
    list.forEach(function (h, i) { order[hostKey(h)] = i; });
    var pairs = Object.create(null);
    var keys = [];
    list.forEach(function (h) {
      var from = hostKey(h);
      (Array.isArray(h.links) ? h.links.slice(0, 8) : []).forEach(function (l) {
        if (!l || typeof l.to !== 'string' || l.to === from || !byId[l.to] || byId[l.to].kind === 'external') return;
        if (l.dir !== 'dials' && l.dir !== 'unknown') return;
        var e = { from: from, to: l.to, dir: l.dir, enabled: l.enabled === false ? false : l.enabled === true ? true : null,
          source: l.source === 'declared' ? 'declared' : 'detected', conflict: l.conflict === 'direction' || l.conflict === 'not_found' ? l.conflict : null };
        var id = order[from] < order[l.to] ? from + '|' + l.to : l.to + '|' + from;
        if (!pairs[id]) { pairs[id] = []; keys.push(id); }
        pairs[id].push(e);
      });
    });
    return keys.map(function (id) {
      var es = pairs[id];
      var dials = es.filter(function (e) { return e.dir === 'dials'; });
      var use = dials.length ? dials : es;
      var first = use[0];
      var other = use.filter(function (e) { return e.from !== first.from; })[0] || null;
      var mutual = dials.length > 0 && other !== null;
      // A mutual pair is drawn from the node that comes first on the page.
      if (mutual && order[other.from] < order[first.from]) { var t = first; first = other; other = t; }
      var edge = { from: first.from, to: first.to, kind: 'link', dir: first.dir, mutual: mutual, enabled: first.enabled, source: first.source, conflict: first.conflict, back: null };
      if (mutual) edge.back = { enabled: other.enabled, source: other.source, conflict: other.conflict };
      else if (first.dir === 'unknown') {
        edge.from = order[first.from] < order[first.to] ? first.from : first.to;
        edge.to = edge.from === first.from ? first.to : first.from;
      }
      return edge;
    });
  }

  // The sentences of the shared wording for one node: dials, dialled by, mutual and unknown links.
  function linkSentences(n, edges, name) {
    var dials = [];
    var by = [];
    var linked = [];
    var mutual = [];
    edges.forEach(function (e) {
      if (e.kind !== 'link' || (e.from !== n.id && e.to !== n.id)) return;
      var mine = e.from === n.id;
      var other = name[mine ? e.to : e.from];
      if (e.dir === 'unknown') { linked.push(qualified(other, qualifiers(e, true))); return; }
      if (e.mutual) {
        var a = qualifiers(mine ? e : e.back, false);
        var b = qualifiers(mine ? e.back : e, false);
        var text = n.name + ' and ' + other + ' dial each other';
        if (a && a === b) text += ' (' + a + ')';
        text += '.';
        if (a && a !== b) text += ' ' + n.name + ' to ' + other + ': ' + a + '.';
        if (b && a !== b) text += ' ' + other + ' to ' + n.name + ': ' + b + '.';
        mutual.push(text);
        return;
      }
      (mine ? dials : by).push(qualified(other, qualifiers(e, false)));
    });
    var out = [];
    if (dials.length) out.push('Dials ' + dials.join(', ') + '.');
    if (by.length) out.push('Dialled by ' + by.join(', ') + '.');
    if (linked.length) out.push('Linked with ' + linked.join(', ') + ', direction not known.');
    return out.concat(mutual).join(' ');
  }

  // The nodes and links of the map. Returns {nodes, edges, empty}; empty is true when there is
  // nothing to draw beyond plain nodes (no proxy, no upstream and no link between nodes).
  function buildModel(hosts) {
    var list = cleanHosts(hosts);
    var hasProxy = list.some(function (h) { return h.role === 'proxy'; });
    var nodes = [];
    var edges = [];
    var byId = Object.create(null);
    var externals = 0;
    list.forEach(function (h) {
      var tier = h.role === 'proxy' ? 0 : (h.proxiedBy || hasProxy) ? 1 : 0;
      var n = {
        id: hostKey(h), kind: h.role === 'proxy' ? 'proxy' : 'node', name: displayName(h), state: h.status || 'unknown', tier: tier,
        clients: h.status === 'down' ? null : clients(h), ms: h.latencyMs, addr: hostKey(h),
        uptime: h.uptime90 && typeof h.uptime90.percent90 === 'number' ? h.uptime90.percent90 : null,
        members: h.proxy && Array.isArray(h.proxy.for) ? h.proxy.for.length : 0, address: null, usedBy: []
      };
      nodes.push(n);
      byId[n.id] = n;
    });
    list.forEach(function (h) {
      var from = byId[hostKey(h)];
      if (h.proxy && Array.isArray(h.proxy.for)) {
        h.proxy.for.forEach(function (m) { if (byId[m]) edges.push({ from: from.id, to: m, kind: 'proxy' }); });
      }
      h.upstreams.forEach(function (u) {
        // The same peer listed by two nodes is one box.
        var id = 'ext:' + u.name.toLowerCase() + '|' + (u.address || '');
        if (!byId[id]) {
          byId[id] = { id: id, kind: 'external', name: u.name, addr: null, state: 'external', tier: -1, clients: null, ms: null, uptime: null, members: 0, address: u.address || null, usedBy: [], report: null, reports: [] };
          nodes.push(byId[id]);
          externals++;
        }
        byId[id].usedBy.push(from.name);
        // What the node itself says about this upstream: nothing is checked from here.
        var report = u.online === true ? 'up' : u.online === false ? 'down' : null;
        if (report) byId[id].reports.push({ id: from.id, by: from.name, report: report });
        edges.push({ from: from.id, to: id, kind: 'upstream', report: report });
      });
    });
    // A box several nodes share is up when any node reporting on it says online, down when every node
    // reporting says offline, and otherwise stays an unknown external peer (report null).
    nodes.forEach(function (n) {
      if (n.kind !== 'external' || !n.reports.length) return;
      n.report = n.reports.some(function (r) { return r.report === 'up'; }) ? 'up' : 'down';
    });
    var links = linkEdges(list, byId);
    links.forEach(function (e) { edges.push(e); });
    var last = 0;
    nodes.forEach(function (n) { if (n.kind !== 'external' && n.tier > last) last = n.tier; });
    nodes.forEach(function (n) { if (n.kind === 'external') n.tier = last + 1; });
    var state = Object.create(null);
    nodes.forEach(function (n) { state[n.id] = n.state; });
    edges.forEach(function (e) { e.down = state[e.from] === 'down' || state[e.to] === 'down' || e.report === 'down'; });
    if (links.length) {
      var names = Object.create(null);
      nodes.forEach(function (n) { names[n.id] = n.name; });
      nodes.forEach(function (n) { n.linkText = linkSentences(n, links, names); });
    }
    return { nodes: nodes, edges: edges, empty: !hasProxy && externals === 0 && links.length === 0 };
  }

  // One node in words, for the title, the accessible name and the list.
  // withAddress adds the address a proxy or node is checked at, for the boxes of the map (the list
  // has the cards beside it, which show it already).
  function describe(n, withAddress) {
    var out = [n.kind === 'proxy' ? 'Proxy ' + n.name + ', ' + WORD[n.state].toLowerCase()
      : n.name + ': ' + (n.kind === 'external' ? 'external backbone peer, not monitored' : WORD[n.state].toLowerCase())];
    if (n.kind === 'external' && n.reports && n.reports.length) {
      out.push('reported ' + n.reports.map(function (r) { return r.report + ' via ' + r.by; }).join(', '));
    }
    if (withAddress && n.kind !== 'external' && n.addr && n.addr !== n.name) out.push('address ' + n.addr);
    if (n.kind === 'proxy') out.push('passes visitors to ' + plural(n.members, 'node', 'nodes'));
    if (n.kind === 'external' && n.address) out.push('address ' + n.address + ' (not checked)');
    if (n.kind === 'external' && n.usedBy.length) out.push('used by ' + n.usedBy.join(', '));
    if (n.clients !== null) out.push(plural(n.clients, 'client', 'clients'));
    if (n.kind !== 'external' && n.state === 'up' && n.ms !== null) out.push('connect time ' + n.ms + ' ms');
    if (n.uptime !== null) out.push('uptime ' + n.uptime + '% over 90 days');
    return out.join(', ') + '.' + (n.linkText ? ' ' + n.linkText : '');
  }

  // The state and fact lines drawn in a box.
  function facts(n) {
    var shown = n.kind === 'external' && n.report ? n.report : n.state;
    var out = [GLYPH[shown] + ' ' + WORD[shown]];
    if (n.clients !== null) out.push(plural(num(n.clients), 'client', 'clients'));
    else if (n.kind === 'external') out.push(n.report ? 'reported by node, not checked' : 'not checked');
    else if (n.state === 'up' && n.ms !== null) out.push(n.ms + ' ms');
    return out;
  }

  // The line above the state in the box, for what the box is, in words: only a proxy has one.
  function tag(n) { return n.kind === 'proxy' ? 'Proxy' : null; }

  // The count in the heading of the map: the proxy, the nodes and the links, each said apart.
  function summaryText(model) {
    var c = { proxy: 0, node: 0, external: 0 };
    model.nodes.forEach(function (n) { c[n.kind]++; });
    var out = [];
    if (c.proxy) out.push(plural(c.proxy, 'proxy', 'proxies'));
    if (c.node) out.push(plural(c.node, 'node', 'nodes'));
    if (c.external) out.push(plural(c.external, 'external peer', 'external peers'));
    var between = model.edges.filter(function (e) { return e.kind === 'link'; }).length;
    out.push(plural(model.edges.length - between, 'link', 'links'));
    if (between) out.push(plural(between, 'link between nodes', 'links between nodes'));
    return out.join(', ');
  }

  function round1(v) { return Math.round(v * 10) / 10; }
  function pt(x, y) { return round1(x) + ' ' + round1(y); }
  function isLink(e) { return e.kind === 'link'; }

  function index(model) {
    var byId = Object.create(null);
    model.nodes.forEach(function (n) { byId[n.id] = n; });
    return byId;
  }

  // A line through the points with rounded corners of radius r (less where a leg is short).
  function rpath(pts, r) {
    var d = 'M' + pt(pts[0][0], pts[0][1]);
    for (var i = 1; i < pts.length - 1; i++) {
      var x0 = pts[i - 1][0], y0 = pts[i - 1][1], x1 = pts[i][0], y1 = pts[i][1], x2 = pts[i + 1][0], y2 = pts[i + 1][1];
      var l1 = Math.hypot(x1 - x0, y1 - y0);
      var l2 = Math.hypot(x2 - x1, y2 - y1);
      if (!l1 || !l2 || !r) { d += ' L' + pt(x1, y1); continue; }
      var rr = Math.min(r, l1 / 2, l2 / 2);
      d += ' L' + pt(x1 - ((x1 - x0) / l1) * rr, y1 - ((y1 - y0) / l1) * rr) + ' Q' + pt(x1, y1) + ' ' + pt(x1 + ((x2 - x1) / l2) * rr, y1 + ((y2 - y1) / l2) * rr);
    }
    var last = pts[pts.length - 1];
    return d + ' L' + pt(last[0], last[1]);
  }

  // A soft S from one side of a box to the side of another.
  function curve(a, b) {
    var mx = (a[0] + b[0]) / 2;
    return 'M' + pt(a[0], a[1]) + ' C' + pt(mx, a[1]) + ' ' + pt(mx, b[1]) + ' ' + pt(b[0], b[1]);
  }

  // The mark at the end of a link for what that direction says: a filled arrowhead, an outlined one
  // when the operator declared it, or a bar across the line when it is turned off.
  function head(f) { return f.enabled === false ? 'bar' : f.source === 'declared' ? 'open' : 'arrow'; }

  // The marks of a link drawn from node a to the other end: a dot where a one-way link starts, the
  // head of each direction at the end it dials, and hollow circles when the direction is not known.
  function marks(e, a) {
    if (e.dir === 'unknown') return { start: 'ring', end: 'ring', off: false, declared: e.source === 'declared' };
    if (e.mutual) {
      var atTo = head({ enabled: e.enabled, source: e.source });
      var atFrom = head(e.back);
      return {
        start: a === e.to ? atTo : atFrom, end: a === e.to ? atFrom : atTo,
        off: e.enabled === false && e.back.enabled === false, declared: e.source === 'declared' && e.back.source === 'declared'
      };
    }
    return { start: 'dot', end: head(e), off: e.enabled === false, declared: e.source === 'declared' };
  }

  // Two short slanted slashes across a line at x, y, which runs at angle ang: a node is down.
  function slashes(x, y, ang) {
    var out = [];
    [-4, 4].forEach(function (off) {
      var cx = x + Math.cos(ang) * off;
      var cy = y + Math.sin(ang) * off;
      var a2 = ang + Math.PI / 2 + 0.6;
      var dx = Math.cos(a2) * 7;
      var dy = Math.sin(a2) * 7;
      out.push('M' + pt(cx - dx, cy - dy) + ' L' + pt(cx + dx, cy + dy));
    });
    return out;
  }

  // One link between nodes, drawn from node a; mid is [x, y, angle] of the middle of the line.
  function linkOut(e, a, pts, d, mid, inFrame) {
    var m = marks(e, a);
    return {
      from: e.from, to: e.to, kind: 'link', down: e.down, d: d, pts: pts, dir: e.dir, mutual: e.mutual, lane: null,
      start: m.start, end: m.end, off: m.off, declared: m.declared, ticks: e.down ? slashes(mid[0], mid[1], mid[2]) : [], inFrame: inFrame
    };
  }

  // Two slashes across the last leg of an upstream line that the node reports as offline.
  function upstreamTicks(report, pts) {
    if (report !== 'down' || pts.length < 2) return [];
    var a = pts[pts.length - 2];
    var b = pts[pts.length - 1];
    return slashes((a[0] + b[0]) / 2, (a[1] + b[1]) / 2, Math.atan2(b[1] - a[1], b[0] - a[0]));
  }

  // The external box as one node sees it: its own report only (the one-node view).
  function seenBy(n, id, report) {
    return Object.assign({}, n, { report: report, reports: n.reports.filter(function (r) { return r.id === id; }) });
  }

  function boxH(n) { return n.kind === 'proxy' ? PROXY_H : n.kind === 'external' ? EXT_H : BOX_H; }

  // The lines of text in a box: the tag of a proxy, the name (two lines at most, one for an external
  // peer), the state and one fact, centred.
  // The address shown in small type under a box's facts: where a proxy or node is checked, or what
  // the operator gave for an external peer; none when it is the name already.
  function addressOf(n) {
    var a = n.kind === 'external' ? n.address : n.addr;
    return a && a !== n.name ? a : null;
  }

  function boxLines(n, w, h) {
    var max = Math.max(4, Math.floor((w - 10) / CHAR_W));
    var names = wrap(n.name, max, n.kind === 'external' ? 1 : 2);
    var texts = facts(n).map(function (f) { return clip(f, max); });
    var addr = addressOf(n);
    if (addr) texts.push(clip(addr, max));
    var label = tag(n);
    var count = (label ? 1 : 0) + names.length + texts.length;
    var top = (h - count * LINE_H) / 2 + 11;
    var lines = [];
    var at = function (text, i, cls) { lines.push({ text: text, x: w / 2, y: round1(top + i * LINE_H), cls: cls, anchor: 'middle' }); };
    if (label) at(label, 0, 'nm-tag');
    var first = label ? 1 : 0;
    names.forEach(function (t, i) { at(t, first + i, 'nm-name'); });
    texts.forEach(function (t, i) { at(t, first + names.length + i, i === 0 ? 'nm-state' : addr && i === texts.length - 1 ? 'nm-addr' : 'nm-fact'); });
    return lines;
  }

  function nodeOut(n, x, y, w, h, id) {
    return { id: id || n.id, kind: n.kind, state: n.state, report: n.kind === 'external' ? n.report : null, x: Math.round(x), y: Math.round(y), w: w, h: h, lines: boxLines(n, w, h), label: describe(n, true) };
  }

  // The facts of a proxy in its frame header, on one line.
  function proxyFacts(p) {
    var out = [];
    if (p.clients !== null) out.push(plural(num(p.clients), 'client', 'clients'));
    if (p.state === 'up' && p.ms !== null) out.push(p.ms + ' ms');
    if (p.uptime !== null) out.push(p.uptime + '% uptime');
    return out.join(' · ');
  }

  // The frame of a proxy: its outer line has the state colour, and its header says what it is.
  function frameNode(p, top, W, h, members, elsewhere) {
    var fw = W - 2 * PAD;
    var state = GLYPH[p.state] + ' ' + WORD[p.state];
    var lines = [
      { text: 'Proxy', x: 26, y: 34, cls: 'nm-tag', anchor: 'start' },
      { text: clip(p.name, Math.max(8, Math.floor((fw - 52) / 9))), x: 26, y: 58, cls: 'nm-name big', anchor: 'start' },
      { text: state, x: 26, y: 78, cls: 'nm-state', anchor: 'start' }
    ];
    var factX = 26 + Math.round(state.length * 7.5) + 14;
    var f = proxyFacts(p);
    if (f) lines.push({ text: clip(f, Math.floor((fw - factX - 26) / CHAR_W)), x: factX, y: 78, cls: 'nm-fact', anchor: 'start' });
    // A node behind two proxies is drawn in the first one's frame; the other says where it went.
    var right = members && elsewhere ? 'Passes visitors to the ' + plural(members, 'node', 'nodes') + ' inside and ' + elsewhere + ' in another frame'
      : members ? 'Passes visitors to the ' + plural(members, 'node', 'nodes') + ' inside'
        : elsewhere ? 'Passes visitors to ' + plural(elsewhere, 'node', 'nodes') + ' in another frame' : 'No nodes behind it on this page';
    lines.push({ text: right, x: fw - 26, y: 34, cls: 'nm-fact', anchor: 'end' });
    var addr = addressOf(p);
    if (addr) lines.push({ text: clip(addr, Math.max(8, Math.floor((fw - 52) / CHAR_W))), x: 26, y: 98, cls: 'nm-addr', anchor: 'start' });
    return { id: p.id, kind: 'proxy', frame: true, state: p.state, x: PAD, y: Math.round(top), w: fw, h: Math.round(h), lines: lines, label: describe(p, true) };
  }

  // The rows of the map: one per proxy, with the nodes it passes visitors to (a node listed by two
  // proxies sits in the first one's frame), then one plain row of the nodes behind no proxy.
  function groupsOf(model) {
    var groups = [];
    var taken = Object.create(null);
    model.nodes.forEach(function (p) {
      if (p.kind !== 'proxy') return;
      var mine = Object.create(null);
      model.edges.forEach(function (e) { if (e.kind === 'proxy' && e.from === p.id) mine[e.to] = true; });
      var members = model.nodes.filter(function (m) { return m.kind === 'node' && mine[m.id] && !taken[m.id]; });
      members.forEach(function (m) { taken[m.id] = true; });
      groups.push({ proxy: p, members: members });
    });
    var loose = model.nodes.filter(function (m) { return m.kind === 'node' && !taken[m.id]; });
    if (loose.length) groups.push({ proxy: null, members: loose });
    return groups;
  }

  // The links inside one row: neighbours get a short arrow in the gap; a link that skips a node runs
  // above the row in a lane, the shortest first, each in the lowest lane where it overlaps no other.
  // Two links may share a lane when one ends at the node where the other starts.
  function planRow(members, links) {
    var at = Object.create(null);
    members.forEach(function (m, i) { at[m.id] = i; });
    var near = [];
    var skips = [];
    links.forEach(function (e) {
      if (at[e.from] === undefined || at[e.to] === undefined) return;
      // A link is drawn from the node that dials; one with no single direction from left to right.
      var a = e.dir === 'dials' && !e.mutual ? e.from : at[e.from] < at[e.to] ? e.from : e.to;
      var b = a === e.from ? e.to : e.from;
      var r = { e: e, a: a, b: b, ia: at[a], ib: at[b], lane: 0 };
      (Math.abs(r.ia - r.ib) === 1 ? near : skips).push(r);
    });
    var lanes = [];
    skips.slice().sort(function (p, q) {
      return Math.abs(p.ia - p.ib) - Math.abs(q.ia - q.ib) || Math.min(p.ia, p.ib) - Math.min(q.ia, q.ib);
    }).forEach(function (r) {
      var lo = Math.min(r.ia, r.ib);
      var hi = Math.max(r.ia, r.ib);
      var l = 0;
      while (l < lanes.length && lanes[l].some(function (t) { return lo < t[1] && hi > t[0]; })) l++;
      (lanes[l] = lanes[l] || []).push([lo, hi]);
      r.lane = l;
    });
    return { near: near, skips: skips, lanes: lanes.length };
  }

  // Where the arcs meet the top of each box: those going left on its left half, those going right on
  // its right half, the highest lane nearest the middle so no arc crosses another at its own node.
  function ports(row, xs, w) {
    var ends = Object.create(null);
    row.skips.forEach(function (r) {
      [['xa', r.ia, r.ib], ['xb', r.ib, r.ia]].forEach(function (x) {
        var k = x[1] + (x[2] < x[1] ? 'L' : 'R');
        (ends[k] = ends[k] || []).push({ r: r, field: x[0] });
      });
    });
    Object.keys(ends).forEach(function (k) {
      var list = ends[k].sort(function (p, q) { return q.r.lane - p.r.lane; });
      var i = Number(k.slice(0, -1));
      var sign = k.slice(-1) === 'L' ? -1 : 1;
      var m = list.length;
      var room = w / 2 - 12;
      var step = m > 1 ? Math.min(PORT_STEP, (room - 8) / (m - 1)) : 0;
      var first = Math.max(8, Math.min(PORT - (step * (m - 1)) / 2, room - step * (m - 1)));
      list.forEach(function (it, n) { it.r[it.field] = round1(xs[i] + w / 2 + sign * (first + n * step)); });
    });
  }

  // The external peers of one row, each under the node that uses it. Returns false when they do not
  // fit side by side. A peer used by several nodes of the row is one box; each line ends at its own
  // spot on the box, and a line that has to turn does so in a lane under the frame.
  function placeExternals(model, byId, sources, bottom, EW, W, seen, out) {
    var srcOf = Object.create(null);
    sources.forEach(function (s) { srcOf[s.id] = s; });
    var exts = [];
    var extOf = Object.create(null);
    model.edges.forEach(function (e) {
      if (e.kind !== 'upstream' || !srcOf[e.from] || !byId[e.to]) return;
      var x = extOf[e.to];
      if (!x) { x = extOf[e.to] = { node: byId[e.to], uses: [], order: exts.length }; exts.push(x); }
      x.uses.push({ e: e, src: srcOf[e.from] });
    });
    if (!exts.length) return { bottom: bottom };
    exts.forEach(function (x) { x.want = x.uses.reduce(function (a, u) { return a + u.src.cx; }, 0) / x.uses.length; });
    var order = exts.slice().sort(function (p, q) { return p.want - q.want || p.order - q.order; });
    var pos = order.map(function (x) { return x.want - EW / 2; });
    for (var i = 0; i < pos.length; i++) pos[i] = Math.max(pos[i], i ? pos[i - 1] + EW + EXT_GAP : PAD);
    for (var j = pos.length - 1; j >= 0; j--) pos[j] = Math.min(pos[j], j < pos.length - 1 ? pos[j + 1] - EW - EXT_GAP : W - PAD - EW);
    if (pos[0] < PAD - 0.5) return false;
    order.forEach(function (x, k) { x.x = Math.round(pos[k]); x.cx = x.x + EW / 2; });
    // Where each line leaves its node: spread along the bottom, in the order of the boxes they go to.
    sources.forEach(function (s) {
      var mine = [];
      order.forEach(function (x) { x.uses.forEach(function (u) { if (u.src === s) mine.push(u); }); });
      var m = mine.length;
      var step = s.proxy ? 14 : m > 1 ? Math.min(12, (s.w - 30) / (m - 1)) : 0;
      mine.forEach(function (u, k) { u.sx = round1(s.proxy ? s.cx + k * step : s.cx + (k - (m - 1) / 2) * step); u.sy = s.y; });
    });
    var bends = [];
    order.forEach(function (x) {
      var k = x.uses.length;
      x.uses.sort(function (p, q) { return p.sx - q.sx; });
      var step = k > 1 ? Math.min(16, (EW - 24) / (k - 1)) : 0;
      x.uses.forEach(function (u, n) {
        u.ex = round1(x.cx + (n - (k - 1) / 2) * step);
        // One line into a box that is under its node goes straight down.
        if (k === 1 && u.sx >= x.x + 12 && u.sx <= x.x + EW - 12) u.ex = u.sx;
        u.straight = Math.abs(u.ex - u.sx) < 0.5;
        if (!u.straight) bends.push(u);
      });
    });
    var lanes = [];
    bends.sort(function (p, q) { return Math.abs(p.ex - p.sx) - Math.abs(q.ex - q.sx); }).forEach(function (u) {
      var lo = Math.min(u.sx, u.ex) - 4;
      var hi = Math.max(u.sx, u.ex) + 4;
      var l = 0;
      while (l < lanes.length && lanes[l].some(function (t) { return lo < t[1] && hi > t[0]; })) l++;
      (lanes[l] = lanes[l] || []).push([lo, hi]);
      u.lane = l;
    });
    var top = bottom + (lanes.length ? 16 + BUS_STEP * (lanes.length - 1) + 22 : 40);
    order.forEach(function (x) {
      seen[x.node.id] = (seen[x.node.id] || 0) + 1;
      var id = seen[x.node.id] === 1 ? x.node.id : x.node.id + '#' + seen[x.node.id];
      x.uses.forEach(function (u) {
        var by = bottom + 16 + BUS_STEP * (u.lane || 0);
        var pts = u.straight ? [[u.sx, u.sy], [u.sx, top]] : [[u.sx, u.sy], [u.sx, by], [u.ex, by], [u.ex, top]];
        out.edges.push({ from: u.e.from, to: id, kind: 'upstream', down: u.e.down, report: u.e.report, ticks: upstreamTicks(u.e.report, pts), d: rpath(pts, 8), pts: pts, turns: !u.straight });
      });
      out.nodes.push(nodeOut(x.node, x.x, top, EW, EXT_H, id));
    });
    return { bottom: top + EXT_H };
  }

  // The whole map: a frame per proxy, stacked, then the nodes behind no proxy. Returns
  // {mode: 'focus', reason} when it does not fit.
  function frameLayout(model, W) {
    var byId = index(model);
    var links = model.edges.filter(isLink);
    var out = { width: W, height: 0, mode: 'frame', reason: null, nodes: [], edges: [], texts: [], pills: [], selected: null, linksHidden: false };
    var linkEdges = [];
    var seen = Object.create(null);
    var drawn = 0;
    var y = PAD;
    var groups = groupsOf(model);
    for (var g = 0; g < groups.length; g++) {
      var grp = groups[g];
      var mem = grp.members;
      var n = mem.length;
      if (n > MAX_ROW_NODES) return { mode: 'focus', reason: 'crowded' };
      var row = planRow(mem, links);
      if (row.lanes > MAX_LANES) return { mode: 'focus', reason: 'lanes' };
      var framed = grp.proxy !== null;
      var inset = framed ? FRAME_INSET : 0;
      var rowW = W - 2 * PAD - 2 * inset;
      var w = n ? Math.min(MAX_BOX_W, Math.floor((rowW - (n - 1) * MIN_GAP) / n)) : 0;
      if (n && w < MIN_BOX_W) return { mode: 'focus', reason: 'fit' };
      var gap = n > 1 ? Math.min(MAX_GAP, Math.floor((rowW - n * w) / (n - 1))) : 0;
      var total = n * w + Math.max(0, n - 1) * gap;
      var x0 = Math.round(PAD + inset + (rowW - total) / 2);
      var xs = mem.map(function (m, i) { return x0 + i * (w + gap); });
      var laneH = row.lanes ? LANE_BASE + LANE_STEP * (row.lanes - 1) + 10 : 0;
      var top = y;
      // Under frames, the row of nodes behind no proxy says so, so it is not read as part of the frame above.
      var loose = !framed && groups.length > 1;
      if (loose) out.texts.push({ text: 'Behind no proxy', x: PAD, y: top + 12, cls: 'nm-head', anchor: 'start' });
      var ny = top + (framed ? HEADER_H : 0) + (loose ? LOOSE_HEAD : 0) + laneH;
      var bottom = framed ? (n ? ny + BOX_H + FRAME_FOOT : top + HEADER_H - 6) : ny + BOX_H;
      if (framed) {
        var inside = Object.create(null);
        mem.forEach(function (m) { inside[m.id] = true; });
        var elsewhere = model.edges.filter(function (e) { return e.kind === 'proxy' && e.from === grp.proxy.id && !inside[e.to] && byId[e.to].kind === 'node'; }).length;
        out.nodes.push(frameNode(grp.proxy, top, W, bottom - top, n, elsewhere));
      }
      mem.forEach(function (m, i) { out.nodes.push(nodeOut(m, xs[i], ny, w, BOX_H)); });
      row.near.forEach(function (r) {
        var ltr = r.ia < r.ib;
        var x1 = ltr ? xs[r.ia] + w : xs[r.ia];
        var x2 = ltr ? xs[r.ib] : xs[r.ib] + w;
        var yy = ny + BOX_H / 2;
        var pts = [[x1, yy], [x2, yy]];
        linkEdges.push(linkOut(r.e, r.a, pts, rpath(pts, 0), [(x1 + x2) / 2, yy, 0], framed));
      });
      ports(row, xs, w);
      // The highest lanes first, so a lower arc is drawn over a higher one where they cross.
      row.skips.slice().sort(function (p, q) { return q.lane - p.lane; }).forEach(function (r) {
        var ly = ny - LANE_BASE - LANE_STEP * r.lane;
        var pts = [[r.xa, ny], [r.xa, ly], [r.xb, ly], [r.xb, ny]];
        var e = linkOut(r.e, r.a, pts, rpath(pts, 10), [(r.xa + r.xb) / 2, ly, 0], framed);
        e.lane = r.lane;
        linkEdges.push(e);
      });
      drawn += row.near.length + row.skips.length;
      var sources = mem.map(function (m, i) { return { id: m.id, cx: xs[i] + w / 2, y: ny + BOX_H, w: w, proxy: false }; });
      if (framed) sources.unshift({ id: grp.proxy.id, cx: PAD + 40, y: bottom, w: 0, proxy: true });
      var placed = placeExternals(model, byId, sources, bottom, n ? w : Math.min(MAX_BOX_W, W - 2 * PAD), W, seen, out);
      if (!placed) return { mode: 'focus', reason: 'fit' };
      y = placed.bottom + GROUP_GAP;
    }
    out.edges = out.edges.concat(linkEdges);
    out.height = Math.round(y - GROUP_GAP + PAD);
    out.linksHidden = drawn < links.length;
    return out;
  }

  // The nodes that can be picked in the one-node view: the nodes, or the proxies when there are none.
  // At most MAX_PILLS; "Show as list" has every node.
  function focusChoices(model) {
    var nodes = model.nodes.filter(function (n) { return n.kind === 'node'; });
    return (nodes.length ? nodes : model.nodes.filter(function (n) { return n.kind === 'proxy'; })).slice(0, MAX_PILLS);
  }

  // The buttons of the one-node view. Two nodes with the same name are told apart by the proxy they
  // are behind, or by their address when that does not tell them apart either.
  function pillsOf(model) {
    var choices = focusChoices(model);
    var byId = index(model);
    var count = Object.create(null);
    choices.forEach(function (n) { count[n.name] = (count[n.name] || 0) + 1; });
    var behind = Object.create(null);
    model.edges.forEach(function (e) { if (e.kind === 'proxy' && !behind[e.to]) behind[e.to] = byId[e.from].name; });
    var hint = choices.map(function (n) { return count[n.name] > 1 ? behind[n.id] || n.addr || '' : ''; });
    var seen = Object.create(null);
    choices.forEach(function (n, i) { var k = n.name + '|' + hint[i]; seen[k] = (seen[k] || 0) + 1; });
    return choices.map(function (n, i) {
      var h = hint[i] && seen[n.name + '|' + hint[i]] > 1 ? n.addr : hint[i];
      return { id: n.id, name: h ? clip(n.name, 24) + ' (' + clip(h, 24) + ')' : clip(n.name, 32), state: n.state };
    });
  }

  // The node to show: the one asked for while it is still there, else the first node with links
  // between nodes, else the first node. Null when there is nothing to pick.
  function pickFocus(model, want) {
    var choices = focusChoices(model);
    if (!choices.length) return null;
    if (typeof want === 'string' && choices.some(function (n) { return n.id === want; })) return want;
    var linked = Object.create(null);
    model.edges.forEach(function (e) { if (e.kind === 'link') { linked[e.from] = true; linked[e.to] = true; } });
    var first = choices.filter(function (n) { return linked[n.id]; })[0];
    return (first || choices[0]).id;
  }

  // One node and its neighbours: the proxies that pass visitors to it, the nodes that dial it (and
  // those linked in a direction not known), the nodes it dials (and those it dials both ways) and its
  // external peers, each in page order. Null for an id that is not on the map.
  function focusModel(model, id) {
    var byId = index(model);
    var n = byId[id];
    if (!n) return null;
    var order = Object.create(null);
    model.nodes.forEach(function (m, i) { order[m.id] = i; });
    var out = { node: n, proxies: [], dialledBy: [], dials: [], externals: [] };
    model.edges.forEach(function (e) {
      if (e.kind === 'proxy' && e.to === id && byId[e.from]) out.proxies.push(byId[e.from]);
      else if (e.kind === 'upstream' && e.from === id && byId[e.to]) out.externals.push({ node: byId[e.to], edge: e });
      else if (e.kind === 'link' && (e.from === id || e.to === id)) {
        var it = { node: byId[e.from === id ? e.to : e.from], edge: e };
        if (e.dir === 'dials' && (e.mutual || e.from === id)) out.dials.push(it);
        else out.dialledBy.push(it);
      }
    });
    var by = function (p, q) { return order[p.node.id] - order[q.node.id]; };
    out.dialledBy.sort(by);
    out.dials.sort(by);
    return out;
  }

  // The lines of the node in the middle of the one-node view: larger, with all its facts.
  function focusLines(n, w, h) {
    var lines = [];
    var row1 = [];
    if (n.clients !== null) row1.push(plural(num(n.clients), 'client', 'clients'));
    if (n.kind !== 'external' && n.state === 'up' && n.ms !== null) row1.push('connect time ' + n.ms + ' ms');
    var texts = [];
    if (row1.length) texts.push(row1.join(' · '));
    if (n.uptime !== null) texts.push('uptime ' + n.uptime + '% over 90 days');
    var max = Math.max(4, Math.floor((w - 16) / CHAR_W));
    var addr = addressOf(n);
    if (addr) texts.push(addr);
    var top = (h - (44 + texts.length * 18)) / 2 + 16;
    lines.push({ text: clip(n.name, Math.max(4, Math.floor((w - 16) / 9))), x: w / 2, y: round1(top), cls: 'nm-name big', anchor: 'middle' });
    lines.push({ text: GLYPH[n.state] + ' ' + WORD[n.state], x: w / 2, y: round1(top + 22), cls: 'nm-state', anchor: 'middle' });
    texts.forEach(function (t, i) { lines.push({ text: clip(t, max), x: w / 2, y: round1(top + 44 + i * 18), cls: addr && i === texts.length - 1 ? 'nm-addr' : 'nm-fact', anchor: 'middle' }); });
    return lines;
  }

  function spread(i, count, room, most) { return count > 1 ? (i - (count - 1) / 2) * Math.min(most, room / (count - 1)) : 0; }

  function columnH(list) {
    return list.reduce(function (a, it) { return a + boxH(it.node); }, 0) + Math.max(0, list.length - 1) * 20;
  }

  // The one-node view: the picked node in the middle, the proxy above it, the nodes that dial it on the
  // left and those it dials on the right (on a phone both under it), and its external peers below.
  function focusLayout(model, W, want, reason) {
    var sel = pickFocus(model, want);
    var out = {
      width: W, height: 2 * PAD, mode: 'focus', reason: reason, nodes: [], edges: [], texts: [], selected: sel, linksHidden: false,
      pills: pillsOf(model)
    };
    var fm = sel === null ? null : focusModel(model, sel);
    if (!fm) return out;
    var nodes = out.nodes;
    var edges = out.edges;
    function text(t, x, y, cls, anchor) { out.texts.push({ text: t, x: round1(x), y: round1(y), cls: cls, anchor: anchor || 'start' }); }
    function more(all, shown, x, y, anchor) {
      if (all.length > shown.length) text('and ' + (all.length - shown.length) + ' more, see the list', x, y, 'nm-label', anchor);
    }
    function heading(list) {
      var unknown = list.filter(function (it) { return it.edge.dir === 'unknown'; }).length;
      return unknown === 0 ? 'Dialled by' : unknown === list.length ? 'Linked with' : 'Dialled by or linked with';
    }
    var phone = W < FOCUS_BELOW;
    var cx = Math.round(W / 2);
    var FW = phone ? Math.min(360, W - 2 * PAD - 40) : Math.min(FOCUS_W, W - 2 * PAD);
    var fx = Math.round(cx - FW / 2);
    var y = PAD;
    var proxies = fm.proxies.slice(0, phone ? 2 : MAX_PROXIES);
    var pFeet = [];
    if (proxies.length) {
      var k = proxies.length;
      var pw = Math.min(phone ? 180 : 200, Math.floor((W - 2 * PAD - (k - 1) * 12) / k));
      var px0 = Math.round(cx - (k * pw + (k - 1) * 12) / 2);
      proxies.forEach(function (p, i) {
        var x = px0 + i * (pw + 12);
        nodes.push(nodeOut(p, x, y, pw, PROXY_H));
        pFeet.push({ p: p, x: x + pw / 2 });
      });
      y += PROXY_H + 48;
    }
    var pBottom = y - 48;
    var inn = fm.dialledBy.slice(0, phone ? PHONE_SIDE : MAX_SIDE);
    var outs = fm.dials.slice(0, phone ? PHONE_SIDE : MAX_SIDE);
    var hasExt = fm.externals.length > 0;
    var trunk = cx;
    var fy;
    var end;
    if (!phone) {
      var hasCols = inn.length + outs.length > 0;
      var top = y + (hasCols ? 24 : 0);
      var hL = columnH(inn);
      var hR = columnH(outs);
      var span = Math.max(FOCUS_H, hL, hR);
      fy = Math.round(top + (span - FOCUS_H) / 2);
      var SW = Math.max(96, Math.min(MAX_BOX_W, Math.floor((W - 2 * PAD - FW) / 2 - 60)));
      var sideGap = Math.min(160, fx - PAD - SW);
      var lx = fx - sideGap - SW;
      var rx = fx + FW + sideGap;
      var yl = Math.round(top + (span - hL) / 2);
      inn.forEach(function (it, i) {
        var h = boxH(it.node);
        nodes.push(nodeOut(it.node, lx, yl, SW, h));
        var a = [lx + SW, yl + h / 2];
        var b = [fx, fy + FOCUS_H / 2 + spread(i, inn.length, FOCUS_H - 24, 24)];
        edges.push(linkOut(it.edge, it.node.id, [a, b], curve(a, b), [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2, Math.atan2(b[1] - a[1], b[0] - a[0])], false));
        yl += h + 20;
      });
      var yr = Math.round(top + (span - hR) / 2);
      outs.forEach(function (it, i) {
        var h = boxH(it.node);
        nodes.push(nodeOut(it.node, rx, yr, SW, h));
        var a = [fx + FW, fy + FOCUS_H / 2 + spread(i, outs.length, FOCUS_H - 24, 24)];
        var b = [rx, yr + h / 2];
        edges.push(linkOut(it.edge, sel, [a, b], curve(a, b), [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2, Math.atan2(b[1] - a[1], b[0] - a[0])], false));
        yr += h + 20;
      });
      if (inn.length) text(heading(inn), lx, top - 10, 'nm-head');
      if (outs.length) text('Dials', rx + SW, top - 10, 'nm-head', 'end');
      var extra = fm.dialledBy.length > inn.length || fm.dials.length > outs.length;
      more(fm.dialledBy, inn, lx, top + span + 16);
      more(fm.dials, outs, rx + SW, top + span + 16, 'end');
      end = top + span + (extra ? 22 : 0);
    } else {
      fy = y;
      var fBottom = fy + FOCUS_H;
      end = fBottom;
      var all = inn.length + outs.length;
      var row = null;
      if (all) {
        // One row under the node when it fits: the nodes that dial it, a gap for the line to the
        // external peers, and the nodes it dials.
        var G = 12;
        var CG = hasExt ? 28 : 0;
        var nw = Math.min(110, Math.floor((W - 2 * PAD - CG - Math.max(0, all - 1 - (hasExt && inn.length && outs.length ? 1 : 0)) * G) / all));
        var seq = inn.map(function (it) { return { it: it, out: false }; });
        if (hasExt) seq.push(null);
        outs.forEach(function (it) { seq.push({ it: it, out: true }); });
        var x = 0;
        var prevBox = false;
        var gapAt = null;
        seq.forEach(function (s) {
          if (s === null) { gapAt = x + CG / 2; x += CG; prevBox = false; return; }
          if (prevBox) x += G;
          s.x = x;
          x += nw;
          prevBox = true;
        });
        var start = Math.round(cx - x / 2);
        var inside = function (v) { return v >= fx + 10 && v <= fx + FW - 10; };
        var fits = nw >= 92 && x <= W - 2 * PAD && seq.every(function (s) { return s === null || inside(start + s.x + nw / 2); }) && (gapAt === null || inside(start + gapAt));
        if (fits) row = { seq: seq, start: start, nw: nw, gapAt: gapAt === null ? null : start + gapAt };
      }
      if (row) {
        var rowY = fBottom + 44;
        row.seq.forEach(function (s) {
          if (s === null) return;
          var bx = row.start + s.x;
          var bcx = bx + row.nw / 2;
          nodes.push(nodeOut(s.it.node, bx, rowY, row.nw, BOX_H));
          var pts = s.out ? [[bcx, fBottom], [bcx, rowY]] : [[bcx, rowY], [bcx, fBottom]];
          edges.push(linkOut(s.it.edge, s.out ? sel : s.it.node.id, pts, rpath(pts, 0), [bcx, (fBottom + rowY) / 2, Math.PI / 2], false));
        });
        var ins = row.seq.filter(function (s) { return s && !s.out; });
        var os = row.seq.filter(function (s) { return s && s.out; });
        if (ins.length) text(heading(inn), row.start + ins[0].x, rowY + BOX_H + 16, 'nm-head');
        if (os.length) text('Dials', row.start + os[os.length - 1].x + row.nw, rowY + BOX_H + 16, 'nm-head', 'end');
        if (row.gapAt !== null) trunk = row.gapAt;
        end = rowY + BOX_H + 22;
      } else if (all) {
        // Two columns under the node; each line runs down its own lane between them, so none crosses.
        var need = function (n) { return n ? 10 + 7 * (n - 1) + 8 : 0; };
        var CW = Math.min(150, Math.floor((W - 2 * PAD) / 2 - Math.max(need(inn.length), need(outs.length), 8)));
        var ctop = fBottom + 44;
        var yy = ctop;
        inn.forEach(function (it, r) {
          var h = boxH(it.node);
          nodes.push(nodeOut(it.node, PAD, yy, CW, h));
          var lane = Math.max(fx + 8, PAD + CW + 10 + 7 * r);
          var pts = [[PAD + CW, yy + h / 2], [lane, yy + h / 2], [lane, fBottom]];
          edges.push(linkOut(it.edge, it.node.id, pts, rpath(pts, 8), [lane, (fBottom + yy + h / 2) / 2, Math.PI / 2], false));
          yy += h + 14;
        });
        var yy2 = ctop;
        outs.forEach(function (it, r) {
          var h = boxH(it.node);
          nodes.push(nodeOut(it.node, W - PAD - CW, yy2, CW, h));
          var lane = Math.min(fx + FW - 8, W - PAD - CW - 10 - 7 * r);
          var pts = [[lane, fBottom], [lane, yy2 + h / 2], [W - PAD - CW, yy2 + h / 2]];
          edges.push(linkOut(it.edge, sel, pts, rpath(pts, 8), [lane, (fBottom + yy2 + h / 2) / 2, Math.PI / 2], false));
          yy2 += h + 14;
        });
        if (inn.length) text(heading(inn), PAD, ctop - 8, 'nm-head');
        if (outs.length) text('Dials', W - PAD, ctop - 8, 'nm-head', 'end');
        var colEnd = Math.max(yy, yy2) - 14;
        var extra2 = fm.dialledBy.length > inn.length || fm.dials.length > outs.length;
        more(fm.dialledBy, inn, PAD, colEnd + 16);
        more(fm.dials, outs, W - PAD, colEnd + 16, 'end');
        end = colEnd + (extra2 ? 22 : 0);
      }
    }
    nodes.push(Object.assign(nodeOut(fm.node, fx, fy, FW, FOCUS_H), { lines: focusLines(fm.node, FW, FOCUS_H), focus: true }));
    pFeet.forEach(function (f, i) {
      var tx = round1(cx + spread(i, pFeet.length, FW - 40, 40));
      var pts = Math.abs(f.x - tx) < 0.5 ? [[tx, pBottom], [tx, fy]] : [[f.x, pBottom], [f.x, pBottom + 16], [tx, pBottom + 16], [tx, fy]];
      edges.push({ from: f.p.id, to: sel, kind: 'proxy', down: f.p.state === 'down' || fm.node.state === 'down', d: rpath(pts, 8), pts: pts });
    });
    // The words sit right of every line down from the proxies, or left of them, so no line runs
    // through them; on a screen too narrow for either they are left out (the legend says it).
    if (pFeet.length) {
      var lineXs = [];
      // Only the last leg of each line, straight down into the node, is beside the words.
      edges.forEach(function (e) { if (e.kind === 'proxy') lineXs.push(e.pts[e.pts.length - 1][0]); });
      var words = 'passes visitors to';
      var wordsW = words.length * CHAR_W;
      var right = Math.max.apply(null, lineXs) + 10;
      var left = Math.min.apply(null, lineXs) - 10;
      if (right + wordsW <= W - PAD) text(words, right, pBottom + 28, 'nm-label');
      else if (left - wordsW >= PAD) text(words, left, pBottom + 28, 'nm-label', 'end');
    }
    var exts = fm.externals.slice(0, MAX_EXTERNALS);
    if (exts.length) {
      var etop = end + 44;
      var fb = fy + FOCUS_H;
      text('connects out to', trunk + 10, etop - 18, 'nm-label');
      var k2 = exts.length;
      var EW = Math.min(phone ? 140 : 200, Math.floor((W - 2 * PAD - (k2 - 1) * EXT_GAP) / k2));
      if (EW >= (phone ? 92 : 120)) {
        var totalE = k2 * EW + (k2 - 1) * EXT_GAP;
        var ex0 = Math.round(Math.max(PAD, Math.min(W - PAD - totalE, trunk - totalE / 2)));
        exts.forEach(function (x, i) {
          var ex = ex0 + i * (EW + EXT_GAP);
          var ecx = ex + EW / 2;
          if (k2 === 1 && trunk >= ex + 12 && trunk <= ex + EW - 12) ecx = trunk;
          var pts = Math.abs(ecx - trunk) < 0.5 ? [[trunk, fb], [trunk, etop]] : [[trunk, fb], [trunk, etop - 10], [ecx, etop - 10], [ecx, etop]];
          edges.push({ from: sel, to: x.node.id, kind: 'upstream', down: x.edge.down, report: x.edge.report, ticks: upstreamTicks(x.edge.report, pts), d: rpath(pts, 8), pts: pts });
          nodes.push(nodeOut(seenBy(x.node, sel, x.edge.report), ex, etop, EW, EXT_H, x.node.id));
        });
        end = etop + EXT_H;
      } else {
        // Too many for one row: two columns, joined to a line down the middle.
        trunk = cx;
        var EW2 = Math.min(160, Math.floor((W - 2 * PAD) / 2 - 14));
        exts.forEach(function (x, i) {
          var ey = etop + (i >> 1) * (EXT_H + 12);
          var left = i % 2 === 0;
          var ex = left ? trunk - 12 - EW2 : trunk + 12;
          var pts = [[trunk, fb], [trunk, ey + EXT_H / 2], [left ? ex + EW2 : ex, ey + EXT_H / 2]];
          edges.push({ from: sel, to: x.node.id, kind: 'upstream', down: x.edge.down, report: x.edge.report, ticks: upstreamTicks(x.edge.report, pts), d: rpath(pts, 8), pts: pts });
          nodes.push(nodeOut(seenBy(x.node, sel, x.edge.report), ex, ey, EW2, EXT_H, x.node.id));
        });
        end = etop + Math.ceil(k2 / 2) * (EXT_H + 12) - 12;
      }
    }
    out.height = Math.round(end + PAD);
    return out;
  }

  // Places the model in width pixels. Returns {width, height, mode: 'frame' | 'focus', reason, nodes,
  // edges, texts, pills, selected, linksHidden}; nodes carry x, y, w, h and their lines of text, edges
  // a path. want is the node to show in the one-node view, when it is still there.
  function layout(model, width, want) {
    var W = Math.max(MIN_WIDTH, Math.floor(Number(width) || 0));
    if (W < FOCUS_BELOW) return focusLayout(model, W, want, 'narrow');
    var f = frameLayout(model, W);
    return f.mode === 'frame' ? f : focusLayout(model, W, want, f.reason);
  }

  // The map as a list for screen readers: each node in words and what it connects to.
  function listItems(model) {
    var name = Object.create(null);
    model.nodes.forEach(function (n) { name[n.id] = n.name; });
    return model.nodes.map(function (n) {
      var to = model.edges.filter(function (e) { return e.kind !== 'link' && e.from === n.id; }).map(function (e) { return name[e.to]; });
      return describe(n) + (to.length ? ' Connects to ' + to.join(', ') + '.' : '');
    });
  }

  if (typeof document === 'undefined') {
    // Loaded by the tests: expose the pure parts only.
    globalThis.netmapLogic = {
      buildModel: buildModel, layout: layout, describe: describe, summaryText: summaryText, listItems: listItems, wrap: wrap, clip: clip,
      planRow: planRow, groupsOf: groupsOf, focusModel: focusModel, pickFocus: pickFocus, rpath: rpath,
      limits: { FOCUS_BELOW: FOCUS_BELOW, MAX_ROW_NODES: MAX_ROW_NODES, MAX_LANES: MAX_LANES }
    };
    return;
  }

  var SVG = 'http://www.w3.org/2000/svg';
  var section = document.getElementById('netmap');
  if (!section) return;
  var holder = document.getElementById('netmap-chart');
  var listEl = document.getElementById('netmap-list');
  var summary = document.getElementById('netmap-summary');
  var legend = document.getElementById('netmap-legend-links');
  var phoneNote = document.getElementById('netmap-phone-note');
  var hostsNow = null;
  var drawn = '';
  // The node picked in the one-node view, set only by the visitor; kept over the refreshes of the
  // page, so a node that is missing from one refresh is shown again when it comes back.
  var picked = null;

  function el(name, attrs, parent) {
    var e = document.createElementNS(SVG, name);
    for (var k in attrs) if (Object.prototype.hasOwnProperty.call(attrs, k)) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }

  // The marks at the ends of node links, in <defs> and styled by class: a filled arrowhead, an open
  // one (declared), a bar (turned off), a dot (the node that dials) and a ring (direction not known).
  // Each exists in the colour of a link that has a node down, and with the fill of a frame.
  function addMarkers(svg) {
    var defs = el('defs', {}, svg);
    function marker(id, w, h, rx, ry, make) {
      make(el('marker', { id: id, markerUnits: 'userSpaceOnUse', markerWidth: w, markerHeight: h, refX: rx, refY: ry, orient: 'auto-start-reverse', overflow: 'visible' }, defs));
    }
    ['', '-dn', '-f', '-dn-f'].forEach(function (sfx) {
      var dn = sfx.indexOf('-dn') === 0 ? ' dn' : '';
      var fr = sfx.slice(-2) === '-f' ? ' fr' : '';
      var c = 'nm-mk-fill' + dn;
      var o = 'nm-mk-open' + dn + fr;
      var b = 'nm-mk-bar' + dn;
      marker('nm-arrow' + sfx, 12, 12, 11, 6, function (m) { el('path', { d: 'M0 0 L11 6 L0 12 Z', 'class': c }, m); });
      marker('nm-open' + sfx, 12, 12, 11, 6, function (m) { el('path', { d: 'M1 1 L11 6 L1 11 Z', 'class': o }, m); });
      marker('nm-bar' + sfx, 8, 16, 6, 8, function (m) { el('path', { d: 'M3 0 L3 16', 'class': b }, m); });
      marker('nm-dot' + sfx, 8, 8, 4, 4, function (m) { el('circle', { cx: 4, cy: 4, r: 4, 'class': c }, m); });
      marker('nm-ring' + sfx, 9, 9, 4.5, 4.5, function (m) { el('circle', { cx: 4.5, cy: 4.5, r: 3.5, 'class': o }, m); });
    });
  }

  // One link between nodes: a halo so it reads as passing over other lines, the line (outlined when
  // the operator declared it), its marks and, when a node is down, two slashes.
  function drawLink(e, parent) {
    var sfx = (e.down ? '-dn' : '') + (e.inFrame ? '-f' : '');
    var g = el('g', { 'class': 'nm-link' + (e.down ? ' down' : '') + (e.inFrame ? ' in-frame' : ''), 'data-from': e.from, 'data-to': e.to }, parent);
    el('path', { 'class': 'nm-halo' + (e.declared ? ' wide' : ''), d: e.d, fill: 'none' }, g);
    if (e.declared) el('path', { 'class': 'nm-edge link outer' + (e.down ? ' down' : ''), d: e.d, fill: 'none' }, g);
    el('path', {
      'class': 'nm-edge link' + (e.declared ? ' inner' : '') + (e.off ? ' off' : '') + (e.down ? ' down' : ''), d: e.d, fill: 'none',
      'marker-start': 'url(#nm-' + e.start + sfx + ')', 'marker-end': 'url(#nm-' + e.end + sfx + ')'
    }, g);
    e.ticks.forEach(function (t) {
      el('path', { 'class': 'nm-tick-halo', d: t }, g);
      el('path', { 'class': 'nm-tick', d: t }, g);
    });
    return g;
  }

  // While a node is hovered or focused, the links that end at it are drawn thicker and the others fade.
  function highlight(svg, edges, groups) {
    var nodeEls = svg.querySelectorAll('.nm-node');
    function on(id) {
      var mine = groups.filter(function (g) { return g.getAttribute('data-from') === id || g.getAttribute('data-to') === id; });
      // A node with no links fades nothing.
      if (!mine.length) return;
      edges.classList.add('has-hot');
      mine.forEach(function (g) { g.classList.add('hot'); });
    }
    function off() {
      edges.classList.remove('has-hot');
      groups.forEach(function (g) { g.classList.remove('hot'); });
    }
    for (var i = 0; i < nodeEls.length; i++) {
      (function (ne) {
        var id = ne.getAttribute('data-id');
        ne.addEventListener('mouseenter', function () { on(id); });
        ne.addEventListener('focus', function () { on(id); });
        ne.addEventListener('mouseleave', off);
        ne.addEventListener('blur', off);
      })(nodeEls[i]);
    }
  }

  function drawNode(n, parent) {
    var cls = 'nm-node ' + n.kind + ' ' + n.state + (n.report ? ' rep-' + n.report : '') + (n.frame ? ' frame' : '') + (n.focus ? ' focus' : '');
    var g = el('g', { 'class': cls, tabindex: '0', role: 'img', 'aria-label': n.label, 'data-id': n.id, transform: 'translate(' + n.x + ' ' + n.y + ')' }, parent);
    el('title', {}, g).textContent = n.label;
    var r = n.frame ? 14 : 10;
    el('rect', { 'class': 'nm-box', width: n.w, height: n.h, rx: r, ry: r }, g);
    // The double border of a proxy: a second, thinner line inside the first.
    if (n.kind === 'proxy') {
      var inset = n.frame ? 6 : 5;
      el('rect', { 'class': 'nm-box-inner', x: inset, y: inset, width: n.w - 2 * inset, height: n.h - 2 * inset, rx: r - 4, ry: r - 4 }, g);
    }
    n.lines.forEach(function (l) {
      el('text', { 'class': l.cls, x: l.x, y: l.y, 'text-anchor': l.anchor }, g).textContent = l.text;
    });
    return g;
  }

  function pick(id) {
    picked = id;
    drawn = '';
    render(true);
  }

  // The row of buttons of the one-node view, a tab list: arrow keys, Home and End move along it.
  function pills(lay) {
    var list = document.createElement('div');
    list.setAttribute('class', 'nm-pills');
    list.setAttribute('role', 'tablist');
    list.setAttribute('aria-label', 'Pick a node to show its links');
    var ids = lay.pills.map(function (p) { return p.id; });
    lay.pills.forEach(function (p, i) {
      var on = p.id === lay.selected;
      var b = document.createElement('button');
      b.setAttribute('type', 'button');
      b.setAttribute('class', 'nm-pill');
      b.setAttribute('role', 'tab');
      b.setAttribute('id', 'nm-tab-' + i);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
      b.setAttribute('aria-controls', 'nm-focus');
      b.setAttribute('tabindex', on ? '0' : '-1');
      b.setAttribute('data-id', p.id);
      var mark = document.createElement('span');
      mark.setAttribute('class', 'nm-pill-mark ' + p.state);
      mark.setAttribute('aria-hidden', 'true');
      mark.textContent = GLYPH[p.state] || '?';
      b.appendChild(mark);
      var name = document.createElement('span');
      name.textContent = p.name;
      b.appendChild(name);
      var state = document.createElement('span');
      state.setAttribute('class', 'sr-only');
      state.textContent = ', ' + (WORD[p.state] || 'Unknown').toLowerCase();
      b.appendChild(state);
      b.addEventListener('click', function () { pick(p.id); });
      b.addEventListener('keydown', function (ev) {
        // A key with a modifier is the browser's or the screen reader's, not ours.
        if (!ev || ev.altKey || ev.ctrlKey || ev.metaKey || ev.shiftKey) return;
        var to = ev.key === 'ArrowRight' || ev.key === 'ArrowDown' ? (i + 1) % ids.length
          : ev.key === 'ArrowLeft' || ev.key === 'ArrowUp' ? (i - 1 + ids.length) % ids.length
            : ev.key === 'Home' ? 0 : ev.key === 'End' ? ids.length - 1 : -1;
        if (to < 0) return;
        ev.preventDefault();
        pick(ids[to]);
      });
      list.appendChild(b);
    });
    return list;
  }

  function draw() { render(false); }

  // Draws the map; focusPick puts the focus on the button of the node shown (after a pick).
  function render(focusPick) {
    if (!hostsNow) return;
    var model;
    var lay;
    var items;
    try {
      model = buildModel(hostsNow);
      section.hidden = model.empty;
      if (model.empty) return;
      var width = holder.clientWidth || 0;
      // Closed or not laid out yet: drawn when it opens or gets a width.
      if (width <= 0) return;
      lay = layout(model, width, picked);
      items = listItems(model);
    } catch (err) {
      // The last guard: data the checks above missed leaves the map as it was drawn last.
      if (typeof console !== 'undefined') console.error('Network map:', err);
      return;
    }
    var sig = JSON.stringify([lay, items]);
    if (sig === drawn) return;
    drawn = sig;
    var active = document.activeElement;
    var focusId = active && holder.contains(active) ? active.getAttribute('data-id') : null;
    var focusPill = focusPick || (active && holder.contains(active) && active.getAttribute('role') === 'tab');
    var focus = lay.mode === 'focus';
    var tab = focus ? lay.pills.map(function (p) { return p.id; }).indexOf(lay.selected) : -1;
    var attrs = { 'class': 'nm-svg', viewBox: '0 0 ' + lay.width + ' ' + lay.height, width: lay.width, height: lay.height, role: 'group', 'aria-label': 'Backbone network map' };
    if (focus && lay.pills.length > 1) {
      attrs.id = 'nm-focus';
      attrs.role = 'tabpanel';
      attrs['aria-labelledby'] = 'nm-tab-' + tab;
      delete attrs['aria-label'];
    }
    var svg = el('svg', attrs);
    lay.nodes.forEach(function (n) { if (n.frame) drawNode(n, svg); });
    var edges = el('g', { 'class': 'nm-edges', 'aria-hidden': 'true' }, svg);
    var hasLinks = lay.edges.some(function (e) { return e.kind === 'link'; });
    if (hasLinks) addMarkers(svg);
    lay.edges.forEach(function (e) {
      if (e.kind === 'link') return;
      if (e.turns) el('path', { 'class': 'nm-stub-halo', d: e.d, fill: 'none' }, edges);
      el('path', { 'class': 'nm-edge ' + e.kind + (e.down ? ' down' : ''), d: e.d, fill: 'none' }, edges);
      (e.ticks || []).forEach(function (t) {
        el('path', { 'class': 'nm-tick-halo', d: t }, edges);
        el('path', { 'class': 'nm-tick', d: t }, edges);
      });
    });
    var linkGroups = [];
    lay.edges.forEach(function (e) {
      if (e.kind === 'link') linkGroups.push(drawLink(e, edges));
    });
    if (lay.texts.length) {
      var labels = el('g', { 'class': 'nm-labels', 'aria-hidden': 'true' }, svg);
      lay.texts.forEach(function (t) { el('text', { 'class': t.cls, x: t.x, y: t.y, 'text-anchor': t.anchor }, labels).textContent = t.text; });
    }
    lay.nodes.forEach(function (n) { if (!n.frame) drawNode(n, svg); });
    if (linkGroups.length) highlight(svg, edges, linkGroups);
    if (focus && lay.pills.length > 1) holder.replaceChildren(pills(lay), svg);
    else holder.replaceChildren(svg);
    var lis = items.map(function (t) {
      var li = document.createElement('li');
      li.textContent = t;
      return li;
    });
    listEl.replaceChildren.apply(listEl, lis);
    if (focusPill && focus && lay.pills.length > 1) {
      var tabs = holder.querySelectorAll('.nm-pill');
      for (var j = 0; j < tabs.length; j++) {
        if (tabs[j].getAttribute('data-id') === lay.selected) { tabs[j].focus(); break; }
      }
    } else if (focusId) {
      var again = holder.querySelectorAll('.nm-node');
      for (var i = 0; i < again.length; i++) {
        if (again[i].getAttribute('data-id') === focusId) { again[i].focus(); break; }
      }
    }
    summary.textContent = summaryText(model);
    if (legend) legend.hidden = !model.edges.some(function (e) { return e.kind === 'link'; });
    if (phoneNote) phoneNote.hidden = !lay.linksHidden;
  }

  // The page hands over each fresh /api/status here. Whether the section is open stays as the
  // visitor left it, because the same element is kept; the node picked in the one-node view is kept
  // until the page is reloaded.
  globalThis.netmapView = {
    update: function (hosts) { hostsNow = hosts; draw(); }
  };
  section.addEventListener('toggle', draw);
  if (typeof ResizeObserver === 'function') new ResizeObserver(draw).observe(holder);
  else window.addEventListener('resize', draw);
})();
