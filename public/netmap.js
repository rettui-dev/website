// The backbone map on the status page: the proxy, the nodes behind it and the external peers they
// connect out to, drawn as inline SVG from the data of /api/status. The layout is pure (see
// netmapLogic, used by the tests); the drawing sets text with textContent only.
(function () {
  var WORD = { up: 'Up', down: 'Down', unknown: 'Unknown', external: 'External' };
  var GLYPH = { up: '●', down: '✕', unknown: '?', external: '↗' };
  var BOX_H = 76;
  var MAX_BOX_W = 176;
  var MIN_BOX_W = 90;
  var PAD = 8;
  var GAP_X = 8;
  var GAP_Y = 14;
  var TIER_GAP = 46;
  var COLUMN_GAP = 48;
  var LINE_H = 15;
  var CHAR_W = 6.8;
  var MIN_WIDTH = 280;

  function hostKey(h) { return h.host + ':' + h.port; }
  function displayName(h) { return h.name || hostKey(h); }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }

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
    return typeof c === 'number' ? c : null;
  }

  // The nodes and links of the map. Returns {nodes, edges, empty}; empty is true when there is
  // nothing to draw beyond plain nodes (no proxy and no upstream).
  function buildModel(hosts) {
    var list = Array.isArray(hosts) ? hosts : [];
    var hasProxy = list.some(function (h) { return h.role === 'proxy'; });
    var nodes = [];
    var edges = [];
    var byId = {};
    var externals = 0;
    list.forEach(function (h) {
      var tier = h.role === 'proxy' ? 0 : (h.proxiedBy || hasProxy) ? 1 : 0;
      var n = {
        id: hostKey(h), kind: h.role === 'proxy' ? 'proxy' : 'node', name: displayName(h), state: h.status || 'unknown', tier: tier,
        clients: h.status === 'down' ? null : clients(h), ms: h.latencyMs === undefined ? null : h.latencyMs,
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
      (Array.isArray(h.upstreams) ? h.upstreams : []).forEach(function (u) {
        // The same peer listed by two nodes is one box.
        var id = 'ext:' + String(u.name).toLowerCase() + '|' + (u.address || '');
        if (!byId[id]) {
          byId[id] = { id: id, kind: 'external', name: String(u.name), state: 'external', tier: -1, clients: null, ms: null, uptime: null, members: 0, address: u.address || null, usedBy: [] };
          nodes.push(byId[id]);
          externals++;
        }
        byId[id].usedBy.push(from.name);
        edges.push({ from: from.id, to: id, kind: 'upstream' });
      });
    });
    var last = 0;
    nodes.forEach(function (n) { if (n.kind !== 'external' && n.tier > last) last = n.tier; });
    nodes.forEach(function (n) { if (n.kind === 'external') n.tier = last + 1; });
    var state = {};
    nodes.forEach(function (n) { state[n.id] = n.state; });
    edges.forEach(function (e) { e.down = state[e.from] === 'down' || state[e.to] === 'down'; });
    return { nodes: nodes, edges: edges, empty: !hasProxy && externals === 0 };
  }

  // One node in words, for the title, the accessible name and the list.
  function describe(n) {
    var out = [n.name + ': ' + (n.kind === 'external' ? 'external backbone peer, not monitored' : WORD[n.state].toLowerCase())];
    if (n.kind === 'proxy') out.push('passes visitors to ' + plural(n.members, 'node', 'nodes'));
    if (n.kind === 'external' && n.address) out.push('address ' + n.address + ' (not checked)');
    if (n.kind === 'external' && n.usedBy.length) out.push('used by ' + n.usedBy.join(', '));
    if (n.clients !== null) out.push(plural(n.clients, 'client', 'clients'));
    if (n.kind !== 'external' && n.state === 'up' && n.ms !== null) out.push('connect time ' + n.ms + ' ms');
    if (n.uptime !== null) out.push('uptime ' + n.uptime + '% over 90 days');
    return out.join(', ') + '.';
  }

  // The state and fact lines drawn in a box.
  function facts(n) {
    var out = [GLYPH[n.state] + ' ' + WORD[n.state]];
    if (n.clients !== null) out.push(plural(num(n.clients), 'client', 'clients'));
    else if (n.kind === 'external') out.push('not checked');
    else if (n.state === 'up' && n.ms !== null) out.push(n.ms + ' ms');
    return out;
  }

  // Splits count items over rows of at most perRow, as even as it can.
  function rowsOf(count, perRow) {
    var rows = Math.ceil(count / perRow);
    var size = Math.ceil(count / rows);
    var out = [];
    for (var left = count; left > 0; left -= size) out.push(Math.min(size, left));
    return out;
  }

  // Places the model in width pixels. Wide: one column per tier, left to right. Narrow: one band
  // per tier, top to bottom, wrapping to more rows when a tier has more nodes than fit.
  // Returns {width, height, mode, nodes, edges}; nodes carry x, y, w, h and their text lines,
  // edges a path.
  function layout(model, width) {
    var W = Math.max(MIN_WIDTH, Math.floor(width));
    var tiers = [];
    model.nodes.forEach(function (n) { (tiers[n.tier] = tiers[n.tier] || []).push(n); });
    tiers = tiers.filter(Boolean);
    var T = tiers.length;
    var columns = T * MAX_BOX_W + (T - 1) * COLUMN_GAP + 2 * PAD <= W;
    var pos = {};
    var height;
    var boxW;
    if (columns) {
      boxW = MAX_BOX_W;
      var tall = 0;
      tiers.forEach(function (t) { tall = Math.max(tall, t.length); });
      height = 2 * PAD + tall * BOX_H + (tall - 1) * GAP_Y;
      var gapX = T > 1 ? (W - 2 * PAD - T * boxW) / (T - 1) : 0;
      tiers.forEach(function (t, ti) {
        var top = PAD + (height - 2 * PAD - (t.length * BOX_H + (t.length - 1) * GAP_Y)) / 2;
        t.forEach(function (n, i) {
          pos[n.id] = { x: T > 1 ? PAD + ti * (boxW + gapX) : (W - boxW) / 2, y: top + i * (BOX_H + GAP_Y), w: boxW };
        });
      });
    } else {
      var perRow = Math.max(1, Math.floor((W - 2 * PAD + GAP_X) / (MIN_BOX_W + GAP_X)));
      var y = PAD;
      boxW = MIN_BOX_W;
      tiers.forEach(function (t) {
        var at = 0;
        rowsOf(t.length, perRow).forEach(function (count) {
          var w = Math.min(MAX_BOX_W, Math.floor((W - 2 * PAD - (count - 1) * GAP_X) / count));
          var left = (W - (count * w + (count - 1) * GAP_X)) / 2;
          for (var i = 0; i < count; i++) pos[t[at + i].id] = { x: left + i * (w + GAP_X), y: y, w: w };
          at += count;
          y += BOX_H + GAP_Y;
        });
        y += TIER_GAP - GAP_Y;
      });
      height = y - TIER_GAP + PAD;
    }
    var nodes = model.nodes.map(function (n) {
      var p = pos[n.id];
      var max = Math.max(4, Math.floor((p.w - 10) / CHAR_W));
      var names = wrap(n.name, max, 2);
      var texts = facts(n).map(function (f) { return clip(f, max); });
      var top = (BOX_H - (names.length + texts.length) * LINE_H) / 2 + 11;
      var lines = names.map(function (t, i) { return { text: t, y: top + i * LINE_H, cls: 'nm-name' }; });
      texts.forEach(function (t, i) { lines.push({ text: t, y: top + (names.length + i) * LINE_H, cls: i === 0 ? 'nm-state' : 'nm-fact' }); });
      return { id: n.id, kind: n.kind, state: n.state, x: Math.round(p.x), y: Math.round(p.y), w: p.w, h: BOX_H, lines: lines, label: describe(n) };
    });
    var at = {};
    nodes.forEach(function (n) { at[n.id] = n; });
    var edges = model.edges.map(function (e) {
      var a = at[e.from];
      var b = at[e.to];
      var d;
      if (columns) {
        var x1 = a.x + a.w;
        var y1 = a.y + a.h / 2;
        var x2 = b.x;
        var y2 = b.y + b.h / 2;
        var mx = (x1 + x2) / 2;
        d = 'M' + x1 + ' ' + y1 + ' C' + mx + ' ' + y1 + ' ' + mx + ' ' + y2 + ' ' + x2 + ' ' + y2;
      } else {
        var cx1 = a.x + a.w / 2;
        var cx2 = b.x + b.w / 2;
        // Down from the bottom of one box to the top of the other (or up, when the link goes back).
        var down = b.y >= a.y;
        var ay = down ? a.y + a.h : a.y;
        var by = down ? b.y : b.y + b.h;
        var my = (ay + by) / 2;
        d = 'M' + cx1 + ' ' + ay + ' C' + cx1 + ' ' + my + ' ' + cx2 + ' ' + my + ' ' + cx2 + ' ' + by;
      }
      return { from: e.from, to: e.to, kind: e.kind, down: e.down, d: d };
    });
    return { width: W, height: Math.round(height), mode: columns ? 'columns' : 'rows', nodes: nodes, edges: edges };
  }

  // The map as a list for screen readers: each node in words and what it connects to.
  function listItems(model) {
    var name = {};
    model.nodes.forEach(function (n) { name[n.id] = n.name; });
    return model.nodes.map(function (n) {
      var to = model.edges.filter(function (e) { return e.from === n.id; }).map(function (e) { return name[e.to]; });
      return describe(n) + (to.length ? ' Connects to ' + to.join(', ') + '.' : '');
    });
  }

  if (typeof document === 'undefined') {
    // Loaded by the tests: expose the pure parts only.
    globalThis.netmapLogic = { buildModel: buildModel, layout: layout, describe: describe, listItems: listItems, wrap: wrap, clip: clip, rowsOf: rowsOf };
    return;
  }

  var SVG = 'http://www.w3.org/2000/svg';
  var section = document.getElementById('netmap');
  if (!section) return;
  var holder = document.getElementById('netmap-chart');
  var listEl = document.getElementById('netmap-list');
  var summary = document.getElementById('netmap-summary');
  var hostsNow = null;
  var drawn = '';

  function el(name, attrs, parent) {
    var e = document.createElementNS(SVG, name);
    for (var k in attrs) if (Object.prototype.hasOwnProperty.call(attrs, k)) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }

  function draw() {
    if (!hostsNow) return;
    var model = buildModel(hostsNow);
    section.hidden = model.empty;
    if (model.empty) return;
    var width = holder.clientWidth || 0;
    // Closed or not laid out yet: drawn when it opens or gets a width.
    if (width <= 0) return;
    var lay = layout(model, width);
    var items = listItems(model);
    var sig = JSON.stringify([lay, items]);
    if (sig === drawn) return;
    drawn = sig;
    var active = document.activeElement;
    var focusId = active && holder.contains(active) ? active.getAttribute('data-id') : null;
    var svg = el('svg', { 'class': 'nm-svg', viewBox: '0 0 ' + lay.width + ' ' + lay.height, width: lay.width, height: lay.height, role: 'group', 'aria-label': 'Backbone network map' });
    var edges = el('g', { 'class': 'nm-edges', 'aria-hidden': 'true' }, svg);
    lay.edges.forEach(function (e) {
      el('path', { 'class': 'nm-edge ' + e.kind + (e.down ? ' down' : ''), d: e.d, fill: 'none' }, edges);
    });
    lay.nodes.forEach(function (n) {
      var g = el('g', { 'class': 'nm-node ' + n.kind + ' ' + n.state, tabindex: '0', role: 'img', 'aria-label': n.label, 'data-id': n.id, transform: 'translate(' + n.x + ' ' + n.y + ')' }, svg);
      el('title', {}, g).textContent = n.label;
      el('rect', { 'class': 'nm-box', width: n.w, height: n.h, rx: 10, ry: 10 }, g);
      n.lines.forEach(function (l) {
        el('text', { 'class': l.cls, x: n.w / 2, y: l.y, 'text-anchor': 'middle' }, g).textContent = l.text;
      });
    });
    holder.replaceChildren(svg);
    var lis = items.map(function (t) {
      var li = document.createElement('li');
      li.textContent = t;
      return li;
    });
    listEl.replaceChildren.apply(listEl, lis);
    if (focusId) {
      var again = holder.querySelectorAll('.nm-node');
      for (var i = 0; i < again.length; i++) {
        if (again[i].getAttribute('data-id') === focusId) { again[i].focus(); break; }
      }
    }
    summary.textContent = model.nodes.length + ' nodes, ' + model.edges.length + ' links';
  }

  // The page hands over each fresh /api/status here. Whether the section is open stays as the
  // visitor left it, because the same element is kept; nothing is saved.
  globalThis.netmapView = {
    update: function (hosts) { hostsNow = hosts; draw(); }
  };
  section.addEventListener('toggle', draw);
  if (typeof ResizeObserver === 'function') new ResizeObserver(draw).observe(holder);
  else window.addEventListener('resize', draw);
})();
