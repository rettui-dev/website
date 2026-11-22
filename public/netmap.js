// The backbone map on the status page: the proxy, the nodes behind it and the external peers they
// connect out to, drawn as inline SVG from the data of /api/status. The layout is pure (see
// netmapLogic, used by the tests); the drawing sets text with textContent only.
(function () {
  var WORD = { up: 'Up', down: 'Down', unknown: 'Unknown', external: 'External' };
  var GLYPH = { up: '●', down: '✕', unknown: '?', external: '↗' };
  var BOX_H = 76;
  // The proxy is wider and taller than a node: it has one more line (its tag) and a double border.
  var PROXY_H = 96;
  var MAX_BOX_W = 176;
  var MAX_PROXY_W = 208;
  var MIN_BOX_W = 90;
  var PAD = 8;
  var GAP_X = 8;
  var GAP_Y = 14;
  var TIER_GAP = 46;
  var COLUMN_GAP = 48;
  var LINE_H = 15;
  var CHAR_W = 6.8;
  var MIN_WIDTH = 280;
  // Arcs between nodes run in a gutter right of the node column: lane l bulges 26 + 20 l pixels, and
  // the gutter is 24 + 20 lanes wide (12 px per lane beyond 6 lanes).
  var ARC_BASE = 26;
  var ARC_STEP = 20;
  var ARC_TIGHT = 12;
  var GUTTER_BASE = 24;
  var LANE_PAD = 8;
  var END_STEP = 12;

  // Lookups by a host key use objects with no prototype, so a key such as "toString" is only a key.
  function hostKey(h) { return h.host + ':' + h.port; }
  function displayName(h) { return h.name || hostKey(h); }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
  function boxH(n) { return n.kind === 'proxy' ? PROXY_H : BOX_H; }
  function maxW(n) { return n.kind === 'proxy' ? MAX_PROXY_W : MAX_BOX_W; }

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
    var list = Array.isArray(hosts) ? hosts : [];
    var hasProxy = list.some(function (h) { return h.role === 'proxy'; });
    var nodes = [];
    var edges = [];
    var byId = Object.create(null);
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
    var links = linkEdges(list, byId);
    links.forEach(function (e) { edges.push(e); });
    var last = 0;
    nodes.forEach(function (n) { if (n.kind !== 'external' && n.tier > last) last = n.tier; });
    nodes.forEach(function (n) { if (n.kind === 'external') n.tier = last + 1; });
    var state = Object.create(null);
    nodes.forEach(function (n) { state[n.id] = n.state; });
    edges.forEach(function (e) { e.down = state[e.from] === 'down' || state[e.to] === 'down'; });
    if (links.length) {
      var names = Object.create(null);
      nodes.forEach(function (n) { names[n.id] = n.name; });
      nodes.forEach(function (n) { n.linkText = linkSentences(n, links, names); });
    }
    return { nodes: nodes, edges: edges, empty: !hasProxy && externals === 0 && links.length === 0 };
  }

  // One node in words, for the title, the accessible name and the list.
  function describe(n) {
    var out = [n.kind === 'proxy' ? 'Proxy ' + n.name + ', ' + WORD[n.state].toLowerCase()
      : n.name + ': ' + (n.kind === 'external' ? 'external backbone peer, not monitored' : WORD[n.state].toLowerCase())];
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
    var out = [GLYPH[n.state] + ' ' + WORD[n.state]];
    if (n.clients !== null) out.push(plural(num(n.clients), 'client', 'clients'));
    else if (n.kind === 'external') out.push('not checked');
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

  // Splits count items over rows of at most perRow, as even as it can.
  function rowsOf(count, perRow) {
    var rows = Math.ceil(count / perRow);
    var size = Math.ceil(count / rows);
    var out = [];
    for (var left = count; left > 0; left -= size) out.push(Math.min(size, left));
    return out;
  }

  // Plans the arcs between nodes: which tier they sit beside, where each end meets its box, which
  // lane each arc takes and how wide the gutter must be. colH: the height of each tier's column.
  // Returns {tier, gutter, drawn}; drawn are the link edges that can be drawn (both ends in the tier).
  function planArcs(model, tiers, colH) {
    var links = model.edges.filter(function (e) { return e.kind === 'link'; });
    var none = { tier: -1, gutter: 0, drawn: [], ys: {} };
    if (!links.length) return none;
    var tierOf = Object.create(null);
    tiers.forEach(function (t, ti) { t.forEach(function (n) { tierOf[n.id] = ti; }); });
    var count = Object.create(null);
    links.forEach(function (e) { if (tierOf[e.from] === tierOf[e.to]) count[tierOf[e.from]] = (count[tierOf[e.from]] || 0) + 1; });
    var tier = -1;
    Object.keys(count).forEach(function (k) { if (tier < 0 || count[k] > count[tier]) tier = Number(k); });
    if (tier < 0) return none;
    // Copies: the plan adds positions, and the model stays as it was.
    var drawn = links.filter(function (e) { return tierOf[e.from] === tier && tierOf[e.to] === tier; }).map(function (e) { return Object.assign({}, e); });
    var H = 2 * PAD + Math.max.apply(null, colH);
    var ys = Object.create(null);
    var y = PAD + (H - 2 * PAD - colH[tier]) / 2;
    tiers[tier].forEach(function (n) { ys[n.id] = { y: y, h: boxH(n) }; y += boxH(n) + GAP_Y; });
    // Where an arc meets a box: the node that dials at 35% of the height, the node that is dialled at
    // 65% (a mutual or unknown link: the upper node at 35%), so one node can do both and neither
    // touches the line to an external peer at 50%. Several ends on one side are spread a little.
    var ends = Object.create(null);
    drawn.forEach(function (e) {
      var upper = ys[e.from].y <= ys[e.to].y ? e.from : e.to;
      e.a = e.dir === 'dials' && !e.mutual ? e.from : upper;
      e.b = e.a === e.from ? e.to : e.from;
      [[e.a, 'out', e.b, 'ya'], [e.b, 'in', e.a, 'yb']].forEach(function (x) {
        var k = x[0] + '/' + x[1];
        (ends[k] = ends[k] || []).push({ e: e, other: x[2], field: x[3] });
      });
    });
    Object.keys(ends).forEach(function (k) {
      var list = ends[k];
      var id = k.slice(0, k.lastIndexOf('/'));
      list.sort(function (p, q) { return ys[p.other].y - ys[q.other].y; });
      var h = ys[id].h;
      var base = ys[id].y + h * (k.slice(-3) === 'out' ? 0.35 : 0.65);
      var step = list.length > 1 ? Math.min(END_STEP, (0.24 * h) / (list.length - 1)) : 0;
      list.forEach(function (it, i) { it.e[it.field] = base + (i - (list.length - 1) / 2) * step; });
    });
    // Lanes: the shortest arcs first, each in the lowest lane where no arc overlaps its span.
    var lanes = [];
    drawn.slice().sort(function (p, q) {
      return Math.abs(p.ya - p.yb) - Math.abs(q.ya - q.yb) || Math.min(p.ya, p.yb) - Math.min(q.ya, q.yb);
    }).forEach(function (e) {
      var lo = Math.min(e.ya, e.yb) - LANE_PAD;
      var hi = Math.max(e.ya, e.yb) + LANE_PAD;
      var l = 0;
      while (l < lanes.length && lanes[l].some(function (r) { return lo < r[1] && hi > r[0]; })) l++;
      if (!lanes[l]) lanes[l] = [];
      lanes[l].push([lo, hi]);
      e.lane = l;
    });
    var step2 = lanes.length > 6 ? ARC_TIGHT : ARC_STEP;
    drawn.forEach(function (e) { e.depth = ARC_BASE + step2 * e.lane; });
    return { tier: tier, gutter: GUTTER_BASE + step2 * lanes.length, drawn: drawn, ys: ys };
  }

  function round1(v) { return Math.round(v * 10) / 10; }

  // The mark at the end of a link for what that direction says: a filled arrowhead, an outlined one
  // when the operator declared it, or a bar across the line when it is turned off.
  function head(f) { return f.enabled === false ? 'bar' : f.source === 'declared' ? 'open' : 'arrow'; }

  // The path, marks and ticks of one arc; xr is the right edge of the node column.
  function arcGeometry(e, xr) {
    var dd = e.depth * 1.33;
    var d = 'M' + round1(xr) + ' ' + round1(e.ya) + ' C' + round1(xr + dd) + ' ' + round1(e.ya) + ' ' + round1(xr + dd) + ' ' + round1(e.yb) + ' ' + round1(xr) + ' ' + round1(e.yb);
    var out = { from: e.from, to: e.to, kind: 'link', down: e.down, d: d, dir: e.dir, mutual: e.mutual, lane: e.lane };
    var fwd = { enabled: e.enabled, source: e.source };
    if (e.dir === 'unknown') {
      out.start = 'ring'; out.end = 'ring'; out.off = false; out.declared = e.source === 'declared';
    } else if (e.mutual) {
      // The head at each end is for the direction that dials that end.
      var atTo = head(fwd);
      var atFrom = head(e.back);
      out.start = e.a === e.from ? atFrom : atTo;
      out.end = e.a === e.from ? atTo : atFrom;
      out.off = e.enabled === false && e.back.enabled === false;
      out.declared = e.source === 'declared' && e.back.source === 'declared';
    } else {
      out.start = 'dot'; out.end = head(fwd); out.off = e.enabled === false; out.declared = e.source === 'declared';
    }
    // A node that is down: two short slanted slashes on the middle of the line, where it bulges most.
    out.ticks = [];
    if (e.down) {
      var mx = xr + 0.75 * dd;
      var my = (e.ya + e.yb) / 2;
      var ang = e.yb >= e.ya ? Math.PI / 2 : -Math.PI / 2;
      [-4, 4].forEach(function (off) {
        var cx = mx + Math.cos(ang) * off;
        var cy = my + Math.sin(ang) * off;
        var a2 = ang + Math.PI / 2 + 0.6;
        var dx = Math.cos(a2) * 7;
        var dy = Math.sin(a2) * 7;
        out.ticks.push('M' + round1(cx - dx) + ' ' + round1(cy - dy) + ' L' + round1(cx + dx) + ' ' + round1(cy + dy));
      });
    }
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
    var tierW = tiers.map(function (t) { return Math.max.apply(null, t.map(maxW)); });
    var colH0 = tiers.map(function (t) { return t.reduce(function (a, n) { return a + boxH(n); }, 0) + (t.length - 1) * GAP_Y; });
    var plan = planArcs(model, tiers, colH0);
    // The gutter widens the node column, so the columns or rows decision already counts it.
    var G = plan.gutter;
    if (G) tierW[plan.tier] += G;
    var columns = tierW.reduce(function (a, b) { return a + b; }, 0) + (T - 1) * COLUMN_GAP + 2 * PAD <= W;
    var pos = Object.create(null);
    var height;
    if (columns) {
      var colH = colH0;
      height = 2 * PAD + Math.max.apply(null, colH);
      var gapX = T > 1 ? (W - 2 * PAD - tierW.reduce(function (a, b) { return a + b; }, 0)) / (T - 1) : 0;
      var left = PAD;
      tiers.forEach(function (t, ti) {
        var y = PAD + (height - 2 * PAD - colH[ti]) / 2;
        t.forEach(function (n) {
          var w = maxW(n);
          pos[n.id] = { x: T > 1 ? left + (tierW[ti] - (ti === plan.tier ? G : 0) - w) / 2 : (W - (ti === plan.tier ? G : 0) - w) / 2, y: y, w: w, h: boxH(n) };
          y += boxH(n) + GAP_Y;
        });
        left += tierW[ti] + gapX;
      });
    } else {
      var perRow = Math.max(1, Math.floor((W - 2 * PAD + GAP_X) / (MIN_BOX_W + GAP_X)));
      var y = PAD;
      tiers.forEach(function (t) {
        var at = 0;
        rowsOf(t.length, perRow).forEach(function (count) {
          var row = t.slice(at, at + count);
          var share = Math.floor((W - 2 * PAD - (count - 1) * GAP_X) / count);
          var widths = row.map(function (n) { return Math.min(maxW(n), share); });
          var total = widths.reduce(function (a, b) { return a + b; }, 0) + (count - 1) * GAP_X;
          var x = (W - total) / 2;
          var rowH = 0;
          row.forEach(function (n, i) {
            pos[n.id] = { x: x, y: y, w: widths[i], h: boxH(n) };
            x += widths[i] + GAP_X;
            rowH = Math.max(rowH, boxH(n));
          });
          at += count;
          y += rowH + GAP_Y;
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
      var label = tag(n);
      var count = (label ? 1 : 0) + names.length + texts.length;
      var top = (p.h - count * LINE_H) / 2 + 11;
      var lines = [];
      if (label) lines.push({ text: label, y: top, cls: 'nm-tag' });
      var first = label ? 1 : 0;
      names.forEach(function (t, i) { lines.push({ text: t, y: top + (first + i) * LINE_H, cls: 'nm-name' }); });
      texts.forEach(function (t, i) { lines.push({ text: t, y: top + (first + names.length + i) * LINE_H, cls: i === 0 ? 'nm-state' : 'nm-fact' }); });
      return { id: n.id, kind: n.kind, state: n.state, x: Math.round(p.x), y: Math.round(p.y), w: p.w, h: p.h, lines: lines, label: describe(n) };
    });
    var at = Object.create(null);
    nodes.forEach(function (n) { at[n.id] = n; });
    var drawnLinks = Object.create(null);
    plan.drawn.forEach(function (e) { drawnLinks[e.from + '>' + e.to] = e; });
    var edges = model.edges.filter(function (e) { return e.kind !== 'link' || (columns && drawnLinks[e.from + '>' + e.to]); }).map(function (e) {
      if (e.kind === 'link') return arcGeometry(drawnLinks[e.from + '>' + e.to], at[e.from].x + at[e.from].w);
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
    var linkCount = model.edges.filter(function (e) { return e.kind === 'link'; }).length;
    var linksDrawn = edges.filter(function (e) { return e.kind === 'link'; }).length;
    return { width: W, height: Math.round(height), mode: columns ? 'columns' : 'rows', nodes: nodes, edges: edges, linksHidden: linkCount > linksDrawn };
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
    globalThis.netmapLogic = { buildModel: buildModel, layout: layout, describe: describe, summaryText: summaryText, listItems: listItems, wrap: wrap, clip: clip, rowsOf: rowsOf };
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

  function el(name, attrs, parent) {
    var e = document.createElementNS(SVG, name);
    for (var k in attrs) if (Object.prototype.hasOwnProperty.call(attrs, k)) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }

  // The marks at the ends of node links, in <defs> and styled by class: a filled arrowhead, an open
  // one (declared), a bar (turned off), a dot (the node that dials) and a ring (direction not known).
  // Each exists twice, the second in the colour of a link that has a node down.
  function addMarkers(svg) {
    var defs = el('defs', {}, svg);
    function marker(id, w, h, rx, ry, make) {
      make(el('marker', { id: id, markerUnits: 'userSpaceOnUse', markerWidth: w, markerHeight: h, refX: rx, refY: ry, orient: 'auto-start-reverse', overflow: 'visible' }, defs));
    }
    ['', '-dn'].forEach(function (sfx) {
      var c = sfx ? 'nm-mk-fill dn' : 'nm-mk-fill';
      var o = sfx ? 'nm-mk-open dn' : 'nm-mk-open';
      var b = sfx ? 'nm-mk-bar dn' : 'nm-mk-bar';
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
    var sfx = e.down ? '-dn' : '';
    var g = el('g', { 'class': 'nm-link' + (e.down ? ' down' : ''), 'data-from': e.from, 'data-to': e.to }, parent);
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
    var hasLinks = lay.edges.some(function (e) { return e.kind === 'link'; });
    if (hasLinks) addMarkers(svg);
    lay.edges.forEach(function (e) {
      if (e.kind !== 'link') el('path', { 'class': 'nm-edge ' + e.kind + (e.down ? ' down' : ''), d: e.d, fill: 'none' }, edges);
    });
    var linkGroups = [];
    lay.edges.forEach(function (e) {
      if (e.kind === 'link') linkGroups.push(drawLink(e, edges));
    });
    lay.nodes.forEach(function (n) {
      var g = el('g', { 'class': 'nm-node ' + n.kind + ' ' + n.state, tabindex: '0', role: 'img', 'aria-label': n.label, 'data-id': n.id, transform: 'translate(' + n.x + ' ' + n.y + ')' }, svg);
      el('title', {}, g).textContent = n.label;
      el('rect', { 'class': 'nm-box', width: n.w, height: n.h, rx: 10, ry: 10 }, g);
      // The double border of a proxy: a second, thinner line inside the first.
      if (n.kind === 'proxy') el('rect', { 'class': 'nm-box-inner', x: 5, y: 5, width: n.w - 10, height: n.h - 10, rx: 6, ry: 6 }, g);
      n.lines.forEach(function (l) {
        el('text', { 'class': l.cls, x: n.w / 2, y: l.y, 'text-anchor': 'middle' }, g).textContent = l.text;
      });
    });
    if (linkGroups.length) highlight(svg, edges, linkGroups);
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
    summary.textContent = summaryText(model);
    if (legend) legend.hidden = !model.edges.some(function (e) { return e.kind === 'link'; });
    if (phoneNote) phoneNote.hidden = !lay.linksHidden;
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
