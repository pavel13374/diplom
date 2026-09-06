

(function (root) {
  'use strict';

  var NS = 'http://www.w3.org/2000/svg';
  var uid = 0;

  function el(tag, attrs, parent) {
    var n = document.createElementNS(NS, tag);
    if (attrs) for (var k in attrs) if (attrs[k] != null) n.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(n);
    return n;
  }
  function div(cls, parent, html) {
    var n = document.createElement('div');
    if (cls) n.className = cls;
    if (html != null) n.innerHTML = html;
    if (parent) parent.appendChild(n);
    return n;
  }
  function esc(x) {
    return (x == null ? '' : ('' + x)).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c];
    });
  }

  function still() {
    try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; }
    catch (x) { return false; }
  }

  function seen(host) {
    if (host.dataset.dscSeen) return true;
    host.dataset.dscSeen = '1';
    return false;
  }
  function same(host, sig) {
    if (host.dataset.dscSig === sig) return true;
    host.dataset.dscSig = sig;
    return false;
  }

  function tokenColor(name, fallback) {
    try {
      var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
      return v || fallback;
    } catch (x) { return fallback; }
  }
  function palette(i) {
    return 'var(--chart-' + ((i % 5) + 1) + ')';
  }
  function fmtNum(v) {
    if (v == null || isNaN(v)) return '—';
    if (Math.abs(v) >= 1000) return Math.round(v).toLocaleString('ru-RU');
    if (Math.abs(v) >= 100) return String(Math.round(v));
    return String(Math.round(v * 10) / 10);
  }

  function monotonePath(pts) {
    var n = pts.length;
    if (n === 0) return '';
    if (n === 1) return 'M' + pts[0][0] + ' ' + pts[0][1];
    if (n === 2) return 'M' + pts[0][0] + ' ' + pts[0][1] + 'L' + pts[1][0] + ' ' + pts[1][1];
    var dx = [], dy = [], m = [], i;
    for (i = 0; i < n - 1; i++) {
      dx.push(pts[i + 1][0] - pts[i][0]);
      dy.push(pts[i + 1][1] - pts[i][1]);
    }
    var slope = dy.map(function (d, k) { return dx[k] ? d / dx[k] : 0; });
    m[0] = slope[0];
    for (i = 1; i < n - 1; i++) {
      if (slope[i - 1] * slope[i] <= 0) m[i] = 0;
      else {
        var w1 = 2 * dx[i] + dx[i - 1], w2 = dx[i] + 2 * dx[i - 1];
        m[i] = (w1 + w2) / (w1 / slope[i - 1] + w2 / slope[i]);
      }
    }
    m[n - 1] = slope[n - 2];
    var d = 'M' + pts[0][0].toFixed(2) + ' ' + pts[0][1].toFixed(2);
    for (i = 0; i < n - 1; i++) {
      var c = dx[i] / 3;
      d += 'C' + (pts[i][0] + c).toFixed(2) + ' ' + (pts[i][1] + c * m[i]).toFixed(2) +
           ' ' + (pts[i + 1][0] - c).toFixed(2) + ' ' + (pts[i + 1][1] - c * m[i + 1]).toFixed(2) +
           ' ' + pts[i + 1][0].toFixed(2) + ' ' + pts[i + 1][1].toFixed(2);
    }
    return d;
  }

  function donut(host, o) {
    if (!host) return;
    o = o || {};
    var items = (o.items || []).filter(function (x) { return (+x.value || 0) > 0; });
    var sig = 'd|' + (o.centerValue || '') + '|' + (o.centerLabel || '') + '|' +
      items.map(function (x) { return x.label + ':' + x.value + ':' + (x.color || ''); }).join(',');
    if (same(host, sig)) return;
    var animate = !seen(host) && !still();
    host.innerHTML = '';
    host.classList.add('dsc-donut');
    if (!items.length) {
      div('ds-empty', host, esc(o.empty || 'Нет данных'));
      return;
    }
    var total = items.reduce(function (a, x) { return a + (+x.value || 0); }, 0);
    var size = o.size || 190;
    var thick = o.thickness || 22;
    var r = (size - thick) / 2;
    var C = 2 * Math.PI * r;
    var gapDeg = items.length > 1 ? 1.6 : 0;

    var wrap = div('dsc-donut-wrap', host);
    var ring = div('dsc-ring', wrap);
    ring.style.width = ring.style.height = size + 'px';

    var svg = el('svg', { viewBox: '0 0 ' + size + ' ' + size, width: size, height: size }, ring);
    var g = el('g', { transform: 'rotate(-90 ' + (size / 2) + ' ' + (size / 2) + ')' }, svg);
    el('circle', {
      cx: size / 2, cy: size / 2, r: r, fill: 'none',
      'stroke-width': thick, stroke: 'var(--surface-3)'
    }, g);

    var acc = 0, arcs = [];
    items.forEach(function (it, i) {
      var frac = (+it.value || 0) / total;
      var deg = frac * 360;
      var len = Math.max(0, (deg - gapDeg) / 360 * C);
      var a = el('circle', {
        cx: size / 2, cy: size / 2, r: r, fill: 'none',
        'stroke-width': thick, 'stroke-linecap': 'butt',
        stroke: it.color || palette(i),
        'stroke-dasharray': len + ' ' + (C - len),
        'stroke-dashoffset': -(acc / 360 * C),
        class: 'dsc-arc'
      }, g);
      a.style.setProperty('--i', i);
      arcs.push(a);
      acc += deg;
    });

    var mid = div('dsc-center', ring);
    var midV = div('dsc-center-v', mid);
    var midL = div('dsc-center-l', mid);
    function showTotal() {
      midV.textContent = o.centerValue != null ? o.centerValue : fmtNum(total);
      midL.textContent = o.centerLabel || 'всего';
      midV.style.color = '';
    }
    function showItem(i) {
      var it = items[i];
      midV.textContent = (o.fmt ? o.fmt(it.value) : fmtNum(it.value));
      midL.textContent = it.label;
      midV.style.color = it.color || palette(i);
    }
    showTotal();

    var legend = div('dsc-legend', wrap);
    if (o.title) div('dsc-legend-t', legend, esc(o.title));
    items.forEach(function (it, i) {
      var row = div('dsc-legend-row', legend);
      var dot = div('dsc-dot', row);
      dot.style.background = it.color || palette(i);
      div('dsc-legend-n', row, esc(it.label));
      var pct = total >= 20 ? Math.round(it.value / total * 100) + '%' : '';
      div('dsc-legend-v', row,
        '<b>' + esc(o.fmt ? o.fmt(it.value) : fmtNum(it.value)) + '</b>' +
        (pct ? '<span>' + pct + '</span>' : ''));
      function on() {
        wrap.classList.add('is-focus');
        arcs.forEach(function (a, k) { a.classList.toggle('is-on', k === i); });
        row.classList.add('is-on');
        showItem(i);
      }
      function off() {
        wrap.classList.remove('is-focus');
        arcs.forEach(function (a) { a.classList.remove('is-on'); });
        row.classList.remove('is-on');
        showTotal();
      }
      row.addEventListener('mouseenter', on);
      row.addEventListener('mouseleave', off);
      row.addEventListener('focus', on);
      row.addEventListener('blur', off);
      row.tabIndex = 0;
      arcs[i].addEventListener('mouseenter', on);
      arcs[i].addEventListener('mouseleave', off);
      if (it.onClick) {
        row.addEventListener('click', it.onClick);
        arcs[i].addEventListener('click', it.onClick);
        row.classList.add('is-clickable');
      }
    });

    if (animate) {
      arcs.forEach(function (a) { a.classList.add('dsc-in'); });
    }
  }

  /* Ширина нужна для отступа под подписи оси. Панель может строиться,
     пока её раздел скрыт (clientWidth === 0), поэтому замер повторяется,
     когда элемент реально получает размер. */
  function watchWidth(host, redraw) {
    if (host.__dscRO || !window.ResizeObserver) return;
    var last = host.clientWidth;
    host.__dscRO = new ResizeObserver(function () {
      var w = host.clientWidth;
      if (!w || Math.abs(w - last) < 8) return;
      last = w;
      delete host.dataset.dscSig;
      redraw();
    });
    host.__dscRO.observe(host);
  }

  function area(host, o) {
    if (!host) return;
    o = o || {};
    watchWidth(host, function () { area(host, o); });
    var series = o.series || [];
    var labels = o.labels || [];
    var n = labels.length || (series[0] && series[0].values.length) || 0;
    var sig = 'a|' + labels.length + '|' + series.map(function (x) {
      return (x.name || '') + ':' + (x.color || '') + ':' + x.values.join(',');
    }).join('|');
    if (same(host, sig)) return;
    var animate = !seen(host) && !still();
    host.innerHTML = '';
    host.classList.add('dsc-area');
    if (!n || !series.length) {
      div('ds-empty', host, esc(o.empty || 'Данных пока нет'));
      return;
    }

    var H = o.height || 190;
    var W = 1000;
    /* Поле графика не знает про подписи оси: под них отведён padding
       контейнера, а SVG занимает ровно остаток. Замерять ширину нельзя —
       карточка может строиться вне документа. */
    var gutterPx = o.gutter == null ? 40 : o.gutter;
    var padL = 0, padR = 0, padT = 14, padB = 24;
    var iw = W, ih = H - padT - padB;

    var all = [];
    series.forEach(function (s) { s.values.forEach(function (v) { if (v != null) all.push(+v); }); });
    var hi = o.max != null ? o.max : Math.max.apply(null, all.concat([0]));
    var lo = o.min != null ? o.min : Math.min.apply(null, all.concat([0]));
    if (o.pct) { hi = 1; lo = 0; }
    else if (hi === lo) { hi = hi || 1; lo = 0; }
    else { hi = hi + (hi - lo) * 0.14; }

    var X = function (i) { return padL + (n <= 1 ? iw / 2 : (i / (n - 1)) * iw); };
    var Y = function (v) { return padT + ih - ((v - lo) / ((hi - lo) || 1)) * ih; };

    var plot = div('dsc-plot', host);
    plot.style.height = H + 'px';
    plot.style.paddingLeft = gutterPx + 'px';
    plot.style.paddingRight = '10px';
    var svg = el('svg', { viewBox: '0 0 ' + W + ' ' + H, preserveAspectRatio: 'none' }, plot);
    var defs = el('defs', null, svg);

    var rows = o.rows || (H < 150 ? 2 : 4);
    for (var gi = 0; gi <= rows; gi++) {
      var gy = padT + (gi / rows) * ih;
      el('line', {
        x1: padL, x2: W - padR, y1: gy, y2: gy,
        class: 'dsc-grid', 'stroke-dasharray': '4 4'
      }, svg);
    }

    series.forEach(function (s, si) {
      var col = s.color || palette(si);
      var gid = 'dscg' + (++uid);
      var lg = el('linearGradient', { id: gid, x1: 0, y1: 0, x2: 0, y2: 1 }, defs);
      el('stop', { offset: '0%', 'stop-color': col, 'stop-opacity': o.fillOpacity == null ? .34 : o.fillOpacity }, lg);
      el('stop', { offset: '100%', 'stop-color': col, 'stop-opacity': 0 }, lg);

      var pts = [];
      s.values.forEach(function (v, i) { if (v != null) pts.push([X(i), Y(+v)]); });
      if (!pts.length) return;
      var line = monotonePath(pts);
      var areaD = line + 'L' + pts[pts.length - 1][0].toFixed(2) + ' ' + (padT + ih) +
                  'L' + pts[0][0].toFixed(2) + ' ' + (padT + ih) + 'Z';
      el('path', { d: areaD, fill: 'url(#' + gid + ')', class: 'dsc-fill' }, svg);
      var pl = el('path', { d: line, fill: 'none', stroke: col, class: 'dsc-line' }, svg);
      pl.style.setProperty('--i', si);

      if (animate) {
        var L = 0;
        try { L = pl.getTotalLength(); } catch (x) { L = 0; }
        if (L) {
          pl.style.strokeDasharray = L;
          pl.style.strokeDashoffset = L;
          pl.classList.add('dsc-draw');
        }
      }
    });

    var yax = div('dsc-y', plot);
    yax.style.width = gutterPx + 'px';
    yax.style.height = H + 'px';
    for (var yi = 0; yi <= rows; yi++) {
      var v = hi - (yi / rows) * (hi - lo);
      var sp = document.createElement('span');
      sp.textContent = o.fmt ? o.fmt(v) : fmtNum(v);
      sp.style.top = ((padT + (yi / rows) * ih) / H * 100) + '%';
      yax.appendChild(sp);
    }

    if (series.length > 1) {
      var lg2 = div('dsc-alegend', host);
      series.forEach(function (s2, si2) {
        var it2 = div('dsc-alegend-i', lg2);
        var d2 = div('dsc-dot', it2);
        d2.style.background = s2.color || palette(si2);
        var sp2 = document.createElement('span');
        sp2.textContent = s2.name || ('ряд ' + (si2 + 1));
        it2.appendChild(sp2);
      });
    }

    var xax = div('dsc-x', host);
    xax.style.paddingLeft = gutterPx + 'px';
    var ticks = Math.min(n, o.xTicks || 4);
    for (var xi = 0; xi < ticks; xi++) {
      var idx = ticks === 1 ? 0 : Math.round(xi / (ticks - 1) * (n - 1));
      var xs = document.createElement('span');
      xs.textContent = labels[idx] || '';
      xax.appendChild(xs);
    }

    var cur = div('dsc-cursor', plot);
    var tip = div('dsc-tip', plot);
    var dots = series.map(function (s, si) {
      var d = div('dsc-dot-m', plot);
      d.style.background = s.color || palette(si);
      return d;
    });
    function hide() {
      cur.style.opacity = 0; tip.style.opacity = 0;
      dots.forEach(function (d) { d.style.opacity = 0; });
    }
    hide();
    plot.addEventListener('mousemove', function (ev) {
      var r = svg.getBoundingClientRect();
      var off = r.left - plot.getBoundingClientRect().left;
      var relIn = Math.min(1, Math.max(0, (ev.clientX - r.left) / (r.width || 1)));
      var i = Math.round(relIn * (n - 1));
      var px = off + (X(i) / W) * r.width;
      cur.style.left = px + 'px'; cur.style.opacity = 1;
      var rowsHtml = '';
      series.forEach(function (s, si) {
        var v = s.values[i];
        if (v == null) { dots[si].style.opacity = 0; return; }
        var py = (Y(+v) / H) * r.height;
        dots[si].style.left = px + 'px';
        dots[si].style.top = py + 'px';
        dots[si].style.opacity = 1;
        rowsHtml += '<div class=dsc-tip-r><i style="background:' + (s.color || palette(si)) + '"></i>' +
          (series.length > 1 ? '<span>' + esc(s.name || '') + '</span>' : '') +
          '<b>' + esc(o.fmt ? o.fmt(+v) : fmtNum(+v)) + '</b></div>';
      });
      tip.innerHTML = '<div class=dsc-tip-t>' + esc(labels[i] || '') + '</div>' + rowsHtml;
      tip.style.opacity = 1;
      var tw = tip.offsetWidth || 120;
      tip.style.left = Math.min(r.width - tw / 2 - 4, Math.max(tw / 2 + 4, px)) + 'px';
    });
    plot.addEventListener('mouseleave', hide);
  }

  function bars(host, o) {
    if (!host) return;
    o = o || {};
    var items = o.items || [];
    var sig = 'b|' + items.map(function (x) {
      return x.label + ':' + x.value + ':' + (x.color || '');
    }).join(',');
    if (same(host, sig)) return;
    var animate = !seen(host) && !still();
    host.innerHTML = '';
    host.classList.add('dsc-bars');
    if (!items.length) {
      div('ds-empty', host, esc(o.empty || 'Нет данных'));
      return;
    }
    var mx = Math.max.apply(null, items.map(function (x) { return +x.value || 0; }).concat([1]));
    items.slice(0, o.limit || 10).forEach(function (it, i) {
      var row = div('dsc-bar-row', host);
      if (it.onClick) { row.classList.add('is-clickable'); row.addEventListener('click', it.onClick); row.tabIndex = 0; }
      div('dsc-bar-n', row, esc(it.label)).title = it.label;
      var track = div('dsc-bar-track', row);
      var fill = div('dsc-bar-fill', track);
      fill.style.background = it.color || palette(o.mono ? 0 : i);
      fill.style.setProperty('--w', Math.max(2, (+it.value || 0) / mx * 100) + '%');
      fill.style.setProperty('--i', Math.min(i, 9));
      if (animate) fill.classList.add('dsc-grow');
      div('dsc-bar-v', row, esc(o.fmt ? o.fmt(it.value) : fmtNum(it.value)));
    });
  }

  function spark(host, values, o) {
    if (!host) return;
    o = o || {};
    var v = (values || []).map(function (x) { return x == null ? null : Number(x); });
    var sig = 's|' + v.join(',') + '|' + (o.color || '') + '|' + (o.fill ? 1 : 0);
    if (same(host, sig)) return;
    host.innerHTML = '';
    host.classList.add('dsc-spark');
    var real = v.filter(function (x) { return x != null; });
    if (real.length < 2) return;
    var W = 100, H = o.height || 30, pad = 3;
    var hi = o.max != null ? o.max : Math.max.apply(null, real);
    var lo = o.min != null ? o.min : Math.min.apply(null, real);
    if (hi === lo) { hi = hi + 1; lo = lo - 1; }
    var X = function (i) { return (i / (v.length - 1)) * W; };
    var Y = function (x) { return H - pad - ((x - lo) / (hi - lo)) * (H - pad * 2); };
    var pts = [];
    v.forEach(function (x, i) { if (x != null) pts.push([X(i), Y(x)]); });
    var svg = el('svg', { viewBox: '0 0 ' + W + ' ' + H, preserveAspectRatio: 'none' }, host);
    var col = o.color || 'var(--chart-1)';
    var d = monotonePath(pts);
    if (o.fill) {
      var gid = 'dscs' + (++uid);
      var defs = el('defs', null, svg);
      var lg = el('linearGradient', { id: gid, x1: 0, y1: 0, x2: 0, y2: 1 }, defs);
      el('stop', { offset: '0%', 'stop-color': col, 'stop-opacity': .34 }, lg);
      el('stop', { offset: '100%', 'stop-color': col, 'stop-opacity': 0 }, lg);
      el('path', {
        d: d + 'L' + pts[pts.length - 1][0].toFixed(2) + ' ' + H +
           'L' + pts[0][0].toFixed(2) + ' ' + H + 'Z',
        fill: 'url(#' + gid + ')', stroke: 'none'
      }, svg);
    }
    el('path', { d: d, fill: 'none', stroke: col, class: 'dsc-spark-l' }, svg);
    if (o.dot && pts.length) {
      var last = pts[pts.length - 1];
      el('circle', { cx: last[0], cy: last[1], r: 2.2, fill: col, class: 'dsc-spark-d' }, svg);
    }
  }

  root.dsDonut = donut;
  root.dsArea = area;
  root.dsBars = bars;
  root.dsSpark = spark;
  root.dsChartPalette = palette;
})(window);
