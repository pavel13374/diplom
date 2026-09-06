

(function () {
  'use strict';

  function L(s) { return (window.socT ? window.socT(s) : s); }

  var I = {
    grid:   'M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z',
    alert:  'M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
    shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
    inbox:  'M22 12h-6l-2 3h-4l-2-3H2M5.4 5.1 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.4-6.9A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.8 1.1z',
    target: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
    code:   'm16 18 6-6-6-6M8 6l-6 6 6 6',
    users:  'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM22 21v-2a4 4 0 0 0-3-3.9',
    zap:    'M13 2 3 14h9l-1 8 10-12h-9l1-8z',
    chart:  'M3 3v18h18M18 17V9M13 17V5M8 17v-3',
    stetho: 'M11 2v2a5 5 0 0 1-10 0V2M6 9v3a6 6 0 0 0 12 0M18 12a3 3 0 1 0 0 6 3 3 0 0 0 0-6z',
    slider: 'M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6',
    term:   'm4 17 6-6-6-6M12 19h8',
    db:     'M12 8c4.4 0 8-1.3 8-3s-3.6-3-8-3-8 1.3-8 3 3.6 3 8 3zM4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3',
    folder: 'M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.7-.9L9.6 3.9A2 2 0 0 0 7.9 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2z',
    search: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3',
    sun:    'M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4',
    moon:   'M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z',
    bright: 'M12 3v2M12 19v2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M3 12h2M19 12h2M5.6 18.4 7 17M17 7l1.4-1.4M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z',
    case:   'M16 20V4a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16M4 20h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2z',
    play:   'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM10 8l6 4-6 4V8z',
    pulse:  'M22 12h-4l-3 9L9 3l-3 9H2'
  };
  function svg(d, cls) {
    return '<svg class="' + (cls || '') + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
           'stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="' + d + '"/></svg>';
  }

  var MAP = {

    overview:  { i: I.grid,   s: 'Обзор' },
    alerts:    { i: I.alert,  s: 'SOC' },
    incidents: { i: I.shield, s: 'SOC' },
    cases:     { i: I.case,   s: 'SOC' },
    workflow:  { i: I.inbox,  s: 'SOC' },
    attack:    { i: I.target, s: 'Purple Team' },
    detections:{ i: I.code,   s: 'Purple Team' },
    red:       { i: I.zap,    s: 'Purple Team' },
    replay:    { i: I.play,   s: 'Purple Team' },
    entities:  { i: I.users,  s: 'Аналитика' },
    risk:      { i: I.pulse,  s: 'Аналитика' },
    trends:    { i: I.chart,  s: 'Аналитика' },
    diag:      { i: I.stetho, s: 'Система' },

    config:    { i: I.slider, s: 'Система' },
    logs:      { i: I.term,   s: 'Среда' },
    data:      { i: I.db,     s: 'Данные' },
    repos:     { i: I.folder, s: 'Среда' },
    insights:  { i: I.chart,  s: 'Данные' },
    people:    { i: I.users,  s: 'Среда' }
  };

  var THEME_KEY = 'soc_theme';
  var THEMES = ['dark', 'light'];
  var THEME_META = {
    dark:  { icon: 'sun',  title: 'Светлая тема' },
    light: { icon: 'moon', title: 'Тёмная тема' }
  };
  function currentTheme() {
    var t = document.documentElement.getAttribute('data-theme');
    return THEMES.indexOf(t) >= 0 ? t : 'dark';
  }
  function applyTheme(t) {
    if (THEMES.indexOf(t) < 0) t = 'dark';
    document.documentElement.setAttribute('data-theme', t);
    var b = document.getElementById('dsTheme');
    if (b) {
      var m = THEME_META[t];
      b.innerHTML = svg(I[m.icon]);
      b.title = L(m.title);
      b.setAttribute('aria-label', L(m.title));
    }
  }
  function initTheme() {
    var saved = null;
    try { saved = localStorage.getItem(THEME_KEY); } catch (x) {}
    applyTheme(saved || 'dark');
  }
  function toggleTheme() {
    var next = THEMES[(THEMES.indexOf(currentTheme()) + 1) % THEMES.length];
    try { localStorage.setItem(THEME_KEY, next); } catch (x) {}
    applyTheme(next);
  }
  function setTheme(t) {
    try { localStorage.setItem(THEME_KEY, t); } catch (x) {}
    applyTheme(t);
  }

  var SECTION_ORDER = ['Обзор', 'SOC', 'Purple Team', 'Аналитика', 'Среда', 'Данные', 'Система'];
  function enhanceNav() {
    var nav = document.querySelector('.nav');
    if (!nav || nav.dataset.dsDone) return;
    var links = Array.prototype.slice.call(nav.querySelectorAll('a'));
    if (!links.length) return;

    links.forEach(function (a) {
      var key = a.getAttribute('data-v') || a.getAttribute('data-view');
      var m = MAP[key];
      if (!a.querySelector('.nav-t')) {
        var label = '';
        Array.prototype.slice.call(a.childNodes).forEach(function (n) {
          if (n.nodeType === 3) { label += n.nodeValue; a.removeChild(n); }
        });
        label = label.trim();
        if (label) {
          var sp = document.createElement('span');
          sp.className = 'nav-t';
          sp.textContent = label;
          a.appendChild(sp);
          a.title = label;
          a.setAttribute('aria-label', label);
        }
      }
      if (m && !a.querySelector('svg')) a.insertAdjacentHTML('afterbegin', svg(m.i));
    });

    links.forEach(function (a) {
      if (!a.hasAttribute('tabindex')) a.setAttribute('tabindex', '0');
      a.setAttribute('role', 'link');
      a.setAttribute('aria-current', a.classList.contains('active') ? 'page' : 'false');
      if (a.dataset.dsKey) return;
      a.dataset.dsKey = '1';
      a.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
          e.preventDefault();
          a.click();
        }
      });
      a.addEventListener('click', function () {
        links.forEach(function (x) {
          x.setAttribute('aria-current', x.classList.contains('active') ? 'page' : 'false');
        });
      });
    });

    var groups = {};
    links.forEach(function (a) {
      var key = a.getAttribute('data-v') || a.getAttribute('data-view');
      var sec = (MAP[key] && MAP[key].s) || 'Прочее';
      (groups[sec] = groups[sec] || []).push(a);
    });
    var order = SECTION_ORDER.filter(function (s) { return groups[s]; });
    Object.keys(groups).forEach(function (s) { if (order.indexOf(s) < 0) order.push(s); });

    var frag = document.createDocumentFragment();
    order.forEach(function (sec) {
      if (sec !== 'Обзор') {
        var h = document.createElement('div');
        h.className = 'nav-section';
        h.textContent = sec;
        frag.appendChild(h);
      }
      groups[sec].forEach(function (a) { frag.appendChild(a); });
    });
    nav.innerHTML = '';
    nav.appendChild(frag);
    nav.dataset.dsDone = '1';
  }

  function mountSkipLink() {
    if (document.getElementById('dsSkip')) return;
    var main = document.querySelector('main') || document.querySelector('.main');
    if (!main) return;
    if (!main.id) main.id = 'dsMain';
    main.setAttribute('tabindex', '-1');
    var a = document.createElement('a');
    a.id = 'dsSkip';
    a.className = 'ds-skip';
    a.href = '#' + main.id;
    a.textContent = 'Перейти к содержимому';
    a.addEventListener('click', function () {
      setTimeout(function () { main.focus(); }, 0);
    });
    document.body.insertBefore(a, document.body.firstChild);
  }

  var SIDE_KEY = 'soc_side';
  function applySide() {
    var app = document.querySelector('.app');
    if (!app) return;
    var collapsed = false;
    try { collapsed = localStorage.getItem(SIDE_KEY) === '1'; } catch (x) {}
    app.classList.toggle('side-collapsed', collapsed);
    app.classList.toggle('side-expanded', !collapsed);
    var b = document.getElementById('dsCollapse');
    if (b) {
      b.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
      b.title = L(collapsed ? 'Развернуть меню' : 'Свернуть меню');
      b.setAttribute('aria-label', b.title);
    }
  }
  function mountUserMenu() {
    var foot = document.querySelector('.side-foot');
    if (!foot || document.getElementById('dsUser')) return;
    var who = foot.querySelector('.who');
    var name = who ? (who.textContent || '').trim() : '';
    var out = foot.querySelector('a[href="/logout"]');
    var href = out ? out.getAttribute('href') : '/logout';
    foot.innerHTML = '';
    var b = el('button', 'ui-button ds-user', {
      id: 'dsUser', type: 'button', 'aria-haspopup': 'menu',
      'aria-expanded': 'false', 'data-variant': 'ghost'
    });
    b.innerHTML = icon('users') + '<span class="ds-user-name">' + esc(name) + '</span>' +
                  icon('chevr', 'ds-user-chev');
    b.title = name;
    b.onclick = function () {
      var lang = (window.socLang ? window.socLang() : 'ru');
      dropdown(b, [
        { label: name },
        { separator: true },
        { label: L(THEME_META[currentTheme()].title),
          icon: THEME_META[currentTheme()].icon, run: toggleTheme },
        { label: lang === 'en' ? 'Русский' : 'English', icon: 'lang',
          run: function () {
            if (window.socSetLang) window.socSetLang(lang === 'en' ? 'ru' : 'en');
          } },
        { separator: true },
        { label: L('Выйти'), icon: 'logout', variant: 'destructive',
          run: function () { location.href = href; } }
      ]);
    };
    foot.appendChild(b);
  }

  function mountCollapse() {
    var side = document.querySelector('.side');
    if (!side || document.getElementById('dsCollapse')) return;
    var b = document.createElement('button');
    b.id = 'dsCollapse';
    b.className = 'ds-collapse';
    b.type = 'button';
    b.innerHTML = svg('m15 18-6-6 6-6') + '<span>' + L('Свернуть меню') + '</span>';
    b.onclick = function () {
      var app = document.querySelector('.app');
      var now = app && app.classList.contains('side-collapsed');
      try { localStorage.setItem(SIDE_KEY, now ? '0' : '1'); } catch (x) {}
      applySide();
    };
    side.appendChild(b);
    applySide();
  }

  var scrollBound = false;
  function readScroll() {
    var bar = document.querySelector('.topbar') || document.querySelector('.main > .top');
    if (!bar) return;
    var host = bar.closest('.main');
    var y = host ? host.scrollTop : (window.scrollY || document.documentElement.scrollTop || 0);
    bar.classList.toggle('is-scrolled', y > 4);
  }
  function watchScroll() {
    if (scrollBound) { readScroll(); return; }
    scrollBound = true;

    document.addEventListener('scroll', readScroll, { passive: true, capture: true });
    window.addEventListener('scroll', readScroll, { passive: true });
    readScroll();
  }

  function mountTopbar() {

    var host = document.querySelector('.topbar') ||
               document.querySelector('.main > .top') ||
               document.querySelector('.content > .top') ||
               document.querySelector('.top');
    if (!host || document.getElementById('dsTheme')) return;
    var box = document.createElement('div');
    box.className = 'ds-shell-actions';
    box.style.cssText = 'display:inline-flex;gap:6px;align-items:center;margin-left:10px;vertical-align:middle';

    if (!document.getElementById('dsSearch')) {
      var sb = document.createElement('div');
      sb.className = 'ds-topsearch';
      sb.innerHTML = svg(I.search) +
        '<input id="dsSearch" type="search" autocomplete="off" ' +
        'aria-label="Поиск по разделам и командам" ' +
        'placeholder="Поиск"><kbd class="ds-topsearch-k">Ctrl K</kbd>';
      var h1 = host.querySelector('h1');
      if (h1 && h1.nextSibling) host.insertBefore(sb, h1.nextSibling);
      else host.appendChild(sb);
      var si = sb.querySelector('input');
      si.addEventListener('focus', function () { openCmdk(); si.blur(); });
    }

    var lang = (window.socLang ? window.socLang() : 'ru');
    box.innerHTML =
      '<button class="ui-button" data-variant="ghost" data-size="icon-sm" id="dsTheme" ' +
      'type="button" aria-label="' + L('Тема оформления') + '"></button>';
    host.appendChild(box);
    document.getElementById('dsTheme').onclick = toggleTheme;
    applyTheme(document.documentElement.getAttribute('data-theme'));
  }

  var cmdk, cmdkInput, cmdkList, cmdItems = [], cmdSel = 0;
  function buildCommands() {
    var out = [];
    document.querySelectorAll('.nav a').forEach(function (a) {
      var key = a.getAttribute('data-v') || a.getAttribute('data-view');
      if (!key) return;
      var m = MAP[key] || {};
      out.push({
        group: 'Разделы', label: (a.textContent || key).trim(),
        icon: m.i || I.grid, run: function () { a.click(); }
      });
    });
    out.push({ group: 'Тема', label: 'Тёмная тема',  icon: I.moon,   run: function () { setTheme('dark'); } });
    out.push({ group: 'Тема', label: 'Светлая тема', icon: I.sun,    run: function () { setTheme('light'); } });
    var other = location.port === '8788' ? 'http://127.0.0.1:8787/' : 'http://127.0.0.1:8788/';
    out.push({
      group: 'Действия', label: 'Открыть вторую консоль',
      icon: I.shield, run: function () { window.open(other, '_blank'); }
    });
    return out;
  }
  function renderCmdk(q) {
    q = (q || '').toLowerCase().trim();
    var all = buildCommands();
    cmdItems = q ? all.filter(function (c) { return c.label.toLowerCase().indexOf(q) >= 0; }) : all;
    cmdSel = 0;
    var html = '', group = null;
    cmdItems.forEach(function (c, i) {
      if (c.group !== group) { group = c.group; html += '<div class="ds-cmdk-group">' + group + '</div>'; }
      html += '<div class="ds-cmdk-item' + (i === 0 ? ' on' : '') + '" data-i="' + i + '">' +
              svg(c.icon) + '<span>' + c.label + '</span></div>';
    });
    cmdkList.innerHTML = html || '<div class="ds-cmdk-group">ничего не найдено</div>';
    cmdkList.querySelectorAll('.ds-cmdk-item').forEach(function (el) {
      el.onclick = function () { runCmd(+el.dataset.i); };
    });
  }
  function runCmd(i) {
    var c = cmdItems[i];
    closeCmdk();
    if (c && c.run) setTimeout(c.run, 40);
  }
  function moveCmd(d) {
    if (!cmdItems.length) return;
    cmdSel = (cmdSel + d + cmdItems.length) % cmdItems.length;
    cmdkList.querySelectorAll('.ds-cmdk-item').forEach(function (el, i) {
      el.classList.toggle('on', i === cmdSel);
      if (i === cmdSel && el.scrollIntoView) el.scrollIntoView({ block: 'nearest' });
    });
  }
  function openCmdk() {
    if (!cmdk) return;
    document.getElementById('dsOverlay').classList.add('open');
    cmdk.classList.add('open');
    cmdkInput.value = '';
    renderCmdk('');
    cmdkInput.focus();
  }
  function closeCmdk() {
    if (!cmdk) return;
    cmdk.classList.remove('open');
    document.getElementById('dsOverlay').classList.remove('open');
  }
  function mountCmdk() {
    if (document.getElementById('dsCmdk')) return;
    var ov = document.createElement('div');
    ov.className = 'ds-overlay'; ov.id = 'dsOverlay';
    ov.onclick = function(){ closeCmdk(); closeDrawer(); };
    document.body.appendChild(ov);

    cmdk = document.createElement('div');
    cmdk.className = 'ds-cmdk'; cmdk.id = 'dsCmdk';
    cmdk.innerHTML = '<input id="dsCmdkIn" placeholder="Поиск по разделам и командам…" autocomplete="off">' +
                     '<div class="ds-cmdk-list" id="dsCmdkList"></div>';
    document.body.appendChild(cmdk);
    cmdkInput = document.getElementById('dsCmdkIn');
    cmdkList = document.getElementById('dsCmdkList');
    cmdkInput.oninput = function () { renderCmdk(cmdkInput.value); };
    cmdkInput.onkeydown = function (e) {
      if (e.key === 'ArrowDown') { e.preventDefault(); moveCmd(1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); moveCmd(-1); }
      else if (e.key === 'Enter') { e.preventDefault(); runCmd(cmdSel); }
      else if (e.key === 'Escape') { closeCmdk(); }
    };
  }

  var drawer;
  function mountDrawer() {
    if (document.getElementById('dsDrawer')) return;
    drawer = document.createElement('aside');
    drawer.className = 'ds-drawer';
    drawer.id = 'dsDrawer';
    drawer.innerHTML =
      '<div class="ds-drawer-head"><div class="t-h2" id="dsDrawerTitle"></div>' +
      '<span style="flex:1"></span>' +
      '<button class="btn ghost" id="dsDrawerX" style="padding:5px 10px">' + L('Закрыть') + '</button></div>' +
      '<div class="ds-drawer-body" id="dsDrawerBody"></div>';
    document.body.appendChild(drawer);
    document.getElementById('dsDrawerX').onclick = closeDrawer;
  }
  function openDrawer(title, html) {
    mountDrawer();
    document.getElementById('dsDrawerTitle').innerHTML = title || '';
    document.getElementById('dsDrawerBody').innerHTML = html || '';
    document.getElementById('dsOverlay').classList.add('open');
    drawer.classList.add('open');
  }
  function closeDrawer() {
    if (!drawer) return;
    drawer.classList.remove('open');
    var ov = document.getElementById('dsOverlay');
    if (ov && !(cmdk && cmdk.classList.contains('open'))) ov.classList.remove('open');
  }
  window.dsDrawer = openDrawer;
  window.dsDrawerClose = closeDrawer;
  window.setTheme = setTheme;
  window.toggleTheme = toggleTheme;

  function toast(msg, type, ms) {
    var host = document.getElementById('dsToasts');
    if (!host) {
      host = document.createElement('div');
      host.className = 'ds-toasts'; host.id = 'dsToasts';

      host.setAttribute('role', 'status');
      host.setAttribute('aria-live', 'polite');
      host.setAttribute('aria-atomic', 'false');
      document.body.appendChild(host);
    }

    host.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite');
    var el = document.createElement('div');
    el.className = 'ds-toast ' + (type || 'info');
    el.textContent = msg;
    host.appendChild(el);
    setTimeout(function () {
      el.style.transition = 'opacity .2s';
      el.style.opacity = '0';
      setTimeout(function () { el.remove(); }, 220);
    }, ms || 3200);
  }
  window.toast = toast;

  var EXTRA_ICONS = {
    check:   'M20 6 9 17l-5-5',
    x:       'M18 6 6 18M6 6l12 12',
    chevd:   'm6 9 6 6 6-6',
    chevr:   'm9 18 6-6-6-6',
    info:    'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 16v-4M12 8h.01',
    warn:    'M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01',
    trash:   'M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v6M14 11v6',
    plus:    'M12 5v14M5 12h14',
    copy:    'M9 9h10v10H9zM5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1',
    filter:  'M3 4h18l-7 8v6l-4 2v-8z',
    refresh: 'M3 12a9 9 0 0 1 15-6.7L21 8M21 12a9 9 0 0 1-15 6.7L3 16M21 3v5h-5M3 21v-5h5',
    lang:    'M5 8h10M9 4v4M11 16c-2.5-1-4.5-3.5-5-8M8 16c3-1 5-4 5-8M13 21l4-9 4 9M14.7 18h4.6',
    logout:  'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9'
  };
  Object.keys(EXTRA_ICONS).forEach(function (k) { if (!I[k]) I[k] = EXTRA_ICONS[k]; });

  function icon(name, cls) { return I[name] ? svg(I[name], cls) : ''; }

  function esc(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
  function attrs(o) {
    var out = '';
    Object.keys(o || {}).forEach(function (k) {
      var v = o[k];
      if (v == null || v === false || v === '') return;
      out += ' ' + k + (v === true ? '' : '="' + esc(v) + '"');
    });
    return out;
  }
  function el(tag, cls, opts) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    Object.keys(opts || {}).forEach(function (k) {
      if (k === 'text') n.textContent = opts[k];
      else if (k === 'html') n.innerHTML = opts[k];
      else if (opts[k] != null && opts[k] !== false) n.setAttribute(k, opts[k]);
    });
    return n;
  }

  /* Компоненты доступны и строками: разметка списков собирается в JS. */
  var UI = {
    icon: icon,
    button: function (o) {
      o = o || {};
      return '<button class="ui-button" type="' + (o.type || 'button') + '"' +
        attrs({ 'data-variant': o.variant, 'data-size': o.size, id: o.id,
                onclick: o.onclick, title: o.title, 'aria-label': o.ariaLabel,
                disabled: o.disabled }) + '>' +
        (o.icon ? icon(o.icon) : '') + (o.label ? esc(o.label) : '') + '</button>';
    },
    badge: function (text, variant, o) {
      o = o || {};
      return '<span class="ui-badge"' +
        attrs({ 'data-variant': variant, 'data-underline': o.underline,
                title: o.title }) + '>' + esc(text) + '</span>';
    },
    label: function (text) { return '<span class="ui-label">' + esc(text) + '</span>'; },
    separator: function (orientation) {
      return '<div class="ui-separator" role="separator" data-orientation="' +
        (orientation || 'horizontal') + '"></div>';
    },
    skeleton: function (w, h) {
      return '<div class="ui-skeleton" aria-hidden="true" style="width:' +
        (w || '100%') + ';height:' + (h || '12px') + '"></div>';
    },
    spinner: function () { return '<span class="ui-spinner" aria-hidden="true"></span>'; },
    empty: function (o) {
      o = o || {};
      return '<div class="ui-empty">' +
        (o.icon ? '<div class="ui-empty-media">' + icon(o.icon) + '</div>' : '') +
        (o.title ? '<div class="ui-empty-title">' + esc(o.title) + '</div>' : '') +
        (o.description ? '<div class="ui-empty-description">' + esc(o.description) + '</div>' : '') +
        (o.action ? '<div class="ui-empty-content">' + o.action + '</div>' : '') +
        '</div>';
    },
    alert: function (o) {
      o = o || {};
      var ic = o.variant === 'destructive' ? 'warn'
             : o.variant === 'warning' ? 'warn' : 'info';
      return '<div class="ui-alert" role="' +
        (o.variant === 'destructive' ? 'alert' : 'status') + '"' +
        attrs({ 'data-variant': o.variant }) + '>' + icon(ic) +
        '<div class="ui-alert-description">' +
        (o.title ? '<span class="ui-alert-title">' + esc(o.title) + '</span> ' : '') +
        (o.description || '') + '</div></div>';
    },
    card: function (o) {
      o = o || {};
      return '<section class="ui-card"' + attrs({ id: o.id }) + '>' +
        (o.title ? '<header class="ui-card-header">' +
          '<h2 class="ui-card-title">' + esc(o.title) + '</h2>' +
          (o.description ? '<span class="ui-card-description">' + esc(o.description) + '</span>' : '') +
          (o.action ? '<div class="ui-card-action">' + o.action + '</div>' : '') +
        '</header>' : '') +
        '<div class="ui-card-content"' + (o.flush ? ' data-flush' : '') + '>' +
        (o.content || '') + '</div>' +
        (o.footer ? '<footer class="ui-card-footer">' + o.footer + '</footer>' : '') +
        '</section>';
    },
    field: function (o) {
      o = o || {};
      return '<div class="ui-field"' +
        attrs({ 'data-orientation': o.orientation, 'data-invalid': o.invalid,
                'data-disabled': o.disabled }) + '>' +
        '<label class="ui-field-label"' + attrs({ 'for': o.id }) + '>' + esc(o.label) + '</label>' +
        (o.control || '') +
        (o.description ? '<span class="ui-field-description">' + esc(o.description) + '</span>' : '') +
        (o.error ? '<span class="ui-field-error">' + esc(o.error) + '</span>' : '') +
        '</div>';
    },
    input: function (o) {
      o = o || {};
      return '<input class="ui-input"' +
        attrs({ id: o.id, type: o.type || 'text', value: o.value,
                placeholder: o.placeholder, 'aria-invalid': o.invalid ? 'true' : null,
                disabled: o.disabled, autocomplete: o.autocomplete || 'off' }) + '>';
    },
    checkbox: function (o) {
      o = o || {};
      return '<input class="ui-checkbox" type="checkbox"' +
        attrs({ id: o.id, checked: o.checked, disabled: o.disabled }) + '>';
    },
    toggleGroup: function (items, active) {
      return '<div class="ui-toggle-group" role="group">' + (items || []).map(function (it) {
        return '<button class="ui-toggle" type="button"' +
          attrs({ 'data-value': it.value, onclick: it.onclick,
                  'aria-pressed': String(it.value === active) }) + '>' +
          esc(it.label) + '</button>';
      }).join('') + '</div>';
    }
  };

  /* Esc закрывает, фокус возвращается на триггер, стрелки водят по пунктам. */
  var openMenu = null, openMenuTrigger = null;

  function menuClose() {
    if (!openMenu) return;
    openMenu.removeAttribute('data-state');
    if (openMenuTrigger) {
      openMenuTrigger.setAttribute('aria-expanded', 'false');
      openMenuTrigger.focus();
    }
    openMenu.remove();
    openMenu = null; openMenuTrigger = null;
  }

  function dropdown(trigger, items) {
    if (!trigger) return;
    menuClose();
    var m = el('div', 'ui-menu', { role: 'menu', tabindex: '-1' });
    m.innerHTML = (items || []).map(function (it) {
      if (it.separator) return '<div class="ui-menu-separator" role="separator"></div>';
      if (it.label && !it.run) return '<div class="ui-menu-label">' + esc(it.label) + '</div>';
      return '<button class="ui-menu-item" type="button" role="menuitem"' +
        attrs({ 'data-variant': it.variant, 'aria-disabled': it.disabled ? 'true' : null }) +
        '>' + (it.icon ? icon(it.icon) : '') + '<span>' + esc(it.label) + '</span></button>';
    }).join('');
    document.body.appendChild(m);

    var r = trigger.getBoundingClientRect();
    m.setAttribute('data-state', 'open');
    var w = m.offsetWidth, h = m.offsetHeight;
    m.style.left = Math.max(8, Math.min(r.left, window.innerWidth - w - 8)) + 'px';
    m.style.top = (r.bottom + h + 8 > window.innerHeight ? Math.max(8, r.top - h - 4)
                                                         : r.bottom + 4) + 'px';

    var opts = Array.prototype.slice.call(m.querySelectorAll('.ui-menu-item'));
    var runnable = (items || []).filter(function (it) { return it.run || (!it.separator && !(it.label && !it.run)); });
    opts.forEach(function (b, i) {
      b.onclick = function () {
        var it = runnable[i];
        menuClose();
        if (it && it.run) setTimeout(it.run, 0);
      };
    });
    var sel = -1;
    function move(d) {
      if (!opts.length) return;
      sel = (sel + d + opts.length) % opts.length;
      opts.forEach(function (b, i) { b.toggleAttribute('data-highlighted', i === sel); });
      opts[sel].focus();
    }
    m.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown') { e.preventDefault(); move(1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
      else if (e.key === 'Escape') { e.preventDefault(); menuClose(); }
      else if (e.key === 'Tab') menuClose();
    });
    trigger.setAttribute('aria-expanded', 'true');
    trigger.setAttribute('aria-haspopup', 'menu');
    openMenu = m; openMenuTrigger = trigger;
    m.focus();
  }
  document.addEventListener('click', function (e) {
    if (!openMenu) return;
    if (openMenu.contains(e.target) || (openMenuTrigger && openMenuTrigger.contains(e.target))) return;
    menuClose();
  }, true);

  var openDialog = null, dialogReturn = null;

  function dialogClose() {
    if (!openDialog) return;
    openDialog.removeAttribute('data-state');
    var ov = document.getElementById('dsOverlay');
    if (ov && !(cmdk && cmdk.classList.contains('open'))) ov.classList.remove('open');
    openDialog.remove();
    openDialog = null;
    if (dialogReturn && dialogReturn.focus) dialogReturn.focus();
    dialogReturn = null;
  }

  function dialog(o) {
    o = o || {};
    dialogClose();
    dialogReturn = document.activeElement;
    var d = el('div', 'ui-dialog', {
      role: 'dialog', 'aria-modal': 'true', tabindex: '-1',
      'aria-labelledby': 'uiDialogTitle'
    });
    d.innerHTML =
      '<header class="ui-dialog-header">' +
        '<h2 class="ui-dialog-title" id="uiDialogTitle">' + esc(o.title || '') + '</h2>' +
        (o.description ? '<span class="ui-dialog-description">' + esc(o.description) + '</span>' : '') +
        '<div class="ui-dialog-close">' +
          UI.button({ variant: 'ghost', size: 'icon-sm', icon: 'x',
                      ariaLabel: L('Закрыть') }) +
        '</div>' +
      '</header>' +
      '<div class="ui-dialog-body">' + (o.body || '') + '</div>' +
      (o.footer ? '<footer class="ui-dialog-footer">' + o.footer + '</footer>' : '');
    document.body.appendChild(d);
    mountCmdk();
    document.getElementById('dsOverlay').classList.add('open');
    d.setAttribute('data-state', 'open');
    d.querySelector('.ui-dialog-close .ui-button').onclick = dialogClose;

    d.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { e.preventDefault(); dialogClose(); return; }
      if (e.key !== 'Tab') return;
      var f = d.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),' +
                                 'select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])');
      if (!f.length) return;
      var first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
    openDialog = d;
    d.focus();
    return d;
  }

  var tipEl = null, tipTimer = 0;
  function tipHide() {
    if (tipTimer) { clearTimeout(tipTimer); tipTimer = 0; }
    if (tipEl) { tipEl.removeAttribute('data-state'); tipEl.remove(); tipEl = null; }
  }
  function tipShow(host) {
    var text = host.getAttribute('data-tip');
    if (!text) return;
    tipHide();
    tipEl = el('div', 'ui-tooltip', { role: 'tooltip', text: text });
    document.body.appendChild(tipEl);
    var r = host.getBoundingClientRect(), w = tipEl.offsetWidth, h = tipEl.offsetHeight;
    tipEl.style.left = Math.max(8, Math.min(r.left + r.width / 2 - w / 2,
                                            window.innerWidth - w - 8)) + 'px';
    tipEl.style.top = (r.top - h - 6 < 8 ? r.bottom + 6 : r.top - h - 6) + 'px';
    tipEl.setAttribute('data-state', 'open');
  }
  function bindTooltips() {
    document.addEventListener('mouseover', function (e) {
      var host = e.target.closest && e.target.closest('[data-tip]');
      if (!host) return;
      tipTimer = setTimeout(function () { tipShow(host); }, 260);
    });
    document.addEventListener('mouseout', function (e) {
      if (e.target.closest && e.target.closest('[data-tip]')) tipHide();
    });
    document.addEventListener('focusin', function (e) {
      var host = e.target.closest && e.target.closest('[data-tip]');
      if (host) tipShow(host);
    });
    document.addEventListener('focusout', tipHide);
  }

  /* Разметка: data-ui="tabs", триггеры data-tab, панели data-panel. */
  function bindTabs(root) {
    var scope = root && root.querySelectorAll ? root : document;
    scope.querySelectorAll('[data-ui="tabs"]').forEach(function (box) {
      if (box.dataset.uiBound) return;
      box.dataset.uiBound = '1';
      var trg = Array.prototype.slice.call(box.querySelectorAll('[data-tab]'));
      if (!trg.length) return;
      var list = trg[0].parentElement;
      if (list) { list.setAttribute('role', 'tablist'); }
      function select(v) {
        trg.forEach(function (t) {
          var on = t.getAttribute('data-tab') === v;
          t.setAttribute('role', 'tab');
          t.setAttribute('aria-selected', String(on));
          t.setAttribute('tabindex', on ? '0' : '-1');
          t.setAttribute('data-state', on ? 'active' : 'inactive');
        });
        box.querySelectorAll('[data-panel]').forEach(function (p) {
          var on = p.getAttribute('data-panel') === v;
          p.setAttribute('role', 'tabpanel');
          p.hidden = !on;
        });
      }
      trg.forEach(function (t, i) {
        t.addEventListener('click', function () { select(t.getAttribute('data-tab')); });
        t.addEventListener('keydown', function (e) {
          var d = e.key === 'ArrowRight' ? 1 : (e.key === 'ArrowLeft' ? -1 : 0);
          if (!d) return;
          e.preventDefault();
          var n = trg[(i + d + trg.length) % trg.length];
          select(n.getAttribute('data-tab'));
          n.focus();
        });
      });
      var init = box.querySelector('[data-tab][data-state="active"]') || trg[0];
      select(init.getAttribute('data-tab'));
    });
  }

  UI.confirm = function (o) {
    o = o || {};
    var okId = 'uiConfirmOk', cancelId = 'uiConfirmCancel';
    var body = (o.description ? '<p class="ui-dialog-description">' +
                  esc(o.description).replace(/\n/g, '<br>') + '</p>' : '') +
               (o.requireWord
                  ? UI.field({ id: 'uiConfirmWord', label: o.requireLabel || o.requireWord,
                               control: UI.input({ id: 'uiConfirmWord',
                                                   placeholder: o.requireWord }) })
                  : '');
    var d = dialog({
      title: o.title || L('Подтвердите действие'),
      body: body,
      footer:
        UI.button({ variant: 'ghost', label: o.cancelLabel || L('Отмена'), id: cancelId }) +
        UI.button({ variant: o.variant || 'destructive',
                    label: o.confirmLabel || L('Подтвердить'), id: okId })
    });
    var ok = document.getElementById(okId);
    var word = document.getElementById('uiConfirmWord');
    if (word) {
      ok.disabled = true;
      word.addEventListener('input', function () {
        ok.disabled = word.value.trim() !== o.requireWord;
      });
      word.focus();
    }
    document.getElementById(cancelId).onclick = function () {
      dialogClose();
      if (o.onCancel) o.onCancel();
    };
    ok.onclick = function () {
      var v = word ? word.value.trim() : null;
      dialogClose();
      if (o.onConfirm) o.onConfirm(v);
    };
    return d;
  };
  UI.dropdown = dropdown;
  UI.menuClose = menuClose;
  UI.dialog = dialog;
  UI.dialogClose = dialogClose;
  UI.tabs = bindTabs;
  UI.el = el;
  UI.esc = esc;
  window.UI = UI;
  window.dsIcon = icon;


  document.addEventListener('keydown', function (e) {
    var tag = (e.target && e.target.tagName || '').toLowerCase();
    var typing = tag === 'input' || tag === 'textarea' || tag === 'select';
    if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      cmdk && cmdk.classList.contains('open') ? closeCmdk() : openCmdk();
      return;
    }
    if (e.key === 'Escape') { closeCmdk(); closeDrawer(); menuClose(); dialogClose(); }
    if (typing) return;
    if (e.key === '/') { e.preventDefault(); openCmdk(); }
  });

  var NATIVE = { A: 1, BUTTON: 1, INPUT: 1, SELECT: 1, TEXTAREA: 1, SUMMARY: 1, LABEL: 1 };
  function stampFocusable(root) {
    var scope = root && root.querySelectorAll ? root : document;

    var list = Array.prototype.slice.call(scope.querySelectorAll('[onclick]'));
    if (scope.nodeType === 1 && scope.hasAttribute && scope.hasAttribute('onclick')) {
      list.unshift(scope);
    }
    list.forEach(function (el) {
      if (NATIVE[el.tagName]) return;
      if (el.hasAttribute('tabindex')) return;
      if (el.closest('thead')) return;
      var p = el.parentElement && el.parentElement.closest('[onclick]');
      if (p) return;
      el.setAttribute('tabindex', '0');

      if (el.tagName === 'TR' || el.tagName === 'TD' || el.tagName === 'TH') return;
      if (!el.getAttribute('role')) el.setAttribute('role', 'button');
    });
  }
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter' && e.key !== ' ' && e.key !== 'Spacebar') return;
    var el = e.target;
    if (!el || !el.getAttribute) return;
    if (NATIVE[el.tagName]) return;
    if (!el.hasAttribute('onclick')) return;

    if (e.key !== 'Enter' && el.scrollHeight > el.clientHeight + 2) return;
    e.preventDefault();
    el.click();
  });

  var shellQueued = false;
  function ensureShell() {
    mountSkipLink(); mountTopbar(); enhanceNav(); mountCollapse();
    mountUserMenu(); watchScroll();
  }
  function queueShell() {
    if (shellQueued) return;
    shellQueued = true;
    var run = function () { shellQueued = false; ensureShell(); };
    if (window.requestAnimationFrame) requestAnimationFrame(run);
    else setTimeout(run, 16);
  }
  function boot() {
    initTheme();
    mountCmdk();
    mountDrawer();
    ensureShell();
    stampFocusable(document);
    bindTooltips();
    bindTabs(document);
    if (window.MutationObserver) {
      new MutationObserver(function (recs) {
        var shell = false;
        for (var i = 0; i < recs.length; i++) {
          var t = recs[i].target;

          if (t && t.closest && (t.closest('.top,.topbar,.nav,.side'))) shell = true;
          var added = recs[i].addedNodes;
          for (var j = 0; j < added.length; j++) {
            if (added[j].nodeType === 1) { stampFocusable(added[j]); bindTabs(added[j]); }
          }
        }
        if (shell) queueShell();
      }).observe(document.body, { childList: true, subtree: true });
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  setInterval(ensureShell, 10000);
})();
