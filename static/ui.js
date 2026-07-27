/* ============================================================
   SENTINEL UI — слой оболочки Enterprise Security Platform.
   Подключается обеими консолями. Ничего не знает о бэкенде:
   работает только с уже отрендеренной разметкой.

   Даёт: переключатель темы, Command Palette (Ctrl+K), тосты,
   иконки и секции в навигации, Drawer, счётчики-одометры.
   ============================================================ */
(function () {
  'use strict';

  // Строка оболочки, задаваемая в рантайме (title/aria-label): если включён
  // EN, переводим через словарь i18n, иначе оставляем русской.
  function L(s) { return (window.socT ? window.socT(s) : s); }

  /* ---------- иконки (Lucide-стиль, отрисованы здесь) ---------- */
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

  /* ---------- карта разделов: иконка + секция ---------- */
  var MAP = {
    // консоль защиты (data-v)
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
    // консоль среды (data-view)
    config:    { i: I.slider, s: 'Система' },
    logs:      { i: I.term,   s: 'Среда' },
    data:      { i: I.db,     s: 'Данные' },
    repos:     { i: I.folder, s: 'Среда' },
    insights:  { i: I.chart,  s: 'Данные' },
    people:    { i: I.users,  s: 'Среда' }
  };

  /* ---------- 1. ТЕМА: тёмная → светлая → яркая ---------- */
  var THEME_KEY = 'soc_theme';
  var THEMES = ['dark', 'light', 'bright'];
  var THEME_META = {
    dark:   { icon: 'sun',    title: 'Тема: тёмная — нажмите для светлой' },
    light:  { icon: 'bright', title: 'Тема: светлая — нажмите для яркой' },
    bright: { icon: 'moon',   title: 'Тема: яркая — нажмите для тёмной' }
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
    }
  }
  function initTheme() {
    var saved = 'dark';
    try { saved = localStorage.getItem(THEME_KEY) || 'dark'; } catch (e) {}
    applyTheme(saved);
  }
  function toggleTheme() {
    var next = THEMES[(THEMES.indexOf(currentTheme()) + 1) % THEMES.length];
    try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
    applyTheme(next);
    if (window.toast) window.toast('Тема: ' + ({dark:'тёмная',light:'светлая',bright:'яркая'})[next], 'info', 1600);
  }
  function setTheme(t) {
    try { localStorage.setItem(THEME_KEY, t); } catch (e) {}
    applyTheme(t);
  }

  /* ---------- 2. НАВИГАЦИЯ: иконки + секции ---------- */
  var SECTION_ORDER = ['Обзор', 'SOC', 'Purple Team', 'Аналитика', 'Среда', 'Данные', 'Система'];
  function enhanceNav() {
    var nav = document.querySelector('.nav');
    if (!nav || nav.dataset.dsDone) return;
    var links = Array.prototype.slice.call(nav.querySelectorAll('a'));
    if (!links.length) return;

    // 1) иконки
    links.forEach(function (a) {
      var key = a.getAttribute('data-v') || a.getAttribute('data-view');
      var m = MAP[key];
      if (m && !a.querySelector('svg')) a.insertAdjacentHTML('afterbegin', svg(m.i));
    });

    // 1b) клавиатура. Пункты меню — это <a> без href, поэтому браузер
    //     их не фокусирует и всей навигацией нельзя пользоваться с
    //     клавиатуры. Даём таб-стоп, роль и обработку Enter/Пробела.
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

    // 2) группировка: пункты в разметке идут вперемешку, поэтому
    //    переставляем их по секциям — иначе заголовки дублируются
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

  /* ---------- 2b. ССЫЛКА «К СОДЕРЖИМОМУ» ----------
     Первый таб-стоп на странице: позволяет перепрыгнуть навигацию
     и сразу попасть в основную область. Видна только при фокусе. */
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

  /* ---------- 2c. СВОРАЧИВАНИЕ САЙДБАРА ----------
     На ноутбуке 1366×768 меню занимает шестую часть ширины, а
     аналитику нужна таблица. Свёрнутый сайдбар оставляет иконки,
     подпись всплывает при наведении и при фокусе с клавиатуры. */
  var SIDE_KEY = 'soc_side';
  function applySide() {
    var app = document.querySelector('.app');
    if (!app) return;
    var collapsed = false;
    try { collapsed = localStorage.getItem(SIDE_KEY) === '1'; } catch (e) {}
    app.classList.toggle('side-collapsed', collapsed);
    app.classList.toggle('side-expanded', !collapsed);
    var b = document.getElementById('dsCollapse');
    if (b) {
      b.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
      b.title = L(collapsed ? 'Развернуть меню' : 'Свернуть меню');
      b.setAttribute('aria-label', b.title);
    }
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
      try { localStorage.setItem(SIDE_KEY, now ? '0' : '1'); } catch (e) {}
      applySide();
    };
    side.appendChild(b);
    applySide();
  }

  /* ---------- 2d. ТЕНЬ ВЕРХНЕЙ ПАНЕЛИ ПРИ ПРОКРУТКЕ ---------- */
  /* Слушатель вешается ОДИН раз на документ и сам находит панель при
     каждом срабатывании. Если вешать его на найденный элемент, то при
     перерисовке страницы на window копятся слушатели, держащие ссылки
     на уже удалённые узлы. */
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
    // capture: событие прокрутки не всплывает, но в фазе перехвата видно любое
    document.addEventListener('scroll', readScroll, { passive: true, capture: true });
    window.addEventListener('scroll', readScroll, { passive: true });
    readScroll();
  }

  /* ---------- 3. КНОПКИ ОБОЛОЧКИ в верхней панели ---------- */
  function mountTopbar() {
    // ВАЖНО: сначала .topbar. В консоли среды класс `.top` есть ещё и у
    // заголовков слайдеров в конфигурации — кнопки уезжали внутрь поля.
    var host = document.querySelector('.topbar') ||
               document.querySelector('.main > .top') ||
               document.querySelector('.content > .top') ||
               document.querySelector('.top');
    if (!host || document.getElementById('dsTheme')) return;
    var box = document.createElement('div');
    box.className = 'ds-shell-actions';
    box.style.cssText = 'display:inline-flex;gap:6px;align-items:center;margin-left:10px;vertical-align:middle';
    // поле поиска: по фокусу расширяется и открывает палитру команд
    if (!document.getElementById('dsSearch')) {
      var sb = document.createElement('div');
      sb.className = 'ds-topsearch';
      sb.innerHTML = svg(I.search) +
        '<input id="dsSearch" type="search" autocomplete="off" ' +
        'aria-label="Поиск по инцидентам, сущностям и правилам" ' +
        'placeholder="Поиск инцидентов, сущностей, правил или команда…">';
      var h1 = host.querySelector('h1');
      if (h1 && h1.nextSibling) host.insertBefore(sb, h1.nextSibling);
      else host.appendChild(sb);
      var si = sb.querySelector('input');
      si.addEventListener('focus', function () { openCmdk(); si.blur(); });
    }

    var lang = (window.socLang ? window.socLang() : 'ru');
    box.innerHTML =
      '<button class="btn ghost" id="dsCmd" aria-label="Поиск и команды" ' +
      'title="Поиск и команды (Ctrl+K)" style="padding:6px 10px">' +
      svg(I.search) + '<kbd>Ctrl K</kbd></button>' +
      '<button class="btn ghost" id="dsLang" style="padding:6px 9px;font-size:11px;font-weight:600" ' +
      'aria-label="Язык интерфейса" title="Язык интерфейса: ' +
      (lang === 'en' ? 'English — нажмите для русского' : 'русский — switch to English') + '">' +
      (lang === 'en' ? 'EN' : 'RU') + '</button>' +
      '<button class="btn ghost" id="dsTheme" aria-label="Тема оформления" style="padding:6px 9px"></button>';
    // ставим рядом со статус-пилюлями, если они есть
    var pills = host.querySelector('.pills') || host.querySelector('.hpills');
    (pills || host).appendChild(box);
    document.getElementById('dsTheme').onclick = toggleTheme;
    document.getElementById('dsCmd').onclick = openCmdk;
    document.getElementById('dsLang').onclick = function () {
      if (window.socSetLang) window.socSetLang(lang === 'en' ? 'ru' : 'en');
    };
    applyTheme(document.documentElement.getAttribute('data-theme'));
  }

  /* ---------- 4. COMMAND PALETTE ---------- */
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
    out.push({ group: 'Тема', label: 'Яркая тема',   icon: I.bright, run: function () { setTheme('bright'); } });
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

  /* ---------- 5. DRAWER (панель деталей справа) ---------- */
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

  /* ---------- 6. ТОСТЫ ---------- */
  function toast(msg, type, ms) {
    var host = document.getElementById('dsToasts');
    if (!host) {
      host = document.createElement('div');
      host.className = 'ds-toasts'; host.id = 'dsToasts';
      // объявляем сообщения скринридеру: ошибки перебивают чтение,
      // остальное дожидается паузы
      host.setAttribute('role', 'status');
      host.setAttribute('aria-live', 'polite');
      host.setAttribute('aria-atomic', 'false');
      document.body.appendChild(host);
    }
    // Ошибку читаем немедленно, но режим возвращаем обратно: иначе после
    // первой же ошибки скринридер начинает перебивать себя на каждом тосте.
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

  /* ---------- 6. ГОРЯЧИЕ КЛАВИШИ ---------- */
  document.addEventListener('keydown', function (e) {
    var tag = (e.target && e.target.tagName || '').toLowerCase();
    var typing = tag === 'input' || tag === 'textarea' || tag === 'select';
    if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      cmdk && cmdk.classList.contains('open') ? closeCmdk() : openCmdk();
      return;
    }
    if (e.key === 'Escape') { closeCmdk(); closeDrawer(); }
    if (typing) return;
    if (e.key === '/') { e.preventDefault(); openCmdk(); }
  });

  /* ---------- 7. СТАРТ + переживание перерисовок ---------- */
  function boot() {
    initTheme();
    mountSkipLink();
    mountCmdk();
    mountDrawer();
    mountTopbar();
    enhanceNav();
    mountCollapse();
    watchScroll();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
  // страницы перерисовывают шапку опросом — восстанавливаем оболочку
  setInterval(function () {
    mountSkipLink(); mountTopbar(); enhanceNav(); mountCollapse(); watchScroll();
  }, 1500);
})();
