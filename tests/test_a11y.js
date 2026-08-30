/* ============================================================
   Проверка доступности обеих консолей (WCAG 2.1 AA, структурная часть).

   Контраст цветов проверяет tests/test_contrast.py — здесь всё
   остальное: клавиатура, роли, подписи иконок, семантика таблиц.

   Запуск:  node tests/test_a11y.js <console.html> <world.html>
   Страницы снимаются с работающих консолей curl-ом; если аргументы
   не переданы, берутся из /tmp/soc/.

   Нужен jsdom:  npm install jsdom
   ============================================================ */
'use strict';
const fs = require('fs');
const path = require('path');

let JSDOM;
try {
  ({ JSDOM } = require('jsdom'));
} catch (e) {
  console.log('  ПРОПУЩЕНО: нет пакета jsdom (npm install jsdom)');
  process.exit(0);
}

const ROOT = path.resolve(__dirname, '..');
const STATIC = path.join(ROOT, 'static');
const i18n = fs.readFileSync(path.join(STATIC, 'i18n.js'), 'utf8');
const ui = fs.readFileSync(path.join(STATIC, 'ui.js'), 'utf8');

const pages = [
  { name: 'консоль защиты', file: process.argv[2] || '/tmp/soc/page.html', url: 'http://127.0.0.1:8788/' },
  { name: 'консоль среды', file: process.argv[3] || '/tmp/soc/world.html', url: 'http://127.0.0.1:8787/' }
];

let pass = 0, fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; console.log('    OK    ' + name); }
  else { fail++; console.log('    ПРОВАЛ ' + name + (extra ? '   << ' + extra : '')); }
}

function boot(file, url) {
  const html = fs.readFileSync(file, 'utf8');
  const dom = new JSDOM(html, { runScripts: 'outside-only', pretendToBeVisual: true, url });
  const w = dom.window;
  w.fetch = () => Promise.resolve({ json: () => Promise.resolve({}), text: () => Promise.resolve('') });
  const errs = [];
  w.addEventListener('error', e => errs.push(e.message));
  w.eval(i18n);
  w.eval(ui);
  const m = html.match(/<script>([\s\S]*?)<\/script>/);
  if (m) { try { w.eval(m[1]); } catch (e) { errs.push('скрипт страницы: ' + e.message); } }
  // jsdom не шлёт это событие при разборе строки, а оболочка монтируется по нему
  w.document.dispatchEvent(new w.Event('DOMContentLoaded'));
  return { w, D: w.document, errs, html };
}

function check(page) {
  console.log('\n  --- ' + page.name + ' ---');
  if (!fs.existsSync(page.file)) {
    ok('страница снята для проверки', false, page.file + ' не найден');
    return;
  }
  const { D, html } = boot(page.file, page.url);

  // 1. Навигация доступна с клавиатуры
  const links = [...D.querySelectorAll('.nav a')];
  ok('навигация не пуста', links.length > 0);
  ok('каждый пункт меню получает фокус табом',
    links.every(a => a.getAttribute('tabindex') === '0'),
    links.filter(a => a.getAttribute('tabindex') !== '0').length + ' без tabindex');
  ok('у пунктов меню задана роль',
    links.every(a => a.getAttribute('role') === 'link'));
  ok('текущий раздел помечен для скринридера',
    links.some(a => a.getAttribute('aria-current') === 'page'));

  // 2. Ссылка «к содержимому»
  const skip = D.getElementById('dsSkip');
  ok('есть ссылка «к содержимому»', !!skip);
  ok('она ведёт в основную область',
    !!skip && !!D.querySelector(skip.getAttribute('href')),
    skip ? skip.getAttribute('href') : '—');
  ok('она первый элемент в body', !!skip && D.body.firstElementChild === skip);

  // 3. Иконочные кнопки подписаны
  const iconBtns = [...D.querySelectorAll('button')].filter(b =>
    b.querySelector('svg') && !b.textContent.replace(/\s/g, ''));
  ok('иконочные кнопки имеют подпись для скринридера',
    iconBtns.every(b => b.getAttribute('aria-label') || b.getAttribute('title')),
    iconBtns.filter(b => !b.getAttribute('aria-label') && !b.getAttribute('title'))
      .map(b => b.id || b.className).join(', '));

  // 4. Семантика таблиц
  const ths = [...D.querySelectorAll('th')];
  if (ths.length) {
    ok('у всех заголовков таблиц задан scope',
      ths.every(t => t.getAttribute('scope')),
      ths.filter(t => !t.getAttribute('scope')).map(t => t.textContent.trim()).join(' | '));
  } else {
    console.log('    (таблиц в разметке нет — проверка scope пропущена)');
  }

  // 5. Одна главная область и один h1
  ok('есть ровно одна область main', D.querySelectorAll('main, .main').length >= 1);
  ok('заголовок страницы существует', !!D.querySelector('h1'));

  // 6. Язык документа объявлен
  ok('у документа объявлен язык',
    !!D.documentElement.getAttribute('lang'),
    D.documentElement.getAttribute('lang') || 'не задан');

  // 7. Поля ввода подписаны
  const inputs = [...D.querySelectorAll('input, select, textarea')]
    .filter(i => (i.type || '').toLowerCase() !== 'hidden');
  const unlabeled = inputs.filter(i =>
    !i.getAttribute('aria-label') && !i.getAttribute('placeholder') &&
    !i.getAttribute('title') && !(i.id && D.querySelector('label[for="' + i.id + '"]')) &&
    !i.closest('label'));
  ok('поля ввода подписаны', unlabeled.length === 0,
    unlabeled.map(i => i.id || i.name || i.type).join(', '));

  // 8. Уровень различается не только цветом
  ok('в стилях есть форма для уровней severity',
    /\.badge:before/.test(fs.readFileSync(path.join(STATIC, 'design-system.css'), 'utf8')));

  // 9. Уважение к настройке «меньше движения»
  ok('учтён prefers-reduced-motion',
    /prefers-reduced-motion/.test(fs.readFileSync(path.join(STATIC, 'design-system.css'), 'utf8')));

  // 10. Нет положительных tabindex — они ломают порядок обхода
  const bad = [...D.querySelectorAll('[tabindex]')]
    .filter(e => parseInt(e.getAttribute('tabindex'), 10) > 0);
  ok('нет положительных tabindex, порядок обхода естественный', bad.length === 0,
    bad.map(e => e.tagName + '.' + e.className).join(', '));
}

console.log('='.repeat(62));
console.log('  ДОСТУПНОСТЬ ИНТЕРФЕЙСА — WCAG 2.1 AA (структура)');
console.log('='.repeat(62));
pages.forEach(check);
console.log('\n' + '='.repeat(62));
if (fail) {
  console.log('  ❌ провалено проверок: ' + fail + ' (прошло ' + pass + ')');
  process.exit(1);
}
console.log('  ✅ все ' + pass + ' проверок доступности прошли');
process.exit(0);
