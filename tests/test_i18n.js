/* ============================================================
   Проверка переключателя языка (static/i18n.js).

   Ловит две вещи, на которые жаловались вживую:
     1) хвосты русского в EN-режиме на составных строках
        («1 детект · 1 тактика · риск 0.7»);
     2) мигание: перевод должен успевать до отрисовки кадра.

   Мигание проверяется так: эмулируем перерисовку контейнера (как
   это делает опрос страницы), ждём одну микрозадачу — ровно в ней
   срабатывает колбэк MutationObserver — и убеждаемся, что русского
   текста в узле уже нет. Если бы перевод был отложен через setTimeout
   (как было раньше), к этому моменту он бы ещё не применился.

   Нужен jsdom:  npm install jsdom
   ============================================================ */
'use strict';
const fs = require('fs');
const path = require('path');

let JSDOM;
try { ({ JSDOM } = require('jsdom')); }
catch (e) { console.log('  ПРОПУЩЕНО: нет пакета jsdom'); process.exit(0); }

const SRC = fs.readFileSync(path.join(__dirname, '..', 'static', 'i18n.js'), 'utf8');
let pass = 0, fail = 0;
const ok = (n, c, x) => { c ? pass++ : fail++; console.log((c ? '  OK  ' : '  FAIL') + '  ' + n + (c ? '' : '   << ' + (x || ''))); };

function bootEN() {
  const dom = new JSDOM('<!doctype html><html><body><main><div id=c></div></main></body></html>',
    { runScripts: 'outside-only', url: 'http://x/' });
  const w = dom.window;
  try { w.localStorage.setItem('soc_lang', 'en'); } catch (e) {}
  w.eval(SRC);
  w.document.dispatchEvent(new w.Event('DOMContentLoaded'));
  return w;
}

(async () => {
  const w = bootEN();
  const T = w.socT;

  console.log('=== сегментный перевод составных строк ===');
  const eq = (i, e) => ok(JSON.stringify(i) + ' → ' + JSON.stringify(e), T(i) === e, JSON.stringify(T(i)));
  eq('1 детект · 1 тактика · риск 0.7', '1 detection · 1 tactic · risk 0.7');
  eq('3 детекта · 1 тактика · риск 0.62', '3 detections · 1 tactic · risk 0.62');
  eq('5 детектов · 2 тактики · риск 0.6', '5 detections · 2 tactics · risk 0.6');
  eq('последние 48 детектов', 'last 48 detections');
  eq('пик 3 за 30 мин', 'peak 3 in 30 min');
  eq('AI-разбор инцидента #123 — оценка low', 'AI analysis of incident #123 — assessment low');
  eq('13 584 соб.', '13 584 ev.');
  eq('работает · 4м', 'running · 4m');

  console.log('\n=== причины срабатываний (продуктовый контент) ===');
  eq('Высокоэнтропийный секрет (без сигнатуры)', 'High-entropy secret (no signature)');
  eq('— Удаление файла (кандидат на массовое)', '— File deletion (mass-delete candidate)');

  console.log('\n=== данные не трогаем ===');
  eq('@maria.ivanova', '@maria.ivanova');
  eq('soc-infra', 'soc-infra');
  eq('2026-07-22 10:00', '2026-07-22 10:00');

  console.log('\n=== мигание: перевод до отрисовки ===');
  const c = w.document.getElementById('c');
  c.innerHTML = '<div class="ds-q-meta">1 детект · 1 тактика · риск 0.7</div>' +
                '<span class="ds-h-name">Приём событий</span>';
  await Promise.resolve(); await Promise.resolve();   // одна порция микрозадач
  ok('после микрозадачи русского текста в узле нет',
    !/детект|тактика|риск|Приём/.test(c.textContent), c.textContent);
  ok('перевод корректный', /1 detection · 1 tactic · risk 0.7/.test(c.textContent) && /Ingest/.test(c.textContent), c.textContent);

  // многократная перерисовка не копит слушателей и остаётся стабильной
  for (let i = 0; i < 6; i++) { c.innerHTML = '<div>2 алерта · риск 0.6</div>'; await Promise.resolve(); await Promise.resolve(); }
  ok('многократная перерисовка стабильна', /2 alerts · risk 0.6/.test(c.textContent), c.textContent);

  // лента: имя актора остаётся, причина переводится
  c.innerHTML = '<div><b>@alex.petrov</b> — Приватный ключ в коммите <span class=ds-feed-repo>soc-infra</span></div>';
  await Promise.resolve(); await Promise.resolve();
  ok('в ленте имя актора не тронуто', c.textContent.indexOf('@alex.petrov') >= 0);
  ok('в ленте причина переведена', c.textContent.indexOf('Private key in a commit') >= 0, c.textContent);

  console.log('\n' + (fail ? '  ❌ провалено: ' + fail + ' (прошло ' + pass + ')'
                            : '  ✅ все ' + pass + ' проверок языка прошли'));
  process.exit(fail ? 1 : 0);
})();
