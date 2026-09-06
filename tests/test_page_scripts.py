#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
СИНТАКСИС И ЖИЗНЕСПОСОБНОСТЬ СКРИПТОВ НА СТРАНИЦАХ.

Зачем понадобился отдельный тест. Смоук-тест маршрутов (`tests/test_routes.py`)
проверяет, что страница отдаётся с кодом 200. Этого недостаточно: страница может
прекрасно отдаваться и рендериться, а весь её JavaScript — не выполняться из-за
одной синтаксической ошибки. Снаружи это выглядит как «интерфейс работает, но
все числа — прочерки»: серверная разметка на месте, а данные никто не подгружает.

Ровно так и было. В панели среды стояла строка

    innerHTML = '... <span title="merge request'ы">MR ...'

Апостроф внутри строки, ограниченной одинарными кавычками, закрывает её раньше
времени. Скрипт целиком не парсился, `setInterval` не заводились, ни одного
запроса к `/api/*` браузер не делал. Дефект прожил в проекте с самого начала и
не был заметен ни по кодам ответов, ни по логам сервера — в них просто не было
запросов, а отсутствие запросов глазами не ловится.

Что проверяется:
  1. каждый инлайновый <script> на каждой странице разбирается как JavaScript;
  2. то же для файлов в static/*.js;
  3. страница доживает до конца выполнения: заводятся таймеры опроса и
     происходит хотя бы одно обращение к API.

Пункт 3 — главный: он отличает «код синтаксически верен» от «код работает».

Требует node. Без него набор помечается пропущенным.
Запуск: python tests/test_page_scripts.py
"""

# --- скрипт живёт в подпапке; движок проекта — в корне ---
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _p in (_ROOT, _os.path.join(_ROOT, "tools"), _os.path.join(_ROOT, "research")):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
_os.chdir(_ROOT)
del _os, _sys

import io
import os
import re
import sys
import glob
import json
import shutil
import tempfile
import subprocess

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

OK = "✅"; BAD = "❌"
fails = []

_SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.S | re.I)


def check(name, cond, detail=""):
    print(f"  {OK if cond else BAD} {name}")
    if not cond:
        fails.append(name)
        if detail:
            for line in str(detail).splitlines()[:8]:
                print(f"      {line}")


def _have_node():
    if not shutil.which("node"):
        return False
    try:
        subprocess.run(["node", "--version"], capture_output=True, timeout=15)
        return True
    except Exception:
        return False


def inline_scripts(html):
    """Инлайновые скрипты страницы (без src=), по порядку."""
    out = []
    for attrs, body in _SCRIPT_RE.findall(html):
        if "src=" in attrs.lower():
            continue
        if body.strip():
            out.append(body)
    return out


def node_check(code, label, tmp):
    """Разобрать код как JavaScript. Возвращает текст ошибки или None."""
    p = os.path.join(tmp, "chunk.js")
    with open(p, "w", encoding="utf-8") as f:
        f.write(code)
    r = subprocess.run(["node", "--check", p], capture_output=True, text=True, timeout=60)
    if r.returncode == 0:
        return None
    err = (r.stderr or "").strip().splitlines()
    # оставляем строку с местом ошибки и саму ошибку
    keep = [x for x in err if "SyntaxError" in x or ".js:" in x]
    return f"{label}: " + " | ".join(keep[:2] or err[:2])


def main():
    print("=" * 72)
    print("  СКРИПТЫ НА СТРАНИЦАХ: синтаксис и запуск")
    print("=" * 72)

    if not _have_node():
        print("  ПРОПУЩЕНО: в системе нет node — проверка скриптов не запускалась")
        print("  (поставить зависимости: npm install)")
        # Код 2 = «проверка не выполнялась». Ноль здесь означал бы
        # успех, и сводка run_tests.py показывала [PASS] на непроверенном.
        return 2

    tmp = tempfile.mkdtemp(prefix="soc-js-")
    pages = sorted(glob.glob(os.path.join("templates", "*", "*.html")))
    statics = sorted(glob.glob(os.path.join("static", "*.js")))
    print(f"  страниц: {len(pages)} | файлов static/*.js: {len(statics)}")
    print("-" * 72)

    # --- 1. инлайновые скрипты страниц ---
    errors, total = [], 0
    for p in pages:
        html = open(p, encoding="utf-8").read()
        for i, code in enumerate(inline_scripts(html)):
            total += 1
            e = node_check(code, f"{p} · скрипт #{i + 1}", tmp)
            if e:
                errors.append(e)
    check(f"все инлайновые скрипты разбираются ({total} шт.)", not errors,
          "\n".join(errors))

    # --- 2. файлы static/*.js ---
    s_err = []
    for p in statics:
        e = node_check(open(p, encoding="utf-8").read(), p, tmp)
        if e:
            s_err.append(e)
    check(f"все static/*.js разбираются ({len(statics)} шт.)", not s_err,
          "\n".join(s_err))

    # --- 3. страница доживает до опроса API ---
    # Синтаксическая корректность ещё не значит, что код доработал до конца:
    # исключение на середине так же оставит интерфейс без данных.
    runner = os.path.join(tmp, "run.js")
    with open(runner, "w", encoding="utf-8") as f:
        f.write(r"""
const fs = require('fs');
let JSDOM;
try { ({ JSDOM } = require('jsdom')); }
catch (e) { console.log(JSON.stringify({skipped: true})); process.exit(0); }

const [pagePath, staticDir] = process.argv.slice(2);
const html = fs.readFileSync(pagePath, 'utf8');
const dom = new JSDOM(html, { runScripts: 'outside-only', url: 'http://127.0.0.1/' });
const w = dom.window;

const calls = [];
const errors = [];

// ПРАВДОПОДОБНЫЕ ОТВЕТЫ API.
// Пустой {} прогоняет только ветки «данных нет» и пропускает ровно те
// места, где живут настоящие ошибки: расчёты процентов, выбор класса по
// порогу, форматирование чисел. Поэтому здесь ненулевые значения.
const NOW = '2026-08-10T12:34:56';
const ACTOR = 'pavel.morozov', REPO = 'threat-hunting';
const ev = (extra) => Object.assign({
  id: 1, ts_sim: NOW, ts: NOW, actor: ACTOR, action: 'push', project: REPO,
  path: 'rules/win/fix.yml', message: 'commit', is_anomaly: false
}, extra || {});
const alert = (r) => ({ id: 1, ts_sim: NOW, actor: ACTOR, project: REPO,
  technique: 'T1072', reason: 'Ручной прогон', risk: r, rule_id: 'deploy-tool-abuse',
  incident: 7, action: 'push', path: 'a.yml' });
const FIX = {
  '/api/status': { running: true, sprint: 4, rules: 80, total_runs: 2252,
    total_ok: 354, total_fail: 49, offhours_skipped: 1639, uptime: 3671,
    is_work: true, work_hours: '10:00-18:00', time_mode: '×48', timelapse: true,
    scale: 48, ff_offhours: true, offhours_mode: 'oncall', gitlab_dates: 'real',
    last_activity: 'docs_wiki', last_actor: ACTOR, last_project: REPO,
    sim_time: 'Mon 2026-08-10 12:34:56', real_time: '2026-08-10 00:34:56',
    gitlab_time: 'Sun, 09 Aug 2026 19:43:32 GMT', oncall: 'nikita.orlov', pto: 'никого',
    activities: { docs_wiki: 12, automation_script: 7, standup: 3 },
    events: { total: 3677, anomalies: 12, by_action: { push: 90, mr_open: 30 },
              last_age_s: 4, file: 'data/events.jsonl', run_id: 'run-1', size_bytes: 12345 },
    runlog: { warnings: 3, errors: 0 }, telegram: true,
    team: [{ username: ACTOR, name: 'Pavel Morozov', role: 'detection_engineer',
             oncall: true, pto: false, working: true,
             stats: { pushes: 13, mrs: 6, anomalies: 0, last_action: 'docs_wiki',
                      last_project: REPO } }] },
  '/api/workload_curve.json': (() => {
    // ДЕФЕКТ, РАДИ КОТОРОГО ЭТОТ МОК. pollWorkload вызывался, но выходил
    // на проверке `if(!pts.length)`: ответа в фикстурах не было. Весь
    // разбор кривой — расчёт рекомендации, сравнение с обходом, отрисовка
    // двух графиков — не выполнялся ни разу, и удалённая при рефакторинге
    // переменная доехала до пользователя, а не до теста.
    const T = [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95];
    const pt = (t, k) => ({
      threshold: t, per_day: 10.5 - k * 0.9,
      recall: 0.75 - k * 0.01, recall_ci: [0.70 - k * 0.01, 0.80 - k * 0.01],
      caught: 258 - k, episodes: 342, precision: 0.18 + k * 0.02 });
    return { capacity: 10, current_threshold: 0.6, episodes: 342,
             seeds: [1, 2, 3], sim_days: 46, built_at: '2026-08-11 18:09',
             points: T.map(pt), points_alt: T.map(pt) };
  })(),
  '/api/health': { world_alive: true, ollama: true, auto_triage: true,
    events: { total: 3677, last_age_s: 4 },
    defense: { running: true, processed: 409 },
    world: { running: true }, gitlab: { state: 'ok', errors: 0, ok: 100, by_op: [] },
    store_error: null },
  '/api/events': { stats: { total: 3677, anomalies: 12, file: 'data/events.jsonl',
      run_id: 'run-1', size_bytes: 12345, by_action: { push: 90, mr_open: 30 },
      by_anomaly: { offhours: 5 } },
    items: [ev(), ev({ is_anomaly: true, anomaly_type: 'offhours' })] },
  '/api/repos': { repos: { [REPO]: { total: 96, files: 20, pushes: 24, mr_open: 10,
      mr_merge: 10, mr_close: 1, tree: ['a.yml'], open_mrs: [], deleted_recent: [],
      recent: [ev()], anomalies: 1, events: 96 } } },
  '/api/insights': { heat: Array.from({ length: 7 }, () => Array(24).fill(3)),
    heat_anom: Array.from({ length: 7 }, () => Array(24).fill(0)) },
  '/api/actor': { summary: { total: 100, anomalies: 3, last_action: 'push',
      last_project: REPO }, feed: [ev()] },
  '/api/config': { TIMELAPSE_ENABLED: true, SIM_WORKDAY_REAL_MINUTES: 10,
    TIME_SCALE_OVERRIDE: 0, FAST_FORWARD_OFFHOURS: false, SIM_START: '',
    WORK_HOURS_START: 10, WORK_HOURS_END: 18, WORK_DAYS: [0, 1, 2, 3, 4],
    LUNCH_BREAK: { enabled: true, hour: 13, duration_min: 45 },
    OFF_HOURS_MODE: 'oncall', OFF_HOURS_ACTIVITY_PROBABILITY: 0.1,
    OFF_HOURS_POLL_SECONDS: 60, SCENARIO_INTERVAL: { min: 30, max: 120 },
    SPEED_MULTIPLIER: 1, MAX_OPEN_MRS: 8, SPRINT_DAYS: 14,
    PTO_PROBABILITY_PER_DAY: 0.02, GITLAB_URL: 'http://localhost',
    ADMIN_TOKEN: 'x', GITLAB_DATES: 'real', FEATURES: { mr: true },
    PROBS: { flaky: 0.1 }, ACTIVITY_WEIGHTS: { docs_wiki: 0.1 } },
  '/api/logs': { logs: [{ id: 1, t: '12:00:00', level: 'INFO', msg: 'ok' }] },
  '/api/stats': { store_events: 40572, processed: 451, alerts: 16, incidents: 8,
    campaigns_detected: 1, coverage_pct: 72, rules: 39, techniques_fired: 2,
    techniques_total: 46, techniques_covered: 33,
    by_actor: { [ACTOR]: 3 }, by_repo: { [REPO]: 3 }, by_tactic: { Execution: 6 },
    alerts_list: [alert(0.95), alert(0.35)], running: true, uptime: 600 },
  '/api/alerts': { alerts: [alert(0.95), alert(0.35)] },
  '/api/incidents': { incidents: [{ id: 7, actor: ACTOR, severity: 'critical',
      max_risk: 0.95, alerts: 2, tactics: ['Execution'], repos: [REPO],
      is_campaign: false, start_ts: NOW, last_ts: NOW, status: 'new' }] },
  '/api/coverage': { grid: [
      { tactic: 'Execution', techniques: [
        { technique: 'T1072', name: 'Software Deployment Tools',
          covered: true, fired: 14, rules: [{ id: 'x', title: 'y', severity: 'high' }] },
        { technique: 'T1059', name: 'Command Interpreter',
          covered: false, fired: 0, rules: [] },
        { technique: 'T1204', name: 'User Execution',
          covered: true, fired: 2, rules: [{ id: 'z', title: 'w', severity: 'low' }] }] },
      { tactic: 'Exfiltration', techniques: [
        { technique: 'T1567', name: 'Exfiltration Over Web Service',
          covered: true, fired: 0, rules: [{ id: 'q', title: 'r', severity: 'medium' }] }] }] },
  '/api/rules': { rules: [{ id: 'deploy-tool-abuse', title: 'Ручной прогон',
      technique: 'T1072', tactic: 'Execution', severity: 'high', risk: 0.64,
      fired: 8 }] },
  '/api/workflow': { items: [{ id: 7, actor: ACTOR, severity: 'critical',
      max_risk: 0.95, alerts: 1, tactics: ['Execution'], status: 'new',
      verdict: null, age_min: 4 }], noisy_rules: [{ rule_id: 'x', fired: 6, fp: 1 }],
    muted_hits: 2, fp_threshold: 3, counts: { new: 8 } },
  '/api/cases': { cases: [{ id: 'CASE-1001', title: 'Утечка', severity: 'critical',
      status: 'open', incidents: [7], analyst: 'L2', note: '' }] },
  '/api/diag': { counts: { ERROR: 2, WARNING: 1, INFO: 546, DEBUG: 5687 },
    recent: [
      { ts: '12:00:00', level: 'INFO', module: 'detector', event: 'алерт поднят', ctx: { rule_id: 'x', risk: 0.6 } },
      { ts: '12:00:01', level: 'ERROR', module: 'console', event: 'ошибка маршрута' },
      { ts: '12:00:02', level: 'DEBUG', module: 'ingest', event: 'пачка событий' }],
    errors: [{ ts: '12:00:01', level: 'ERROR', module: 'console', event: 'ошибка маршрута' }],
    errors_log_tail: ['2026-08-10 12:00:01 ERROR console: сбой\n',
                      '  File "/home/u/soc/console.py", line 793, in f\n'],
    paths: {} },
  '/api/risk': { developers: [{ key: ACTOR, risk: 73, alerts: 4, incidents: 2,
      techniques: 1, peers: 3 }], repos: [{ key: REPO, risk: 62, alerts: 3,
      incidents: 3, techniques: 1, peers: 3 }], dynamics: [],
    alerts: [alert(0.95), alert(0.35)] },
  '/api/trends': { history: [
      { ts: '2026-08-10T10:00:00', detection_rate: 0.62, coverage: 0.55, fp_rate: 0.22, mttd: 7.4, alerts: 3 },
      { ts: '2026-08-10T10:05:00', detection_rate: 0.71, coverage: 0.58, fp_rate: 0.19, mttd: 6.1, alerts: 5 },
      { ts: '2026-08-10T10:10:00', detection_rate: 0.74, coverage: 0.61, fp_rate: 0.17, mttd: 5.2, alerts: 9 }],
    annotations: [],
    snapshot: { last: '2026-08-10T10:10:00', next_in_s: 214, period_s: 300,
                running: false, error: null, count: 3 } },
  '/api/replay': { events: [], alerts: [], incidents: [] },
  '/api/entities': { entities: [{ actor: ACTOR, alerts: 4, events: 355 }] },
  '/api/scenarios': { scenarios: [{ id: 's1', title: 'CI-токен', steps: [] }] },
  '/api/executive': { metrics: null, computing: true, holdout: [] },
  '/api/roi': { mttd_sim_min: 1.2, incidents_seen: 9 }
};
function fixtureFor(u) {
  const path = String(u).split('?')[0];
  return FIX[path] !== undefined ? FIX[path] : {};
}
// Заглушка обязана вести себя как настоящий Response: тело ОДНО, и
// text() с json() не могут расходиться. Раньше text() отдавал пустую
// строку при непустом json() — невозможная для браузера комбинация, на
// которой любой честный разбор ответа выглядел бы падением.
w.fetch = (u, o) => { calls.push(String(u));
  const body = JSON.stringify(fixtureFor(u));
  return Promise.resolve({
    ok: true, status: 200,
    json: () => Promise.resolve(JSON.parse(body)),
    text: () => Promise.resolve(body)
  }); };
w.EventSource = function () { this.addEventListener = () => {}; this.close = () => {}; };
w.matchMedia = w.matchMedia || (() => ({ matches: false, addListener(){}, addEventListener(){} }));
w.scrollTo = () => {};
w.alert = () => {}; w.confirm = () => true; w.open = () => ({ document: { write(){}, close(){} } });

// Ошибки интерфейса ловим двумя путями: через console.error (туда пишет
// uiErr) и через собственный обработчик.
const origErr = w.console.error;
w.console.error = function () {
  errors.push('console.error: ' + Array.prototype.slice.call(arguments).join(' ').slice(0, 200));
};
w.onerror = (m) => { errors.push('onerror: ' + m); };

let timers = 0;
const pending = [];
w.setInterval = (fn, ms) => { timers++; return 0; };
w.setTimeout = (fn, ms) => { if (!ms) pending.push(fn); return 0; };

for (const f of ['i18n.js', 'charts.js', 'ui.js']) {
  const p = staticDir + '/' + f;
  if (fs.existsSync(p)) {
    try { w.eval(fs.readFileSync(p, 'utf8')); } catch (e) { errors.push(f + ': ' + e.message); }
  }
}
const inline = [...w.document.querySelectorAll('script:not([src])')];
inline.forEach((s, i) => {
  try { w.eval(s.textContent); } catch (e) { errors.push('inline#' + (i + 1) + ': ' + e.message); }
});
try { w.document.dispatchEvent(new w.Event('DOMContentLoaded')); } catch (e) {}

// ПРОГОН ОПРОСОВ. Синтаксис и загрузка ничего не говорят о том, доходит
// ли обновление до конца: исключение на середине оставляет половину
// экрана прочерками, и раньше это было не видно вообще никак.
// Список опросчиков НЕ перечисляется руками: он устаревает молча.
// Так и вышло — pollWorkload в перечислении не было, раздел «Тренды»
// не прогонялся ни разу, и панель выбора рабочего порога оставалась
// непроверенной (её подпись висела прочерком, и это никого не смущало).
// Берём с window всё, что выглядит опросчиком, плюс общие точки входа.
const POLLERS = ['tick', 'refresh', 'poll'].concat(
  Object.keys(w).filter(k => /^poll[A-Z]/.test(k) && typeof w[k] === 'function').sort());
(async () => {
  for (const name of POLLERS) {
    const fn = w[name];
    if (typeof fn !== 'function') continue;
    try { await fn(); } catch (e) { errors.push(name + '(): ' + e.message); }
  }
  pending.splice(0).forEach(fn => { try { fn(); } catch (e) { errors.push('timeout: ' + e.message); } });

  // Сколько значений так и осталось прочерком после полного прогона.
  const dashes = [...w.document.querySelectorAll('[id]')]
    .filter(el => el.offsetParent !== null || true)
    .filter(el => (el.textContent || '').trim() === '—')
    .map(el => el.id);

  // РАЗМЕТКА, ВЫВЕДЕННАЯ ТЕКСТОМ.
  // Кнопка реплея показывала на экране буквально
  // '<svg class=ico viewBox=...><path d=.../></svg> Реплей атаки':
  // строку с иконкой присвоили через textContent вместо innerHTML.
  // Синтаксически это корректный код, опрос доходит до конца, ошибок в
  // консоли нет — поймать можно только глазами или вот такой проверкой.
  const rawMarkup = [];
  const walker = w.document.createTreeWalker(w.document.body, 4 /* TEXT */);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    const t = (n.nodeValue || '');
    if (/<(svg|div|span|path|button|table|tr|td)\b/i.test(t)) {
      const owner = n.parentElement;
      if (owner && /SCRIPT|STYLE|PRE|CODE|TEXTAREA/.test(owner.tagName)) continue;
      rawMarkup.push(((owner && (owner.id || owner.className)) || '?') + ': ' + t.trim().slice(0, 60));
    }
  }

  // КОМПОНЕНТЫ, КОТОРЫЕ ОБЯЗАНЫ ОТРИСОВАТЬСЯ НА ФИКСТУРАХ.
  // Без этого «прогон без ошибок» проходит и на пустом экране: функция
  // отработала, но не нарисовала ничего.
  const want = {
    '#trendGrid .metric-card': 'карточки метрик',
    '#trendGrid .dsc-line': 'линия графика',
    '#cSeverity .dsc-arc': 'круг очереди по уровню',
    '#cCoverage .dsc-arc': 'круг покрытия ATT&CK',
    '#alFlow .dsc-line': 'поток сработок',
    '#byRepo .dsc-bar-fill': 'полосы по репозиториям',
    '#matrix .mx-cell': 'ячейки матрицы ATT&CK',
    '#matrix .mx-th': 'шапки тактик',
    '#diagRecent .logrow': 'строки структурного лога',
    '#wfQueue .wfi': 'очередь триажа'
  };
  const missing = [];
  for (const sel in want) {
    if (!w.document.querySelector(sel)) missing.push(want[sel] + ' (' + sel + ')');
  }

  // СЛИПШИЙСЯ ТЕКСТ.
  // «шагов: 1тактик: 1развитие атаки: 0 мин» — пять значений подряд
  // соседними span-ами без единого разделителя. Каждый узел по
  // отдельности корректен, ошибок нет, но прочитать это нельзя.
  //
  // Тонкость: у flex- и grid-контейнеров с gap соседние элементы
  // разведены раскладкой, и склейка в textContent там ничего не значит.
  // jsdom раскладку не считает, поэтому список таких классов приходит
  // снаружи — он собран разбором самой таблицы стилей.
  const SPACED = new Set(JSON.parse(process.env.SPACED_CLASSES || '[]'));
  const glued = [];
  function textOf(el) {
    // Собираем видимый текст так, как его склеит браузер: блочные
    // потомки дают перенос строки, строчные — нет.
    let out = '';
    for (const n of el.childNodes) {
      if (n.nodeType === 3) { out += n.nodeValue; continue; }
      if (n.nodeType !== 1) continue;
      const inline = /^(SPAN|B|I|EM|STRONG|A|CODE|KBD|SMALL|SUP|SUB|LABEL)$/.test(n.tagName);
      const spaced = [...n.classList].some(c => SPACED.has(c));
      const sep = (inline && !spaced) ? '' : '\n';
      out += sep + textOf(n) + sep;
    }
    return out;
  }
  for (const el of w.document.querySelectorAll('div,p,li,td,th')) {
    if (el.querySelector('div,p,li,table')) continue;   // только листья
    if ([...el.classList].some(c => SPACED.has(c))) continue;
    const t = textOf(el).replace(/[ \t]+/g, ' ');
    for (const line of t.split('\n')) {
      const m = line.match(/\d[А-Яа-яЁё]{3,}|[а-яё][А-ЯЁ][а-яё]{3,}/);
      if (m) glued.push(line.trim().slice(0, 70));
    }
  }

  console.log(JSON.stringify({ errors, timers, calls: calls.length,
    sample: calls.slice(0, 4), dashes, rawMarkup, missing,
    glued: [...new Set(glued)] }));
})();
""")

    # Классы, у которых раскладка сама разводит соседние элементы:
    # flex/grid с ненулевым gap, а также сетки «ключ — значение».
    # Без этого списка проверка склейки ругалась бы на .kv и .ds-cov-legend,
    # где в textContent соседи стоят вплотную, а на экране между ними
    # шестнадцать пикселей.
    css_all = io.open(os.path.join("static", "design-system.css"), encoding="utf-8").read()
    css_all = re.sub(r"/\*.*?\*/", "", css_all, flags=re.S)
    spaced = set()
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", css_all):
        body = m.group(2)
        if not re.search(r"display\s*:\s*(inline-)?(flex|grid)", body):
            continue
        g = re.search(r"(?<!row-)(?<!column-)\bgap\s*:\s*([^;}]+)", body)
        if not g or g.group(1).strip() in ("0", "0px"):
            if not re.search(r"column-gap\s*:", body):
                continue
        for cls in re.findall(r"\.([A-Za-z][\w-]*)", m.group(1)):
            spaced.add(cls)

    env = dict(os.environ)
    env["SPACED_CLASSES"] = json.dumps(sorted(spaced))
    extra = [os.path.join(os.getcwd(), "node_modules"), "/tmp/soc/node_modules"]
    env["NODE_PATH"] = os.pathsep.join([p for p in extra if os.path.isdir(p)]
                                       + [env.get("NODE_PATH", "")])

    dashboards = [p for p in pages if os.path.basename(p) == "dashboard.html"]
    any_checked = False
    for p in dashboards:
        r = subprocess.run(["node", runner, p, os.path.join(os.getcwd(), "static")],
                           capture_output=True, text=True, timeout=180, env=env)
        try:
            res = json.loads((r.stdout or "").strip().splitlines()[-1])
        except Exception:
            check(f"{p}: страница выполняется", False,
                  (r.stderr or r.stdout or "нет вывода")[:400])
            continue
        if res.get("skipped"):
            print(f"  ПРОПУЩЕНО ({p}): нет пакета jsdom (npm install)")
            continue
        any_checked = True
        check(f"{os.path.basename(os.path.dirname(p))}: прогон без ошибок",
              not res["errors"], "\n".join(res["errors"][:8]))
        check(f"{os.path.basename(os.path.dirname(p))}: заводит опрос данных",
              res["timers"] > 0 or res["calls"] > 0,
              f"таймеров {res['timers']}, обращений к API {res['calls']} — "
              f"страница отрисуется, но данные не подгрузятся")
        # Прочерк после полного прогона с данными означает, что значение
        # так и не подставилось: либо обрыв, либо забытый идентификатор.
        dashes = [d for d in res.get("dashes", []) if not d.startswith("v-")]
        check(f"{os.path.basename(os.path.dirname(p))}: все значения заполнились",
              not dashes,
              "остались прочерками: " + ", ".join(dashes[:14]))
        glued = res.get("glued", [])
        check(f"{os.path.basename(os.path.dirname(p))}: значения не слипаются с подписями",
              not glued, "\n".join(glued[:8]))
        raw = res.get("rawMarkup", [])
        check(f"{os.path.basename(os.path.dirname(p))}: разметка не выводится текстом",
              not raw, "\n".join(raw[:6]))
        # На env-консоли части этих блоков нет — проверяем там, где они есть.
        miss = [m for m in res.get("missing", [])
                if "console" in p.replace("\\", "/")]
        check(f"{os.path.basename(os.path.dirname(p))}: ключевые блоки отрисованы",
              not miss, "не отрисовалось: " + ", ".join(miss[:6]))
        print(f"       обращений к API: {res['calls']}, таймеров: {res['timers']}")
        if any_checked and not fails:
            print(f"      таймеров опроса: {res['timers']}, "
                  f"обращений к API при загрузке: {res['calls']}")

    print("-" * 72)
    if fails:
        print(f"  {BAD} ПРОВАЛЕНО: {len(fails)}")
        print()
        print("  Частая причина — апостроф внутри строки в одинарных кавычках:")
        print("    '... merge request'ы ...'   ломает разбор всего скрипта.")
        return 1
    if not any_checked:
        # Ни одна страница не прогонялась (нет jsdom) — это ПРОПУСК, а не успех:
        # раньше в такой ситуации печаталось «скрипты корректны», и сводка
        # показывала PASS на непроверенном клиентском коде.
        print("  ПРОПУЩЕНО: ни одна страница не прогонялась (нет пакета jsdom)")
        return 2
    print(f"  {OK} Скрипты страниц корректны и доходят до опроса данных.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
