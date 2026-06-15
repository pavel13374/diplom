# Оставшиеся задачи — промпты для Claude (по одному за раз)

Закидывай блоки **по порядку**, каждый самодостаточный. После каждого — прогони
`python export_dataset.py` и `python rule_baseline.py`, чтобы убедиться, что ничего
не сломалось и нет утечки таргета.

Статус на момент составления: закрыто — анти-лик/экспорт датасета, rule-baseline,
session_id и per-actor сессии, единая схема событий, heatmap+таймлайн в веб-панели,
банк секретов. Ниже — то, что осталось.

---

## Пункт 1 — Убрать секреты из репозитория (.env + .gitignore)

```
В проекте soc-simulator секреты захардкожены в config.py: ADMIN_TOKEN,
TELEGRAM.token, WEB_ADMIN_PASS = "123". Файлы data/events.jsonl, logs/,
.sim_state.json, web_config.json закоммичены. Это SOC-проект — так быть не должно.

Сделай:
1. Создай .env.example с плейсхолдерами всех секретов (GITLAB_ADMIN_TOKEN,
   TELEGRAM_TOKEN, TELEGRAM_CHAT_ID, WEB_ADMIN_USER, WEB_ADMIN_PASS, WEB_SECRET).
2. В config.py читай эти значения через os.getenv(...) с безопасными дефолтами;
   подключи python-dotenv (load_dotenv()) в начале config.py. Добавь python-dotenv
   в requirements.txt. Если переменной нет — понятная ошибка/предупреждение, а не
   падение всего.
3. Создай .gitignore: .env, web_config.json, .sim_state.json, data/events.jsonl,
   data/dataset/, logs/, __pycache__/, *.pyc, simulator.log.
4. В README добавь короткую секцию «Конфигурация через .env» (скопировать
   .env.example в .env, заполнить).
5. В конце ответа отдельно напомни: засвеченные в истории git токены нужно
   ОТОЗВАТЬ и перевыпустить — это я сделаю руками.

Не меняй остальную логику. Не коммить .env.
```

---

## Пункт 2 — Признаки контента для детекта секретов (главный enabler для secret-ML)

```
В soc-simulator событие push (agents/base.py -> push_file) пишет в events.jsonl
только lines/bytes/ext. Для обучения детектора секретов нужны ПРИЗНАКИ КОНТЕНТА,
причём считаться они должны для ВСЕХ пушей (и нормальных, и аномальных) — иначе это
будет утечка разметки, а не честная фича.

Сделай новый модуль content_features.py с функцией analyze(content, path) -> dict:
  - shannon_entropy: максимальная энтропия Шеннона среди токенов длины >= 16
    (разбивай по не-буквенно-цифровым; бери max по токенам).
  - has_high_entropy_token: bool (энтропия >= ~4.0 при длине токена >= 20).
  - regex_hits: список названий сработавших паттернов из набора:
    glpat- (GitLab PAT), AKIA[0-9A-Z]{16} (AWS), -----BEGIN ... PRIVATE KEY-----,
    eyJ... (JWT), xox[baprs]- (Slack), ghp_ (GitHub), postgres://...@ (db url).
  - n_regex_hits: int (len(regex_hits)).
  - filename_signal: bool (путь содержит .env / secret / credential / id_rsa / .pem).
  - placeholder_signal: bool (в контенте есть EXAMPLE / CHANGEME / xxx / <...> /
    dummy / placeholder / your-… — признак benign-lookalike).

Подключи в agents/base.py::push_file — добавь эти поля в extra= при emit("push").

ВАЖНО про утечку: эти признаки — наблюдаемые (их видит и настоящий сканер), их
оставляем в датасете как ФИЧИ. Но secret_type / lookalike — это разметка, они уже
в drop-листе export_dataset.py; убедись, что новые поля (shannon_entropy,
regex_hits, n_regex_hits, has_high_entropy_token, filename_signal,
placeholder_signal) НЕ попали в DROP_COLUMNS, а остались фичами.

Проверь: после прогона у обычного .env.example placeholder_signal=true и низкая
энтропия, а у реальной утечки — высокая энтропия + regex_hits непустой.
```

---

## Пункт 3 — События аутентификации + source_ip/geo/device (главный enabler для UEBA)

```
В soc-simulator нет событий аутентификации и сетевых атрибутов — без них UEBA не
сделать. Добавь их.

1. В events.emit добавь сквозные поля source_ip, geo, device (брать из профиля
   актора). Заведи реестр «нормального» окружения на актора: стабильный source_ip
   (приватный диапазон), geo (город/страна), device — детерминированно по username
   (например, хэш). Большинство событий идут с этим нормальным окружением.

2. Новый тип событий аутентификации (emit с action):
   - "login"        — в начале рабочей сессии актора (см. _actor_session_id);
   - "logout"       — в конце (по желанию);
   - "failed_login" — редкая аномалия (брутфорс): несколько подряд от одного актора.
   Заведи активность/инъекцию, которая их порождает.

3. Поведенческие UEBA-аномалии (редкие, размеченные через events.tag, severity):
   - "login_new_geo"     — логин из НОВОЙ страны/города (impossible travel):
                            два логина одного актора из разных гео за короткое sim-время.
   - "login_offhours"    — логин среди ночи у того, кто обычно работает днём.
   - "brute_force"        — серия failed_login, затем успешный login.
   Зарегистрируй их в config.ANOMALIES с небольшими весами и в anomaly.py.

Поля source_ip/geo/device — наблюдаемые ФИЧИ, не разметка: убедись, что они НЕ в
DROP_COLUMNS export_dataset.py. Аномальность определяется метками anomaly_type,
а не самим фактом наличия ip.

Не ломай существующую схему: у событий без явного актора (system) ip=null.
```

---

## Пункт 4 — Профили поведения акторов (baseline-фичи для UEBA)

```
Для UEBA нужны причинные (только по прошлому) baseline-признаки на каждое событие.
Сделай модуль actor_profiles.py и опционально подмешивай фичи в export_dataset.py.

Функция build_profile_features(rows) которая, идя по событиям ХРОНОЛОГИЧЕСКИ, для
каждого события считает по скользящим окнам предыдущей активности ЭТОГО актора
(24 часа и 7 дней sim-времени, НЕ включая текущее событие — без утечки будущего):
  - actor_events_24h, actor_events_7d        — частота действий;
  - actor_night_ratio_7d                     — доля ночных действий;
  - actor_repo_count_7d                      — сколько разных репозиториев трогал;
  - actor_is_new_repo                        — впервые ли актор в этом project;
  - actor_is_new_hour                        — необычен ли час для актора (квантиль);
  - actor_action_entropy_7d                  — энтропия распределения его action;
  - actor_mean_bytes_7d                      — средний размер пуша;
  - actor_velocity_15m                       — число действий за 15 мин до события.
И пиринговые (отклонение от роли):
  - role_events_mean_24h, actor_dev_from_role — z-score частоты относительно своей роли.

Все фичи считаются ТОЛЬКО по событиям строго раньше текущего (causal). Никаких полей
таргета не используем. Добавь флаг в export_dataset.py (--profiles), который
подмешивает эти фичи в train/val/test. Проверь на утечку: значения для первого
события актора должны быть нулевыми/NaN, а не «знать» будущее.
```

---

## Пункт 5 — Два профиля частоты аномалий (realistic / training) + ребаланс

```
В config.py сейчас один ANOMALY_RATE=0.05 и ANOMALY_RATE_OFFHOURS=0.30 — последнее
нереалистично (каждое третье ночное действие = атака). Сделай переключаемые профили.

1. Введи ANOMALY_PROFILE = "training"  # "realistic" | "training"
   и словарь PROFILES:
     realistic: rate ~0.01, offhours ~0.03, SECRET_RATE_MULT ~0.3  (для отчёта
                «как настоящий SOC», редкие позитивы);
     training:  текущие высокие значения (быстро набрать позитивы для обучения).
   Эффективные ANOMALY_RATE / ANOMALY_RATE_OFFHOURS / SECRET_RATE_MULT берутся из
   выбранного профиля (сохрани обратную совместимость с web_config.json и
   EDITABLE_SCALARS — профиль тоже редактируемый из веб-панели).

2. Ребаланс ANOMALIES: сейчас self_approval_merge+merge_without_review доминируют
   (их тривиально берёт rule_baseline). Снизь их веса и подними «тонкие»
   (secret_*, data_exfiltration, pipeline_*, поведенческие из пункта 3), чтобы
   позитивный класс был разнообразнее. Цель — чтобы в датасете доля «слепых для
   правил» типов выросла.

3. В README/таблице конфига отрази: для раздела «реализм» берём realistic, для
   обучения — training.

Не меняй формат events.jsonl.
```

---

## Пункт 6 — Обучить и показать модели (UEBA + secret-классификатор)

```
Данные готовы (data/dataset/ из export_dataset.py, признаки контента и профили
акторов). Сделай два обучающих скрипта + сравнение с rule_baseline.py. Используй
scikit-learn (добавь в requirements.txt). Метрики — PR-AUC и precision@k,
НЕ accuracy (класс редкий). Сплит брать готовый по времени (train/val/test.jsonl).

1. secret_clf.py — supervised-классификатор утечек секретов:
   - фичи: признаки контента из пункта 2 (энтропия, regex_hits, filename/placeholder
     signal, ext, путь-флаги) + контекст (project, branch, hour, is_night);
   - таргет: _label, но ОБУЧАТЬ только различать секретные утечки vs benign-lookalikes
     и норму (используй _anomaly_type для отбора позитивов-секретов);
   - модель: GradientBoosting/RandomForest; выведи PR-AUC, precision@k, и отдельно
     точность на hard-negatives (placeholder_signal=true);
   - сравни с регулярочным baseline (только regex_hits>0).

2. ueba_unsup.py — unsupervised поведенческий детектор:
   - фичи: профили акторов из пункта 4 (частоты, night_ratio, velocity, new_repo,
     отклонение от роли) + source_ip/geo-новизна из пункта 3;
   - модель: IsolationForest (и для сравнения LocalOutlierFactor) — БЕЗ меток;
   - оцени, насколько топ-аномальные по score совпадают с _label (precision@k,
     PR-AUC), разбивка по anomaly_type;
   - покажи, что ловит поведенческие/секретные типы, на которых rule_baseline слеп.

3. eval_report.py (или секция в каждом скрипте): единая таблица
   rule_baseline vs secret_clf vs ueba_unsup по precision/recall/F1/PR-AUC и
   recall по типам аномалий. Это ключевой результат для диплома: ML добавляет
   recall на «слепых зонах» правил.

Никакого таргета в фичах. Сплит — строго по времени. Зафиксируй random_state.
```

---

### Порядок и зачем

1 — гигиена (без неё стыдно на защите). 2 — открывает secret-ML. 3 — открывает UEBA.
4 — baseline-фичи поведения. 5 — честный/обучающий режимы и разнообразие позитивов.
6 — собственно ML и главный вывод диплома (ML > правил на тонких атаках).
