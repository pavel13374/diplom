# Каталог правил детектирования

> Файл создаётся скриптом `tools/gen_rule_index.py` — правьте правила в
> `detections/*.json`, а не здесь.

Правил: **38**. Покрыто техник модели угроз: **33/46**.

Правило описывается декларативно и подхватывается без перезапуска логики.
Условия опираются только на **наблюдаемые атрибуты** события — то, что видно
в аудит-логе GitLab. Правил вида «действие == название атаки» в каталоге нет
и быть не может: это проверяет `tools/lint_rules.py`.

---

## Reconnaissance

### ✅ T1087 — Account/Repo Discovery

**Массовое перечисление репозиториев через API**  
`recon-enumeration` · риск 0.55 · средн.

Разведка выглядит как обычные GET к API — отличает её ОБЪЁМ и ОХВАТ. Пороги подняты по результатам замера точности (tools/rule_quality.py): на прежних 5 запросов / 150 объектов правило давало 14% всего шума, потому что человек, листающий дерево репозитория, укладывался в них.

Условие срабатывания:

```json
{
  "action": "api_read",
  "api_path": {
    "in": [
      "/projects",
      "/repository/tree"
    ]
  },
  "burst_api_read_15m": {
    ">=": 8
  },
  "api_items_sum_15m": {
    ">=": 300
  },
  "distinct_projects_1h": {
    ">=": 3
  }
}
```

### ✅ T1593.003 — Search Code Repositories

**Серия поисковых запросов по коду (охота за секретами)**  
`code-search` · риск 0.5 · средн.

Поиск по коду делают все. Признак охоты за секретами — серия запросов подряд с широкой выдачей. Пороги подняты с 3/25 по результатам замера точности.

Условие срабатывания:

```json
{
  "action": "api_read",
  "api_path": "/search",
  "burst_api_read_15m": {
    ">=": 5
  },
  "items_returned": {
    ">=": 40
  }
}
```


## Initial Access

### ✅ T1078 — Valid Accounts

**Ночное обращение к репозиторию секретов**  
`offhours-secrets-access` · риск 0.65 · высок.

Доступ к soc-secrets вне рабочих часов.

Условие срабатывания:

```json
{
  "project": "soc-secrets",
  "is_night": true
}
```

### ✅ T1195.002 — Supply Chain

**Секрет в манифесте зависимостей**  
`supply-chain-dep` · риск 0.7 · высок.

Сигнатура секрета внутри requirements/package.json.

Условие срабатывания:

```json
{
  "action": "push",
  "deps_manifest": true,
  "n_regex_hits": {
    ">=": 1
  }
}
```

### ✅ T1195.001 — Compromise Software Dependencies

**В манифест добавлена новая закреплённая зависимость**  
`dep-poison` · риск 0.55 · средн.

Признак typo-squat: новая зависимость, закреплённая точной версией. Обычный бамп версии существующей зависимости не срабатывает.

Условие срабатывания:

```json
{
  "action": "push",
  "deps_manifest": true,
  "dependency_pinned_new": true
}
```

### ⬜ T1199 — Trusted Relationship

Слепая зона: правила пока нет. Это очередь работ detection
engineering, а не пробел в модели угроз.


## Execution

### ✅ T1059 — Command/Script Interpreter

**Изменён конвейер CI**  
`ci-pipeline-change` · риск 0.3 · низк.

Любая правка .gitlab-ci.yml — потенциальная точка исполнения кода, но в норме это происходит постоянно. Правило намеренно оставлено ИНФОРМАЦИОННЫМ: низкий риск, не создаёт действенный инцидент сам по себе, но обогащает контекст, когда рядом сработало что-то ещё. Держать его как high — значит гарантировать поток ложных тревог.

Условие срабатывания:

```json
{
  "action": "push",
  "path": {
    "contains": ".gitlab-ci.yml"
  }
}
```

### ✅ T1072 — Software Deployment Tools

**Ручной прогон в production вне рабочего времени**  
`deploy-tool-abuse` · риск 0.64 · высок.

Релизы вручную бывают и в норме, поэтому одного признака мало. Срабатывает сочетание: ручной запуск + production + ночь.

Условие срабатывания:

```json
{
  "action": "pipeline_run",
  "manual_trigger": true,
  "target_env": "production",
  "is_night": true
}
```

### ✅ T1053 — Scheduled Task/Job

**Расписание пайплайна на защищённой ветке в production**  
`ci-scheduled-job` · риск 0.66 · высок.

Ночные сборки — обычная практика, поэтому один лишь ночной cron не срабатывает. Признак закрепления: расписание на защищённой ветке с выкладкой в production.

Условие срабатывания:

```json
{
  "action": "schedule_create",
  "protected_branch": true,
  "target_env": "production"
}
```


## Persistence

### ✅ T1098.001 — Additional Cloud Credentials

**Токен с правами api выписан не себе и без срока**  
`extra-token-created` · риск 0.75 · высок.

Команда регулярно ротирует СВОИ read-токены со сроком — это норма и не срабатывает. Признак закрепления: широкий scope, бессрочный, выписан третьему лицу.

Условие срабатывания:

```json
{
  "action": "token_create",
  "token_scope": {
    "in": [
      "api",
      "sudo"
    ]
  },
  "for_self": false
}
```

### ✅ T1098 — Account Manipulation

**Изменён список доступа к репозиторию секретов**  
`secrets-access-granted` · риск 0.72 · высок.

Правка policy-файла членства soc-secrets.

Условие срабатывания:

```json
{
  "action": "push",
  "path": {
    "contains": "soc-secrets-members"
  }
}
```

### ✅ T1136.003 — Create Cloud Account

**Новый служебный аккаунт с широкими правами**  
`cloud-account-create` · риск 0.65 · высок.

Новый участник сразу с уровнем Maintainer и выше.

Условие срабатывания:

```json
{
  "action": "member_update",
  "new_member": true,
  "access_level": {
    ">=": 40
  },
  "self_grant": false
}
```

### ⬜ T1505 — Server Software Component

Слепая зона: правила пока нет. Это очередь работ detection
engineering, а не пробел в модели угроз.


## Privilege Escalation

### ✅ T1098 — Account Manipulation

**Изменён список доступа к репозиторию секретов**  
`secrets-access-granted` · риск 0.72 · высок.

Правка policy-файла членства soc-secrets.

Условие срабатывания:

```json
{
  "action": "push",
  "path": {
    "contains": "soc-secrets-members"
  }
}
```

### ✅ T1548 — Abuse Elevation Control

**Актор поднял права сам себе до Owner**  
`elevate-privs` · риск 0.85 · критич.

Штатная выдача прав — Reporter/Developer другому человеку. Самовыдача Owner/Maintainer не встречается в нормальном процессе.

Условие срабатывания:

```json
{
  "action": "member_update",
  "self_grant": true,
  "access_level": {
    ">=": 40
  }
}
```

### ⬜ T1078.004 — Valid Accounts: Cloud

Слепая зона: правила пока нет. Это очередь работ detection
engineering, а не пробел в модели угроз.


## Defense Evasion

### ✅ T1562 — Impair Defenses

**Автор сам смёржил свой MR в защищённую ветку без апрувов**  
`self-merged-mr` · риск 0.66 · высок.

Самостоятельный merge встречается в обычной работе (мелкие правки, дежурный на выходных) и сам по себе не является инцидентом — раньше это правило давало 82 ложных срабатывания на 2 верных. Признаком остаётся сочетание: свой MR + защищённая ветка + НИ ОДНОГО апрува.

Условие срабатывания:

```json
{
  "action": "mr_merge",
  "self_merged": true,
  "protected_branch": true,
  "approvals_count": 0
}
```

### ✅ T1562 — Impair Defenses

**Merge в защищённую ветку без единого апрува**  
`merge-without-approval` · риск 0.55 · средн.

Обязательное ревью обойдено на защищённой ветке.

Условие срабатывания:

```json
{
  "action": "mr_merge",
  "approvals_count": 0,
  "protected_branch": true
}
```

### ✅ T1562.001 — Disable/Modify Tools

**В CI отключён сканер безопасности**  
`ci-scanner-disabled` · риск 0.72 · высок.

Правка .gitlab-ci.yml с отключением проверки.

Условие срабатывания:

```json
{
  "action": "push",
  "path": {
    "contains": ".gitlab-ci.yml"
  },
  "message": {
    "contains": "disable"
  }
}
```

### ✅ T1556 — Modify Auth Process

**Ослаблена защита ветки**  
`branch-protection-weakened` · риск 0.72 · высок.

Правка политики branch-protection.

Условие срабатывания:

```json
{
  "action": "push",
  "path": {
    "contains": "branch-protection"
  }
}
```

### ✅ T1556 — Modify Auth Process

**Изменён файл политики доступа**  
`policy-file-change` · риск 0.55 · средн.

Правка в каталоге policy/.

Условие срабатывания:

```json
{
  "action": "push",
  "path": {
    "contains": "policy/"
  }
}
```

### ✅ T1070.004 — Indicator Removal: File Deletion

**Переписана история защищённой ветки**  
`history-rewrite` · риск 0.75 · высок.

Force-push после rebase своей ветки — рутина и не срабатывает. Признак заметания следов: защищённая ветка и потерянные коммиты.

Условие срабатывания:

```json
{
  "action": "force_push",
  "protected_branch": true,
  "commits_dropped": {
    ">=": 3
  }
}
```

### ✅ T1027 — Obfuscated Files or Information

**Обфусцированное содержимое в коммите**  
`obfuscated-payload` · риск 0.72 · высок.

Исполнение закодированной строки: eval(atob(...)), new Function(atob(...)), exec(b64decode(...)), «| base64 -d | sh». Раньше правило опиралось на энтропию — и было слепо ровно там, где обфускацию и прячут: в минифицированном JS высокая энтропия легитимна, файл попадал под исключение generated_signal, и техника T1027 переставала детектироваться. Отличает вредонос не «случайность» текста, а КОНСТРУКЦИЯ исполнения.

Условие срабатывания:

```json
{
  "action": "push",
  "obfuscation_signal": true
}
```

### ⬜ T1550.001 — Application Access Token

Слепая зона: правила пока нет. Это очередь работ detection
engineering, а не пробел в модели угроз.


## Credential Access

### ✅ T1552.001 — Credentials In Files

**Приватный ключ в коммите**  
`private-key-commit` · риск 0.95 · критич.

PEM-заголовок приватного ключа в содержимом.

Условие срабатывания:

```json
{
  "action": "push",
  "regex_hits": {
    "contains": "private_key"
  }
}
```

### ✅ T1552.001 — Credentials In Files

**Секрет по сигнатуре в коммите**  
`secret-signature-commit` · риск 0.92 · критич.

Сработала известная сигнатура (glpat/AKIA/JWT/private key) и это не плейсхолдер.

Условие срабатывания:

```json
{
  "action": "push",
  "n_regex_hits": {
    ">=": 1
  },
  "placeholder_signal": false
}
```

### ✅ T1552.001 — Credentials In Files

**Секрет в комментарии к merge request или задаче**  
`secret-in-mr-comment` · риск 0.75 · высок.

Сигнатура секрета в тексте обсуждения. Комментарий — такой же канал утечки, как и коммит, и настоящий сканер проверяет его наравне с кодом. Раньше признаки содержимого для комментариев вообще не считались, и правило не могло сработать ни разу.

Условие срабатывания:

```json
{
  "action": {
    "in": [
      "mr_comment",
      "issue_comment"
    ]
  },
  "n_regex_hits": {
    ">=": 1
  },
  "placeholder_signal": false
}
```

### ✅ T1552 — Unsecured Credentials

**Высокоэнтропийный секрет без известной сигнатуры**  
`high-entropy-push` · риск 0.62 · высок.

Ключевое правило против НОВЫХ форматов токенов. Исключены файлы, где высокая энтропия ожидаема (lock-файлы, минифицированный JS, base64-иконки) — раньше именно они давали основную массу ложных срабатываний.

Условие срабатывания:

```json
{
  "action": "push",
  "shannon_entropy": {
    ">=": 5.0
  },
  "has_high_entropy_token": true,
  "placeholder_signal": false,
  "generated_signal": false,
  "n_regex_hits": 0
}
```

### ✅ T1552.004 — Private Keys

**Отладочный вывод CI светит токены**  
`ci-debug-token-leak` · риск 0.72 · высок.

Правка CI, печатающая переменные окружения в лог джобы.

Условие срабатывания:

```json
{
  "action": "push",
  "path": {
    "contains": ".gitlab-ci.yml"
  },
  "message": {
    "contains": "debug"
  }
}
```

### ✅ T1552.007 — Container API Credentials

**Учётные данные реестра контейнеров в манифесте**  
`container-api-creds` · риск 0.7 · высок.

Манифест k8s/registry с длинным высокоэнтропийным токеном.

Условие срабатывания:

```json
{
  "action": "push",
  "path": {
    "contains_any": [
      "k8s/",
      "kubernetes/",
      "registry",
      "imagepull"
    ]
  },
  "has_high_entropy_token": true,
  "placeholder_signal": false
}
```

### ✅ T1528 — Steal Application Access Token

**Чтение списка OAuth-токенов приложения**  
`steal-oauth` · риск 0.7 · высок.

Обращение к /oauth/tokens в рабочем процессе SOC-команды не встречается: токены выдаёт администратор через UI.

Условие срабатывания:

```json
{
  "action": "api_read",
  "api_path": {
    "contains": "/oauth"
  }
}
```

### ⬜ T1555 — Credentials from Password Stores

Слепая зона: правила пока нет. Это очередь работ detection
engineering, а не пробел в модели угроз.


## Discovery

### ✅ T1069 — Permission Groups Discovery

**Перечисление участников и прав по многим репозиториям**  
`perm-discovery` · риск 0.5 · средн.

Разовый просмотр состава команды — норма. Подозрителен систематический обход: 4+ разных репозитория и плотная серия запросов. Пороги подняты с 3/3 — на них правило шумело и не ловило ни одного эпизода в одиночку.

Условие срабатывания:

```json
{
  "action": "api_read",
  "api_path": "/members",
  "distinct_projects_1h": {
    ">=": 4
  },
  "burst_api_read_15m": {
    ">=": 5
  }
}
```

### ⬜ T1526 — Cloud Service Discovery

Слепая зона: правила пока нет. Это очередь работ detection
engineering, а не пробел в модели угроз.

### ⬜ T1518 — Software Discovery

Слепая зона: правила пока нет. Это очередь работ detection
engineering, а не пробел в модели угроз.

### ⬜ T1613 — Container and Resource Discovery

Слепая зона: правила пока нет. Это очередь работ detection
engineering, а не пробел в модели угроз.


## Lateral Movement

### ✅ T1021.004 — Remote Services: SSH

**Внешний deploy-ключ с правом записи**  
`ssh-deploy-key` · риск 0.7 · высок.

Норма — read-only ключ на внутренний раннер. Подозрителен ключ на запись, указывающий наружу.

Условие срабатывания:

```json
{
  "action": "deploy_key_add",
  "key_write_access": true,
  "external_host": true
}
```

### ⬜ T1080 — Taint Shared Content

Слепая зона: правила пока нет. Это очередь работ detection
engineering, а не пробел в модели угроз.


## Collection

### ✅ T1213 — Data from Repositories

**Обращение к хранилищу секретов в коде**  
`data-repo-collection` · риск 0.65 · высок.

Путь ведёт в vault/секрет-хранилище.

Условие срабатывания:

```json
{
  "action": "push",
  "path": {
    "contains": "vault"
  },
  "placeholder_signal": false
}
```

### ✅ T1213 — Data from Repositories

**Прямое касание репозитория секретов**  
`secrets-repo-touch` · риск 0.3 · низк.

Любая операция записи в репозиторий секретов. Команда туда заходит и по делу, поэтому правило намеренно ИНФОРМАЦИОННОЕ: низкий риск, само по себе действенный инцидент не создаёт, но обогащает контекст, когда рядом сработало что-то ещё. Держать его как high — значит гарантировать поток ложных тревог: измеренная точность в отрыве от контекста около 5%.

Условие срабатывания:

```json
{
  "project": "soc-secrets",
  "action": {
    "in": [
      "push",
      "branch_create",
      "mr_merge",
      "file_delete",
      "branch_delete",
      "force_push"
    ]
  },
  "placeholder_signal": false
}
```

### ✅ T1114.003 — Email Forwarding Rule

**Настроена пересылка почты**  
`mailbox-forward-rule` · риск 0.5 · средн.

Раньше правило ловило любой путь со словом forward (12 ложных срабатываний). Теперь нужен именно почтовый контекст.

Условие срабатывания:

```json
{
  "action": "push",
  "path": {
    "contains": "forward",
    "contains_any": [
      "mail",
      "smtp",
      "imap",
      "inbox"
    ]
  }
}
```

### ✅ T1119 — Automated Collection

**Автоматизированная выгрузка репозиториев**  
`automated-collection` · риск 0.68 · высок.

Серия скачиваний архивов репозиториев за короткое окно — признак харвестера, а не ручной работы.

Условие срабатывания:

```json
{
  "action": "api_read",
  "api_path": "/repository/archive",
  "burst_api_read_15m": {
    ">=": 3
  }
}
```

### ⬜ T1074 — Data Staged

Слепая зона: правила пока нет. Это очередь работ detection
engineering, а не пробел в модели угроз.


## Command and Control

### ✅ T1102 — Web Service

**Вебхук на внешний хост**  
`webhook-c2` · риск 0.7 · высок.

Команда заводит вебхуки на внутренние сервисы (SIEM, чат) — это норма. Наружу — канал управления.

Условие срабатывания:

```json
{
  "action": "hook_create",
  "external_host": true
}
```

### ⬜ T1071.001 — Web Protocols

Слепая зона: правила пока нет. Это очередь работ detection
engineering, а не пробел в модели угроз.


## Exfiltration

### ✅ T1567 — Exfil Over Web Service

**Крупный закодированный блоб в коммите**  
`large-encoded-blob` · риск 0.7 · высок.

Крупный файл, внутри которого есть ДЛИННЫЙ высокоэнтропийный токен, в месте, где генерация не ожидается. Требование has_high_entropy_token добавлено по замеру точности: одной лишь средней энтропии мало — под неё попадали обычные .md и .json, и правило давало 27% всего шума при точности 10%.

Условие срабатывания:

```json
{
  "action": "push",
  "bytes": {
    ">=": 1500
  },
  "shannon_entropy": {
    ">=": 5.0
  },
  "has_high_entropy_token": true,
  "generated_signal": false,
  "placeholder_signal": false
}
```

### ✅ T1537 — Transfer to Cloud Account

**Выгрузка резервной копии секретов**  
`secrets-backup-export` · риск 0.72 · высок.

Путь ведёт в backup/export.

Условие срабатывания:

```json
{
  "action": "push",
  "path": {
    "contains_any": [
      "backup",
      "export"
    ]
  },
  "has_high_entropy_token": true
}
```

### ✅ T1048 — Exfil Over Alternative Protocol

**Выгрузка на внешний хост по альтернативному протоколу**  
`exfil-altproto` · риск 0.75 · высок.

У такого файла обычная энтропия, и по ней его не отличить — отличает структура содержимого: scp/dig/curl на внешний хост.

Условие срабатывания:

```json
{
  "action": "push",
  "net_sink_signal": true
}
```

### ⬜ T1030 — Data Transfer Size Limits

Слепая зона: правила пока нет. Это очередь работ detection
engineering, а не пробел в модели угроз.


## Impact

### ✅ T1485 — Data Destruction

**Массовое удаление файлов одним актором**  
`mass-file-delete` · риск 0.7 · высок.

ГЛАВНОЕ ИСПРАВЛЕНИЕ. Раньше условием было просто action=file_delete: правило срабатывало на каждой обычной уборке репозитория (96 ложных, ни одного верного) и при этом НЕ ловило атаку, которая эмитила другое действие. Теперь массовость ВЫЧИСЛЯЕТСЯ (detector.Enricher). Порог поднят с 5 до 8: команда тоже иногда удаляет пачку устаревших правил, и на пороге 5 эти уборки давали треть всего шума.

Условие срабатывания:

```json
{
  "action": "file_delete",
  "burst_file_delete_10m": {
    ">=": 8
  }
}
```

### ⬜ T1565.001 — Stored Data Manipulation

Слепая зона: правила пока нет. Это очередь работ detection
engineering, а не пробел в модели угроз.

### ✅ T1490 — Inhibit System Recovery

**Удаление резервных веток и тегов**  
`inhibit-recovery` · риск 0.72 · высок.

Удаление слитых feature-веток — рутина. Признак: серия удалений защищённых/резервных веток.

Условие срабатывания:

```json
{
  "action": "branch_delete",
  "protected_branch": true,
  "burst_branch_delete_30m": {
    ">=": 2
  }
}
```


---

## Слепые зоны

Техник в модели угроз без правила: **13**.

| Техника | Почему пока не покрыта |
|---|---|
| `T1030` Data Transfer Size Limits | лимиты размера передачи не видны в событиях git/CI |
| `T1071.001` Web Protocols | прикладной сетевой уровень вне контура GitLab-аудита |
| `T1074` Data Staged | промежуточное складирование данных наблюдаемо только на хосте |
| `T1078.004` Valid Accounts: Cloud | облачные учётные записи живут вне GitLab |
| `T1080` Taint Shared Content | заражение общего содержимого требует данных файловой системы |
| `T1199` Trusted Relationship | доверенные отношения видны на уровне интеграций, не в аудите репо |
| `T1505` Server Software Component | серверные компоненты — уровень хоста |
| `T1518` Software Discovery | инвентаризация ПО не отражается в событиях репозитория |
| `T1526` Cloud Service Discovery | перечисление облачных сервисов идёт мимо GitLab API |
| `T1550.001` Application Access Token | использование украденного токена неотличимо от легитимного вызова |
| `T1555` Credentials from Password Stores | хранилища паролей вне периметра |
| `T1565.001` Stored Data Manipulation | манипуляция данными в покое — уровень БД, не репозитория |
| `T1613` Container and Resource Discovery | инвентаризация контейнеров — уровень оркестратора |

Эти техники намеренно оставлены в матрице: если бы в знаменатель попали
только те, под которые уже написаны правила, покрытие всегда равнялось бы
100%, и метрика измеряла бы сама себя.
