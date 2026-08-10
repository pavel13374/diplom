# Разбор ошибки нормализации событий `type=TRUSTED_APP`

**Дата:** 29.07.2026
**Компонент:** Vector, transform `reduce` (`component_id=f8a86cbe-…_ar_6e23e0d9-…_reduce`)
**Затронутые источники:** парк хостов `veeam*` (019, 026, 027-2, 029, 032, 034-2, 035-2, 038-2, 039, 040-2, 043, 045-2, 046, 046-2, 047, 047-2, 048, 048-2, …), агент `audisp-syslog`
**Хранилище:** `default.EventStorage_f7bd2dc9_2562_4428_a1ea_6097116976e2`

---

## 1. Что приходит от источника

Хост шлёт через rsyslog запись auditd типа `TRUSTED_APP`. Событие приходит **целым и корректным** — с ним всё в порядке:

```json
{
  "appname": "audisp-syslog",
  "facility": "user",
  "hostname": "veeam038-2",
  "message": "type=TRUSTED_APP msg=audit(1785314941.675:1536023): pid=521050 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='{\"datetime\":\"2026-07-29T08:49:01.676724974Z\",\"level\":\"CRITICAL\",\"description\":\"Security logging disabled\",\"app_id\":\"canonical.snapd.snapd\",\"type\":\"security\",\"category\":\"SYS\",\"event\":\"sys_logging_disabled\"} '",
  "severity": "info",
  "timestamp": "2026-07-29T13:49:01Z"
}
```

Ключевая особенность формата — **двухуровневая вложенность**:

| Уровень | Формат | Содержимое |
|---|---|---|
| 1. Конверт syslog | JSON | `hostname`, `appname`, `severity`, `timestamp` |
| 2. Запись auditd | key=value | `type=`, `msg=audit(...)`, `pid=`, `uid=`, `auid=`, `ses=`, `subj=`, `msg='...'` |
| 3. Полезная нагрузка | **JSON внутри одинарных кавычек** | `datetime`, `level`, `description`, `app_id`, `type`, `category`, `event` |

Третий уровень — это и есть само событие безопасности:

```json
{
  "datetime": "2026-07-29T08:49:01.676724974Z",
  "level": "CRITICAL",
  "description": "Security logging disabled",
  "app_id": "canonical.snapd.snapd",
  "type": "security",
  "category": "SYS",
  "event": "sys_logging_disabled"
}
```

---

## 2. Где ломается

Правило нормализации разбирает **второй уровень** (запись auditd) как key-value с разделителем «пробел». Для полей `pid=521050`, `uid=0`, `subj=unconfined` это работает.

Но последнее поле — `msg='{…}'` — содержит JSON, **внутри значений которого есть пробелы**:

```
"description":"Security logging disabled"
                       ↑        ↑
                   пробелы внутри значения
```

KV-парсер не знает про кавычки третьего уровня и режет строку по этим пробелам на три куска:

| Кусок после разреза | Во что превращается |
|---|---|
| `msg='{"datetime":"…","level":"CRITICAL","description":"Security` | ключ `{\"datetime\":\"…\",\"level\":\"critical\",\"description\":\"security` со значением `true` |
| `logging` | поле `logging: true` |
| `disabled","app_id":"canonical.snapd.snapd","type":"security","category":"SYS","event":"sys_logging_disabled"}` | **имя поля**, значение `true` |

Обрати внимание: осмысленное значение `"Security logging disabled"` полностью исчезает, а его обрывки становятся **именами полей**.

---

## 3. Что получается на выходе

Нормализованное событие для того же `audit(1785314941.675:1536023)`:

```json
[{
  "trusted_app": {
    "auid": "4294967295",
    "disabled\",\"app_id\":\"canonical.snapd.snapd\",\"type\":\"security\",\"category\":\"sys\",\"event\":\"sys_logging_disabled\"}": true,
    "logging": true,
    "msg": [
      "audit(1785314941.675:1536023):",
      "{\"datetime\":\"2026-07-29t08:49:01.676724974z\",\"level\":\"critical\",\"description\":\"security logging disabled\",\"app_id\":\"canonical.snapd.snapd\",\"type\":\"security\",\"category\":\"sys\",\"event\":\"sys_logging_disabled\"} "
    ],
    "pid": "521050",
    "ses": "4294967295",
    "subj": "unconfined",
    "type": "trusted_app",
    "uid": "0",
    "{\"datetime\":\"2026-07-29t08:49:01.676724974z\",\"level\":\"critical\",\"description\":\"security": true
  }
}]
```

Два поля с мусорными именами вместо семи нормальных полей события. Плюс регистр приведён к нижнему (`CRITICAL` → `critical`), что дополнительно ломает сопоставление.

---

## 4. Как это видно в логе Vector

Дальше по конвейеру трансформация `reduce` пытается обратиться к полю по пути. Имя поля содержит кавычки, запятые и фигурную скобку — валидным путём это быть не может:

```
ERROR transform{component_kind="transform" component_type=reduce}:
vector::internal_events::reduce: Event field could not be reduced.
path=KeyString("raw.trusted_app.\"disabled\",\"app_id\":\"canonical.snapd.snapd\",\"type\":\"security\",\"category\":\"sys\",\"event\":\"sys_logging_disabled\"}\"")
error=InvalidPathSyntax { path: "raw.trusted_app.\"disabled\",…" }
error_type="condition_failed" stage="processing" internal_log_rate_limit=true
```

Рядом идут строки вида:

```
Internal log [Event field could not be reduced.] has been suppressed 23 times.
Internal log [Event field could not be reduced.] is being suppressed to avoid flooding.
```

Это не отдельная проблема, а внутренний рейт-лимит логов Vector. Но цифры (13, 23, 25 подавлений за считаные секунды) показывают масштаб — битых событий сотни в минуту.

---

## 5. Последствия

1. **События теряют семантику.** Ни `event`, ни `level`, ни `description` не попадают в поля модели — искать и коррелировать по ним нечем.
2. **`reduce` падает на стадии `processing`** с `condition_failed`. События не сливаются, а в зависимости от конфига могут отбрасываться.
3. **Детект не срабатывает.** `Security logging disabled` — это MITRE ATT&CK **T1562.002 (Impair Defenses: Disable Windows/System Event Logging)**, уровень `CRITICAL`. Сейчас эти события фактически невидимы для правил корреляции.
4. **Шум в логе Vector** маскирует другие ошибки конвейера.

---

## 6. Как чинить

**Основное.** В правиле нормализации не отдавать содержимое `msg='…'` KV-парсеру. Сначала вырезать вложенный объект, затем разобрать его как JSON:

```vrl
# 1. вытащить запись auditd из конверта
msg = string!(.message)

# 2. отделить вложенный JSON от KV-части
payload = parse_regex!(msg, r'msg=\'(?P<json>\{.*\})\s*\'$').json

# 3. KV-часть без payload
head = replace(msg, r'msg=\'\{.*\}\s*\'$', "")

. |= parse_key_value!(head)
. |= object!(parse_json!(payload))
```

**Проверка.** После правки убедиться, что в нормализованном событии появились поля `event`, `level`, `description`, `app_id`, а ошибок `InvalidPathSyntax` в логе Vector больше нет.

**Обходной путь на время починки** — работать напрямую по исходным событиям в ClickHouse:

```sql
WITH src AS (
    SELECT DISTINCT
        extract(JSONExtractString(raw, 'message'), 'audit\\(([0-9.:]+)\\)') AS audit_id,
        JSONExtractString(raw, 'hostname') AS host,
        parseDateTime64BestEffortOrNull(
            JSONExtractString(extract(JSONExtractString(raw, 'message'), '(\\{.*\\})'), 'datetime')
        ) AS event_time,
        JSONExtractString(extract(JSONExtractString(raw, 'message'), '(\\{.*\\})'), 'event') AS event,
        JSONExtractString(extract(JSONExtractString(raw, 'message'), '(\\{.*\\})'), 'level') AS level
    FROM default.EventStorage_f7bd2dc9_2562_4428_a1ea_6097116976e2
    WHERE timestamp >= toDateTime64('2026-07-29 00:00:00.000', 3)
      AND type = 'исходное событие'
      AND position(raw, 'sys_logging_') > 0
)
SELECT * FROM src ORDER BY host, event_time
```

---

## 7. Сопутствующие находки

Обнаружены при разборе, к основной ошибке отношения не имеют, но требуют внимания.

### 7.1. Дубликаты доставки

Одно и то же событие приходит **дважды**, отличаясь только наличием поля `procid`:

```
Row 890: …"hostname":"veeam039",…"severity":"info","timestamp":"2026-07-29T13:49:23Z"}
Row 891: …"hostname":"veeam039",…"procid":542425,"severity":"info","timestamp":"2026-07-29T13:49:23Z"}
```

Похоже на два маршрута доставки в rsyslog (RFC3164 и RFC5424 либо два `action`/`omfwd`). В нормализованных событиях это видно ещё нагляднее — массив содержит два идентичных объекта: `[{…},{…}]`.

**Действие:** проверить конфигурацию rsyslog на дублирующие правила пересылки. Для дедупликации в запросах использовать `audit_id` (`audit(<timestamp>:<serial>)`) — он уникален.

### 7.2. Расхождение таймзон на 5 часов

| Источник времени | Значение |
|---|---|
| Конверт syslog, поле `timestamp` | `2026-07-29T13:49:01Z` |
| Вложенный JSON, поле `datetime` | `2026-07-29T08:49:01.676724974Z` |
| Колонка `timestamp` в ClickHouse (UTC) | `2026-07-29 08:49:11` |

Отправитель пишет местное время (UTC+5) и помечает его суффиксом `Z`, то есть маркирует как UTC. Реальное UTC содержится только во вложенном `datetime`.

**Действие:** исправить формирование метки времени на отправителе. До исправления — брать время **только** из вложенного `datetime`, иначе корреляция по времени даст сдвиг на 5 часов.

### 7.3. Незаполненные поля коллектора

`art` = `1970-01-01 00:00:00.000`, `sourceIp` = `::` во всех событиях. Время получения и адрес источника не заполняются — невозможно отличить задержку доставки от задержки на самом хосте.

### 7.4. Периодика самих событий — требует отдельного разбора

За окно ~2 часа 29.07.2026 собрано **2508 уникальных событий** `sys_logging_*` по всему парку `veeam*`. Цикл строго периодический — **300 секунд**, у каждого хоста свой фазовый сдвиг.

Пример, `veeam045-2`:

```
09:26:01.166  sys_logging_enabled   INFO
09:26:09.679  sys_logging_disabled  CRITICAL   ← +8.5 c
09:31:02.178  sys_logging_enabled   INFO       ← +300 c
09:31:10.672  sys_logging_disabled  CRITICAL   ← +8.5 c
09:36:03.163  sys_logging_enabled   INFO
09:41:04.163  sys_logging_enabled   INFO
09:41:12.654  sys_logging_disabled  CRITICAL
```

Тот же рисунок на `veeam046`, `veeam046-2`, `veeam047`, `veeam047-2`, `veeam048`, `veeam048-2`.

**Интерпретация.** Строгая периодичность и синхронность по десяткам хостов означают автоматику (cron / systemd timer / агент), а не действия человека — на целенаправленную атаку это не похоже.

Но важен порядок внутри цикла: `enabled` держится примерно **8 секунд**, затем `disabled` на оставшиеся ~292. То есть security-логирование на этих хостах выключено **порядка 97% времени**. Это следует эскалировать независимо от причины.

**Действие:** найти на хостах `veeam*` задание с интервалом 5 минут, которое дёргает audit/snapd, и выяснить, почему логирование остаётся выключенным между срабатываниями.
