# Detection-as-Code

Правила детектирования живут в `detections/*.json` (формат — наш «Sigma-lite»):
условие по НАБЛЮДАЕМЫМ полям события → alert с привязкой к MITRE ATT&CK.
Движок `detector.py` потоково применяет их к событиям из event-store.

Схема правила:
{
  "id": "...", "title": "...", "technique": "T1xxx", "tactic": "...",
  "severity": "low|medium|high|critical", "risk": 0.0-1.0,
  "when": { "<field>": <value> | {"<op>": <value>} }
}
Операторы: ==(прямое значение), ">=",">","<=","<","ne","in","nin","contains".
