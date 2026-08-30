#!/usr/bin/env bash
# Точка входа контейнера: демо-данные + обе консоли.
set -euo pipefail
cd /app

# ПАРОЛЬ: из окружения либо сгенерированный. В образе его нет намеренно —
# раньше Dockerfile зашивал SOC_ADMIN_PASS=admin прямо в слой.
if [ -z "${SOC_ADMIN_PASS:-}" ]; then
  SOC_ADMIN_PASS="$(python -c 'import secrets;print(secrets.token_urlsafe(12))')"
  export SOC_ADMIN_PASS
  echo "[entrypoint] SOC_ADMIN_PASS не задан — сгенерирован пароль: ${SOC_ADMIN_PASS}"
  echo "[entrypoint] задайте свой:  docker compose run -e SOC_ADMIN_PASS=... "
fi
export SOC_ADMIN_USER="${SOC_ADMIN_USER:-admin}"

# Свежие демо-данные, если стор пуст
if [ ! -f data/events.db ]; then
  echo "[entrypoint] генерирую демо-поток (норма + кампании)…"
  python tools/make_demo.py --fresh || echo "[entrypoint] make_demo не удался — продолжаю"
fi

# Корректное завершение: без этого docker stop убивал процессы по таймауту,
# а мир не успевал сохранить состояние и закрыть журнал.
pids=()
term() {
  echo "[entrypoint] останавливаю консоли…"
  for p in "${pids[@]}"; do kill -TERM "$p" 2>/dev/null || true; done
  wait || true
}
trap term TERM INT

echo "[entrypoint] запускаю Purple Team Console (:8788)…"
python console.py & pids+=($!)
echo "[entrypoint] запускаю Environment Console (:8787)…"
python webapp.py & pids+=($!)

# Ждём любой из процессов
wait -n
term
