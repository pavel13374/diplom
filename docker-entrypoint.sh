#!/usr/bin/env bash
# Точка входа контейнера: демо-данные + обе консоли.
set -e
cd /app

# Свежие демо-данные, если стор пуст
if [ ! -f data/events.db ]; then
  echo "[entrypoint] генерирую демо-поток (норма + кампании)…"
  python tools/make_demo.py --fresh || echo "[entrypoint] make_demo не удался — продолжаю"
fi

echo "[entrypoint] запускаю Purple Team Console (:8788)…"
python console.py &
echo "[entrypoint] запускаю Environment Console (:8787)…"
python webapp.py &

# Ждём любой из процессов
wait -n
