# SOC Purple-Team Platform — контейнер для защиты диплома.
# Поднимает обе консоли (среда :8787 + Purple Team :8788) в offline-режиме
# (без внешнего GitLab). Демо-данные генерируются на старте.
FROM python:3.11-slim

# Шрифты с кириллицей для PDF-отчётов (reportlab -> DejaVu)
RUN apt-get update && apt-get install -y --no-install-recommends \
    fonts-dejavu-core curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# ПРИВЯЗКА К 0.0.0.0 ВНУТРИ КОНТЕЙНЕРА — ОБЯЗАТЕЛЬНА.
#
# Обе консоли по умолчанию слушают 127.0.0.1, и это правильно для запуска на
# машине разработчика. Но внутри контейнера петля недостижима снаружи: `docker
# compose up` публиковал 8787 и 8788, на которых никто не слушал, то есть
# документированное развёртывание одной командой не работало вовсе.
# Наружу порты выставляет compose, и только на 127.0.0.1 хоста.
ENV SOC_OFFLINE=1 \
    SOC_WEB_HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1

# ПАРОЛЬ НЕ ЗАШИТ В ОБРАЗ.
#
# Здесь стояло SOC_ADMIN_PASS=admin: известный пароль в слое образа, который
# вместе с публикацией портов на 0.0.0.0 давал открытую админ-консоль. Если
# переменная не задана, entrypoint сгенерирует пароль и напечатает его.
EXPOSE 8787 8788

# Оба процесса + генерация демо-данных при первом старте
CMD ["bash", "docker-entrypoint.sh"]
