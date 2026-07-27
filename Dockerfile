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

# offline по умолчанию (мир пишет события локально), демо-пароль для показа
ENV SOC_OFFLINE=1 \
    SOC_ADMIN_PASS=admin \
    PYTHONUNBUFFERED=1

EXPOSE 8787 8788

# Оба процесса + генерация демо-данных при первом старте
CMD ["bash", "docker-entrypoint.sh"]
