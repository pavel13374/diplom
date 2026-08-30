#!/usr/bin/env bash
# =====================================================================
#  ДИАГНОСТИКА GITLAB  —  только чтение, ничего не меняет
#
#  Запуск на 192.168.1.43:
#     sudo bash gitlab-diag.sh 2>&1 | tee /tmp/gitlab-diag.txt
#
#  Пришлите /tmp/gitlab-diag.txt целиком.
#
#  Что мы уже знаем: https://gitlab.polenov.ru отдаёт 404 от nginx/1.22.1.
#  404 (а не 502) означает, что отвечает НЕ GitLab: nginx жив, но запрос
#  не доходит до приложения. Дальше — три типовые причины, и скрипт
#  проверяет каждую.
# =====================================================================
set -u
line(){ printf '\n=== %s ===\n' "$1"; }

line "1. КТО СЛУШАЕТ 80/443"
# Ключевой вопрос. GitLab Omnibus поднимает СВОЙ nginx. Если порты уже
# занял системный nginx (в Debian 12 это как раз 1.22.1 — совпадает с
# тем, что вы видите), gitlab-nginx не стартует, а системный отдаёт 404
# со своего дефолтного сайта.
ss -tlnp 2>/dev/null | grep -E ':(80|443)\b' || netstat -tlnp 2>/dev/null | grep -E ':(80|443)\b'

line "2. СИСТЕМНЫЙ NGINX (не тот, что от GitLab)"
systemctl is-enabled nginx 2>/dev/null; systemctl is-active nginx 2>/dev/null
nginx -v 2>&1
ls -l /etc/nginx/sites-enabled/ 2>/dev/null

line "3. СОСТОЯНИЕ GITLAB"
if command -v gitlab-ctl >/dev/null 2>&1; then
  gitlab-ctl status 2>&1 | head -40
else
  echo "gitlab-ctl НЕ НАЙДЕН — Omnibus-пакет не установлен."
  echo "Возможно, GitLab стоит в docker:"
  docker ps -a 2>/dev/null | head -20
fi

line "4. НАСТРОЕННЫЙ ВНЕШНИЙ АДРЕС"
# Если external_url не совпадает с gitlab.polenov.ru, у nginx GitLab нет
# server-блока под это имя, и запрос уходит в дефолтный — снова 404.
grep -E "^\s*external_url" /etc/gitlab/gitlab.rb 2>/dev/null || echo "нет /etc/gitlab/gitlab.rb"
grep -rn "server_name" /var/opt/gitlab/nginx/conf/ 2>/dev/null | head

line "5. МЕСТО НА ДИСКАХ  <-- вы писали, что его мало"
df -hT | grep -vE '^(tmpfs|devtmpfs|overlay)'
echo "--- inodes ---"
df -i | grep -vE '^(tmpfs|devtmpfs|overlay)'
echo "--- крупнейшие потребители ---"
du -shx /var/opt/gitlab /var/log/gitlab /var/lib/docker 2>/dev/null

line "6. БЛОЧНЫЕ УСТРОЙСТВА И LVM"
lsblk -o NAME,SIZE,FSTYPE,TYPE,MOUNTPOINT
echo "--- физические тома ---"; pvs 2>/dev/null
echo "--- группы томов ---";    vgs 2>/dev/null
echo "--- логические тома ---"; lvs 2>/dev/null

line "7. ЛОГИ GITLAB (последние ошибки)"
gitlab-ctl tail --quiet 2>/dev/null | tail -5
tail -n 30 /var/log/gitlab/nginx/gitlab_error.log 2>/dev/null
tail -n 20 /var/log/gitlab/gitlab-rails/production.log 2>/dev/null | tail -10

line "8. ПРОВЕРКА ИЗНУТРИ МАШИНЫ"
# Если локально отвечает GitLab, а снаружи 404 — дело в проксировании.
curl -skI http://127.0.0.1/  2>&1 | head -5
curl -skI https://127.0.0.1/ 2>&1 | head -5
echo "--- по имени ---"
curl -skI https://gitlab.polenov.ru/api/v4/version 2>&1 | head -5
echo "--- куда резолвится имя ---"
getent hosts gitlab.polenov.ru

line "ГОТОВО"
echo "Пришлите этот вывод целиком."
