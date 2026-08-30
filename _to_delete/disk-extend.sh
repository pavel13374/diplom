#!/usr/bin/env bash
# =====================================================================
#  РАСШИРЕНИЕ МЕСТА НА ДИСКЕ  (добавленный диск -> в существующий том)
#
#  Запуск:
#     sudo bash disk-extend.sh            # только ПОКАЗАТЬ план, ничего не делать
#     sudo bash disk-extend.sh --apply    # выполнить
#
#  Скрипт СПЕЦИАЛЬНО не делает ничего сам по умолчанию: операции с
#  томами необратимы, и «объединить всё» вслепую — верный способ
#  потерять данные. Сначала посмотрите план.
#
#  Что он умеет и чего НЕ умеет:
#    умеет  — добавить ЧИСТЫЙ диск в существующую LVM-группу и отдать
#             всё свободное место корневому (или указанному) тому;
#    не умеет — сливать разделы, на которых уже есть файловые системы
#             с данными; объединять диски без LVM. В этих случаях он
#             остановится и объяснит, что делать руками.
# =====================================================================
set -euo pipefail

APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1
say(){ printf '\n=== %s ===\n' "$1"; }
run(){ echo "+ $*"; [ "$APPLY" = "1" ] && "$@"; }

[ "$(id -u)" -eq 0 ] || { echo "нужен root: sudo bash $0"; exit 1; }

say "ТЕКУЩАЯ КАРТИНА"
lsblk -o NAME,SIZE,FSTYPE,TYPE,MOUNTPOINT
df -hT | grep -vE '^(tmpfs|devtmpfs|overlay)'

command -v pvs >/dev/null || { echo; echo "LVM не установлен: apt install -y lvm2"; exit 1; }

say "LVM"
pvs; vgs; lvs

# --- какой том хотим растить: тот, где смонтирован / (или $TARGET) ---
TARGET_MP="${TARGET:-/}"
SRC=$(findmnt -no SOURCE "$TARGET_MP")
echo
echo "Растим том, обслуживающий $TARGET_MP  ->  $SRC"

case "$SRC" in
  /dev/mapper/*|/dev/*/*)
    if ! lvs --noheadings -o lv_path 2>/dev/null | tr -d ' ' | grep -qx "$(readlink -f "$SRC")"; then
      echo
      echo "ОСТАНОВКА: $SRC — не логический том LVM."
      echo "Расширить его добавлением второго диска нельзя: это обычный раздел."
      echo "Варианты (делать осознанно, со снапшотом/бэкапом):"
      echo "  а) смонтировать новый диск отдельно и перенести на него"
      echo "     каталог данных GitLab: /var/opt/gitlab;"
      echo "  б) перевести систему на LVM — это переустановка."
      echo
      echo "Вариант (а) для GitLab — рабочий и обратимый, см. конец файла."
      exit 2
    fi
    ;;
  *) echo "ОСТАНОВКА: неожиданный источник монтирования $SRC"; exit 2;;
esac

VG=$(lvs --noheadings -o vg_name "$SRC" | tr -d ' ')
LV=$(lvs --noheadings -o lv_name "$SRC" | tr -d ' ')
FSTYPE=$(findmnt -no FSTYPE "$TARGET_MP")
echo "группа томов: $VG | логический том: $LV | ФС: $FSTYPE"

# --- ищем ЧИСТЫЕ диски: без ФС, без разделов, не смонтированы ---
say "ПОИСК ДОБАВЛЕННОГО ДИСКА"
CANDIDATES=()
while read -r name type fstype mp; do
  [ "$type" = "disk" ] || continue
  [ -z "$fstype" ] || continue
  [ -z "$mp" ] || continue
  # есть ли у диска разделы
  if [ "$(lsblk -no NAME "/dev/$name" | wc -l)" -gt 1 ]; then continue; fi
  # уже в LVM?
  if pvs --noheadings -o pv_name 2>/dev/null | tr -d ' ' | grep -qx "/dev/$name"; then continue; fi
  CANDIDATES+=("/dev/$name")
done < <(lsblk -rno NAME,TYPE,FSTYPE,MOUNTPOINT)

# Свободные экстенты В САМОЙ ГРУППЕ — самый частый случай, и первая версия
# скрипта его не покрывала: диск уже добавлен в VG, а логическому тому место
# не отдано. Именно так и оказалось на 192.168.1.43: VG 98G, из них 49G
# свободно, LV — 49G и заполнен на 89%. Новый диск искать не нужно вообще.
VG_FREE=$(vgs --noheadings --units g -o vg_free "$VG" | tr -d ' g' | cut -d. -f1)
VG_FREE=${VG_FREE:-0}

if [ "${#CANDIDATES[@]}" -eq 0 ] && [ "$VG_FREE" -lt 1 ]; then
  echo "Ни чистых дисков, ни свободного места в группе $VG не найдено."
  echo "Если диск добавлен, но уже размечен — проверьте вывод lsblk выше"
  echo "и убедитесь, что на нём НЕТ нужных данных."
  exit 3
fi

if [ "${#CANDIDATES[@]}" -eq 0 ]; then
  echo "Чистых дисков нет, но в группе $VG свободно ${VG_FREE}G —"
  echo "их и отдадим тому $LV. Добавлять ничего не нужно."
fi
if [ "${#CANDIDATES[@]}" -gt 0 ]; then
  echo "найдены чистые диски: ${CANDIDATES[*]}"
  for d in "${CANDIDATES[@]}"; do echo "  $d  $(lsblk -dno SIZE "$d")"; done
fi

say "ПЛАН"
for d in "${CANDIDATES[@]}"; do
  echo "  pvcreate $d            # пометить как физический том"
  echo "  vgextend $VG $d        # добавить в группу $VG"
done
echo "  lvextend -l +100%FREE /dev/$VG/$LV     # отдать всё свободное тому $LV"
case "$FSTYPE" in
  ext4|ext3|ext2) echo "  resize2fs /dev/$VG/$LV                 # растянуть ФС";;
  xfs)            echo "  xfs_growfs $TARGET_MP                  # растянуть ФС";;
  *)              echo "  ВНИМАНИЕ: ФС $FSTYPE — растяните вручную";;
esac

if [ "$APPLY" != "1" ]; then
  echo
  echo "Это был только план. Выполнить:  sudo bash $0 --apply"
  exit 0
fi

say "ВЫПОЛНЕНИЕ"
for d in "${CANDIDATES[@]}"; do
  run pvcreate -y "$d"
  run vgextend "$VG" "$d"
done
run lvextend -l +100%FREE "/dev/$VG/$LV"
case "$FSTYPE" in
  ext4|ext3|ext2) run resize2fs "/dev/$VG/$LV";;
  xfs)            run xfs_growfs "$TARGET_MP";;
esac

say "РЕЗУЛЬТАТ"
df -hT "$TARGET_MP"
vgs; lvs

cat <<'NOTE'

--- ЕСЛИ LVM НЕТ (вариант «а») -------------------------------------
Перенести данные GitLab на новый диск, не трогая систему:

  sudo gitlab-ctl stop
  sudo mkfs.ext4 /dev/sdX                      # НОВЫЙ пустой диск
  sudo mkdir -p /mnt/newdisk && sudo mount /dev/sdX /mnt/newdisk
  sudo rsync -aHAX --info=progress2 /var/opt/gitlab/ /mnt/newdisk/
  sudo mv /var/opt/gitlab /var/opt/gitlab.old   # старое НЕ удаляем сразу
  sudo mkdir /var/opt/gitlab
  sudo umount /mnt/newdisk
  echo "/dev/sdX /var/opt/gitlab ext4 defaults 0 2" | sudo tee -a /etc/fstab
  sudo mount -a && sudo gitlab-ctl reconfigure && sudo gitlab-ctl start

Убедившись, что всё работает, освободите место:
  sudo rm -rf /var/opt/gitlab.old
NOTE
