#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC Simulator — панель запуска (нативное приложение, светлая тема).

Главное окно делает ровно одно: запускает/останавливает два сайта и показывает
их логи раздельно. Плюс кнопка сброса данных для чистого перезапуска.

  • «Мир»     (webapp.py)  — рабочая среда команды + атаки;
  • «Защита»  (console.py) — SOC-консоль, ловит атаки.

Логи каждого сайта пишутся в logs/world.log и logs/defense.log и видны в окне.
Tkinter входит в стандартный Python — отдельных зависимостей нет.

Запуск:  python launcher.py   (или двойной клик по START_PANEL.bat)
"""
import os
import sys
import time
import queue
import threading
import subprocess
import webbrowser

import tkinter as tk
from tkinter import scrolledtext, messagebox

BASE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable or "python"
LOGS = os.path.join(BASE, "logs")
os.makedirs(LOGS, exist_ok=True)

CHILD_ENV = dict(os.environ)
CHILD_ENV["PYTHONUTF8"] = "1"
CHILD_ENV["PYTHONIOENCODING"] = "utf-8"
CHILD_ENV["PYTHONUNBUFFERED"] = "1"

# --- светлая палитра ---
BG = "#eef1f6"; CARD = "#ffffff"; INK = "#1f2733"; MUT = "#6b7480"; LINE = "#dce1ea"
BLUE = "#2563eb"; GREEN = "#16a34a"; RED = "#dc2626"; GREY = "#64748b"; LOGBG = "#f8fafc"

SITES = {
    "world":   {"title": "Мир", "script": "webapp.py", "url": "http://127.0.0.1:8787",
                "log": os.path.join(LOGS, "world.log"),
                "desc": "Рабочий день команды в GitLab, среди которого прячутся атаки."},
    "defense": {"title": "Защита", "script": "console.py", "url": "http://127.0.0.1:8788",
                "log": os.path.join(LOGS, "defense.log"),
                "desc": "SOC-консоль: сама ловит атаки в потоке и показывает их."},
}

class Launcher:
    def __init__(self, root):
        self.root = root
        self.proc = {}                 # key -> Popen
        self.dot = {}                  # key -> status label
        self.logbox = {}               # key -> scrolledtext
        self.q = {k: queue.Queue() for k in SITES}
        self.q["_x"] = queue.Queue()   # лог доп. задач / системных сообщений
        self._hstate = {}              # key -> цвет точки по реальному HTTP-ответу
        self._build()
        self.root.after(120, self._drain)
        threading.Thread(target=self._health_loop, daemon=True).start()
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    # ---------------- UI ----------------
    def _btn(self, parent, text, cmd, bg, fg="#ffffff", big=False):
        return tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg, activebackground=bg,
                         activeforeground=fg, relief="flat", bd=0, cursor="hand2",
                         font=("Segoe UI", 11 if big else 10, "bold"),
                         padx=18 if big else 12, pady=10 if big else 7)

    def _build(self):
        self.root.title("SOC Simulator")
        self.root.configure(bg=BG)
        self.root.geometry("1080x760")
        self.root.minsize(900, 620)

        head = tk.Frame(self.root, bg=BG); head.pack(fill="x", padx=22, pady=(18, 4))
        tk.Label(head, text="SOC Simulator", bg=BG, fg=INK,
                 font=("Segoe UI", 20, "bold")).pack(side="left")
        tk.Label(head, text="  обнаружение компрометации секретов в CI/CD",
                 bg=BG, fg=MUT, font=("Segoe UI", 11)).pack(side="left", pady=(8, 0))

        bar = tk.Frame(self.root, bg=BG); bar.pack(fill="x", padx=22, pady=(8, 4))
        self._btn(bar, "▶  Запустить", self.start_all, GREEN, big=True).pack(side="left")
        self._btn(bar, "■  Остановить", self.stop_all, GREY, big=True).pack(side="left", padx=8)
        self._btn(bar, "⟲  Сброс данных", self.reset, RED, big=True).pack(side="left", padx=8)

        st = tk.Frame(bar, bg=BG); st.pack(side="right")
        for key in SITES:
            f = tk.Frame(st, bg=CARD, highlightbackground=LINE, highlightthickness=1)
            f.pack(side="left", padx=5, ipadx=8, ipady=5)
            d = tk.Label(f, text="●", bg=CARD, fg="#cbd5e1", font=("Segoe UI", 11))
            d.pack(side="left", padx=(6, 4))
            tk.Label(f, text=SITES[key]["title"], bg=CARD, fg=INK,
                     font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 4))
            tk.Button(f, text="открыть ↗", command=lambda k=key: webbrowser.open(SITES[k]["url"]),
                      bg=CARD, fg=BLUE, activebackground=CARD, activeforeground=BLUE,
                      relief="flat", bd=0, cursor="hand2",
                      font=("Segoe UI", 8, "underline")).pack(side="left", padx=(0, 6))
            self.dot[key] = d

        tk.Label(self.root, text="После запуска откроются оба сайта в браузере. "
                 "На сайте «Мир» нажмите зелёную кнопку Start, чтобы пошла жизнь команды и атаки. "
                 "Точка: серая — выключен, оранжевая — поднимается, зелёная — сайт отвечает.",
                 bg=BG, fg=MUT, font=("Segoe UI", 9), anchor="w").pack(fill="x", padx=24, pady=(2, 6))

        logs = tk.Frame(self.root, bg=BG); logs.pack(fill="both", expand=True, padx=22, pady=(2, 6))
        for col, key in enumerate(SITES):
            logs.columnconfigure(col, weight=1)
            logs.rowconfigure(0, weight=1)
            card = tk.Frame(logs, bg=CARD, highlightbackground=LINE, highlightthickness=1)
            card.grid(row=0, column=col, sticky="nsew", padx=(0, 8) if col == 0 else (8, 0))
            tk.Label(card, text=f"Логи · {SITES[key]['title']}", bg=CARD, fg=INK,
                     font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=12, pady=(10, 2))
            tk.Label(card, text=SITES[key]["desc"], bg=CARD, fg=MUT,
                     font=("Segoe UI", 9), wraplength=470, justify="left").pack(anchor="w", padx=12)
            box = scrolledtext.ScrolledText(card, bg=LOGBG, fg="#334155", relief="flat",
                                            font=("Consolas", 9), wrap="word", height=10,
                                            highlightthickness=0, bd=0)
            box.pack(fill="both", expand=True, padx=10, pady=(10, 4))
            self.logbox[key] = box
            brow = tk.Frame(card, bg=CARD); brow.pack(fill="x", padx=10, pady=(0, 8))
            self._btn(brow, "📋 Копировать", lambda k=key: self._copy_log(k), "#e2e8f4", fg=INK).pack(side="left")
            self._btn(brow, "📂 Открыть файл", lambda k=key: self._open_log(k), "#e2e8f4", fg=INK).pack(side="left", padx=6)

        # Нижний ряд — только строка статуса. Служебные кнопки (тесты,
        # наблюдатель за GitLab, демо-данные, отчёты) убраны: для запуска
        # и мониторинга они не нужны, а эти задачи запускаются командой
        # из терминала, когда действительно требуются.
        foot = tk.Frame(self.root, bg=BG); foot.pack(fill="x", padx=22, pady=(4, 14))
        self.status = tk.Label(foot, text="готово", bg=BG, fg=MUT, font=("Segoe UI", 9))
        self.status.pack(side="left")
        self.status.configure(text="Нажмите «Запустить», затем на сайте «Мир» — зелёную кнопку Start.")

    # ---------------- процессы ----------------
    def start_all(self):
        any_started = False
        for key in SITES:
            if self.proc.get(key) and self.proc[key].poll() is None:
                continue
            self._start_one(key); any_started = True
        if not any_started:
            self.status.configure(text="Оба сайта уже запущены.")
            return
        self.root.after(1900, lambda: [webbrowser.open(SITES[k]["url"]) for k in SITES])

    def _start_one(self, key):
        info = SITES[key]
        try:
            os.makedirs(LOGS, exist_ok=True)   # папку могли удалить сбросом
            logf = open(info["log"], "a", encoding="utf-8")
            logf.write(f"\n===== запуск {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n"); logf.flush()
            p = subprocess.Popen([PY, info["script"]], cwd=BASE, env=CHILD_ENV,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, encoding="utf-8", errors="replace", bufsize=1)
            self.proc[key] = p
            self._set(key, True)
            self._hstate[key] = "#d97706"   # поднимается
            threading.Thread(target=self._reader, args=(key, p, logf), daemon=True).start()
            self.q[key].put(f"[панель] запускаю {info['script']}…")
        except Exception as e:
            self.q[key].put(f"[ошибка] {e}")

    def _reader(self, key, p, logf):
        """Перекачивает вывод дочернего процесса в панель и в файл.

        `logf` закрывается в finally: файл открывается на каждый запуск, и без
        этого дескрипторы копились бы по одному за «Запустить/Остановить», а на
        Windows открытый файл ещё и не даёт переименовать себя при ротации.
        """
        try:
            for line in p.stdout:
                line = line.rstrip("\n")
                self.q[key].put(line)
                try:
                    logf.write(line + "\n"); logf.flush()
                except OSError:
                    pass
        except Exception:
            pass
        finally:
            try:
                logf.close()
            except OSError:
                pass
        self.q[key].put("[панель] процесс завершился.")
        self.q["_x"].put(("_down", key))

    def stop_all(self):
        stopped = 0
        for key, p in list(self.proc.items()):
            if p and p.poll() is None:
                self._terminate(p); stopped += 1
            self._set(key, False)
            self._hstate[key] = "#cbd5e1"
        self.status.configure(text=(f"Остановлено сайтов: {stopped}." if stopped else "Сайты не запущены."))

    def _terminate(self, p):
        try:
            p.terminate()
            for _ in range(20):
                if p.poll() is not None:
                    return
                time.sleep(0.05)
            p.kill()
        except Exception:
            pass

    def reset(self):
        running = [k for k, p in self.proc.items() if p and p.poll() is None]
        if running:
            if not messagebox.askyesno("Сброс данных",
                    "Сайты запущены. Остановить их и удалить все накопленные данные\n"
                    "(журнал событий, логи, отчёты, результаты)?"):
                return
            self.stop_all(); time.sleep(0.6)
        elif not messagebox.askyesno("Сброс данных",
                "Удалить локальные данные (журнал событий, логи, отчёты, результаты)?\n"
                "GitLab (репозитории и сотрудники) НЕ трогаем — они переиспользуются.\n"
                "Код и настройки не пострадают."):
            return
        # Сброс ТОЛЬКО локальных данных. GitLab не сносим — деструктивный снос
        # копит «pending deletion» и блокирует аккаунты; репо/юзеры переиспользуются.
        self.run_extra("Сброс данных", ["tools/reset_data.py", "--yes"])

    def run_extra(self, label, args):
        self.status.configure(text=f"выполняется: {label}…", fg="#b45309")
        threading.Thread(target=self._run_extra, args=(label, args), daemon=True).start()

    def _run_extra(self, label, args):
        try:
            p = subprocess.Popen([PY] + args, cwd=BASE, env=CHILD_ENV,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, encoding="utf-8", errors="replace", bufsize=1)
            for line in p.stdout:
                self.q["_x"].put(line.rstrip("\n"))
            p.wait()
            self.q["_x"].put(("_done", f"✔ {label} (код {p.returncode})"))
        except Exception as e:
            self.q["_x"].put(("_done", f"✖ {label}: {e}"))

    # ---------------- helpers ----------------
    def _copy_log(self, key):
        try:
            txt = self.logbox[key].get("1.0", "end-1c")
            self.root.clipboard_clear(); self.root.clipboard_append(txt)
            self.root.update()  # закрепить буфер
            self.status.configure(text=f"Лог «{SITES[key]['title']}» скопирован ({len(txt)} симв.)")
        except Exception as e:
            self.status.configure(text=f"копирование не удалось: {e}")

    def _open_log(self, key):
        path = SITES[key]["log"]
        try:
            os.makedirs(LOGS, exist_ok=True)
            if not os.path.exists(path):
                open(path, "a", encoding="utf-8").close()
            if hasattr(os, "startfile"):
                os.startfile(path)          # Windows
            else:
                subprocess.Popen(["xdg-open", path])
            self.status.configure(text=f"Открыт файл: {os.path.basename(path)}")
        except Exception as e:
            self.status.configure(text=f"не удалось открыть файл: {e}")

    def _set(self, key, on):
        self.dot[key].configure(fg=(GREEN if on else "#cbd5e1"))

    def _append(self, key, text):
        box = self.logbox[key]
        box.insert("end", text + "\n")
        if int(box.index("end-1c").split(".")[0]) > 600:
            box.delete("1.0", "200.0")
        box.see("end")

    def _drain(self):
        for key in SITES:
            try:
                while True:
                    self._append(key, self.q[key].get_nowait())
            except queue.Empty:
                pass
        for hk, col in list(self._hstate.items()):
            try:
                self.dot[hk].configure(fg=col)
            except Exception:
                pass
        try:
            while True:
                item = self.q["_x"].get_nowait()
                if isinstance(item, tuple) and item[0] == "_down":
                    self._set(item[1], False)
                elif isinstance(item, tuple) and item[0] == "_done":
                    self.status.configure(text=item[1], fg=MUT)
                else:
                    self._append("defense", item)
        except queue.Empty:
            pass
        self.root.after(150, self._drain)

    # ---------- живой статус сайтов: реальный HTTP-ответ, не только процесс ----------
    def _health_loop(self):
        import urllib.request
        import urllib.error
        while True:
            for key in SITES:
                p = self.proc.get(key)
                if not p or p.poll() is not None:
                    self._hstate[key] = "#cbd5e1"      # выключен
                    continue
                try:
                    urllib.request.urlopen(SITES[key]["url"], timeout=1.5)
                    self._hstate[key] = GREEN          # сайт отвечает
                except urllib.error.HTTPError:
                    self._hstate[key] = GREEN          # 302/401 — тоже «жив»
                except Exception:
                    self._hstate[key] = "#d97706"      # процесс есть, HTTP молчит
            time.sleep(3)

    def _close(self):
        for p in self.proc.values():
            self._terminate(p)
        self.root.destroy()


def main():
    root = tk.Tk()
    Launcher(root)
    root.mainloop()


if __name__ == "__main__":
    main()
