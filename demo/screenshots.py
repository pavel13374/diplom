#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Автоскриншоты ключевых экранов для презентации и текста диплома (ретина 2x).

Требует playwright:
    pip install playwright
    playwright install chromium

Использование (обе консоли должны быть запущены, демо-данные сгенерированы):
    python demo/screenshots.py
Результат: demo/shots/*.png
"""
import os
import sys
import time

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shots")
ENV = "http://127.0.0.1:8787"
PT = "http://127.0.0.1:8788"

# (url, имя файла, что кликнуть перед снимком — селектор или None)
SHOTS = [
    (PT + "/executive", "01_executive", None),
    (PT + "/", "02_overview", None),
    (PT + "/", "03_workflow", "a[data-v=workflow]"),
    (PT + "/", "04_incidents", "a[data-v=incidents]"),
    (PT + "/", "05_attack", "a[data-v=attack]"),
    (PT + "/", "06_science", "a[data-v=science]"),
    (PT + "/", "07_trends", "a[data-v=trends]"),
    (PT + "/roi", "08_roi", None),
    (ENV + "/", "09_environment", None),
]


def main():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Нет playwright. Установи: pip install playwright && playwright install chromium")
        sys.exit(1)

    os.makedirs(OUT, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1280, "height": 800},
                                  device_scale_factor=2)
        page = ctx.new_page()

        # логин в консоль среды (:8787), если попросит
        for url, name, click in SHOTS:
            try:
                page.goto(url, wait_until="networkidle", timeout=15000)
                if "127.0.0.1:8787" in url and page.query_selector("input[name=username]"):
                    page.fill("input[name=username]", "admin")
                    page.fill("input[name=password]", os.environ.get("SOC_ADMIN_PASS", "admin"))
                    page.click("button[type=submit]")
                    page.wait_for_load_state("networkidle")
                if click:
                    el = page.query_selector(click)
                    if el:
                        el.click()
                        time.sleep(2.5)  # дать графикам отрисоваться
                else:
                    time.sleep(2.0)
                path = os.path.join(OUT, name + ".png")
                page.screenshot(path=path, full_page=True)
                print("сохранил", path)
            except Exception as e:
                print(f"[!] {name}: {e}")
        browser.close()
    print("Готово. Скриншоты в", OUT)


if __name__ == "__main__":
    main()
