"""
Модель угроз контура разработки — матрица MITRE ATT&CK Enterprise, техники
которой в принципе наблюдаемы по событиям git, CI/CD и GitLab API.

Вынесена в отдельный модуль, чтобы и консоль защиты (страница «Покрытие»),
и оффлайн-метрики (metrics.py) считали покрытие по ОДНОМУ и тому же честному
знаменателю. Иначе метрика «покрытие» на дашборде и на «Трендах»
рассинхронизировались: одна брала всю матрицу (72%), другая — только
атакованные техники (всегда ~100%, метрика мерила саму себя).

В матрице есть техники БЕЗ правил — они честно горят как слепые зоны и
образуют очередь работ для detection engineering. Ненаблюдаемые в этом
контуре техники (фишинг, эндпоинт, сеть) сюда намеренно не включены:
их отсутствие — граница системы, а не пробел в правилах.
"""

ATTACK = [
    ("Reconnaissance",      [("T1087", "Account/Repo Discovery"),
                             ("T1593.003", "Search Code Repositories")]),
    ("Initial Access",      [("T1078", "Valid Accounts"),
                             ("T1195.002", "Supply Chain"),
                             ("T1195.001", "Compromise Software Dependencies"),
                             ("T1199", "Trusted Relationship")]),
    ("Execution",           [("T1059", "Command/Script Interpreter"),
                             ("T1072", "Software Deployment Tools"),
                             ("T1053", "Scheduled Task/Job")]),
    ("Persistence",         [("T1098.001", "Additional Cloud Credentials"),
                             ("T1098", "Account Manipulation"),
                             ("T1136.003", "Create Cloud Account"),
                             ("T1505", "Server Software Component")]),
    ("Privilege Escalation",[("T1098", "Account Manipulation"),
                             ("T1548", "Abuse Elevation Control"),
                             ("T1078.004", "Valid Accounts: Cloud")]),
    ("Defense Evasion",     [("T1562", "Impair Defenses"),
                             ("T1562.001", "Disable/Modify Tools"),
                             ("T1556", "Modify Auth Process"),
                             ("T1070.004", "Indicator Removal: File Deletion"),
                             ("T1027", "Obfuscated Files or Information"),
                             ("T1550.001", "Application Access Token")]),
    ("Credential Access",   [("T1552.001", "Credentials In Files"),
                             ("T1552", "Unsecured Credentials"),
                             ("T1552.004", "Private Keys"),
                             ("T1552.007", "Container API Credentials"),
                             ("T1528", "Steal Application Access Token"),
                             ("T1555", "Credentials from Password Stores")]),
    ("Discovery",           [("T1069", "Permission Groups Discovery"),
                             ("T1526", "Cloud Service Discovery"),
                             ("T1518", "Software Discovery"),
                             ("T1613", "Container and Resource Discovery")]),
    ("Lateral Movement",    [("T1021.004", "Remote Services: SSH"),
                             ("T1080", "Taint Shared Content")]),
    ("Collection",          [("T1213", "Data from Repositories"),
                             ("T1114.003", "Email Forwarding Rule"),
                             ("T1119", "Automated Collection"),
                             ("T1074", "Data Staged")]),
    ("Command and Control", [("T1102", "Web Service"),
                             ("T1071.001", "Web Protocols")]),
    ("Exfiltration",        [("T1567", "Exfil Over Web Service"),
                             ("T1537", "Transfer to Cloud Account"),
                             ("T1048", "Exfil Over Alternative Protocol"),
                             ("T1030", "Data Transfer Size Limits")]),
    ("Impact",              [("T1485", "Data Destruction"),
                             ("T1565.001", "Stored Data Manipulation"),
                             ("T1490", "Inhibit System Recovery")]),
]


def all_techniques():
    """Множество уникальных ID техник в матрице (честный знаменатель покрытия)."""
    return {t for _, lst in ATTACK for t, _ in lst}
