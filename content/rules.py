"""
Генератор контента для Sigma-правил.
Большой банк техник (≈100), индикаторов и вариаций.
"""
import uuid
import random
from datetime import date
import simclock

# -----------------------------------------------------------------------
# Банк техник MITRE ATT&CK
# -----------------------------------------------------------------------
TECHNIQUES = [
    {
        "id": "T1003.001", "tactic": "credential_access",
        "title": "LSASS Memory Dump via ProcDump",
        "description": "Detects credential dumping from LSASS memory using ProcDump or similar tools",
        "tools": ["procdump.exe", "procdump64.exe", "nanodump.exe", "createdump.exe"],
        "cmdline": ["lsass", "sekurlsa", "-ma lsass"],
        "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows",
        "level": "high",
    },
    {
        "id": "T1003.002", "tactic": "credential_access",
        "title": "SAM Database Credential Extraction",
        "description": "Detects attempts to access SAM database to extract local account credentials",
        "tools": ["reg.exe", "esentutl.exe"],
        "cmdline": ["save HKLM\\\\SAM", "sam", "system hive"],
        "eventid": "4663", "logsource_cat": "file_access", "logsource_prod": "windows",
        "level": "high",
    },
    {
        "id": "T1059.001", "tactic": "execution",
        "title": "Suspicious PowerShell Encoded Command",
        "description": "Detects PowerShell execution with encoded commands often used to evade detection",
        "tools": ["powershell.exe", "pwsh.exe"],
        "cmdline": ["-EncodedCommand", "-enc ", "-e ", "bypass", "-nop", "-windowstyle hidden"],
        "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows",
        "level": "medium",
    },
    {
        "id": "T1059.003", "tactic": "execution",
        "title": "Suspicious CMD Execution via Office Application",
        "description": "Detects cmd.exe launched from Office applications indicating macro execution",
        "tools": ["cmd.exe"],
        "cmdline": ["cmd /c", "cmd.exe /c", "/q /c"],
        "parent": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"],
        "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows",
        "level": "high",
    },
    {
        "id": "T1053.005", "tactic": "persistence",
        "title": "Scheduled Task Created by Non-System Process",
        "description": "Detects creation of scheduled tasks by unexpected parent processes",
        "tools": ["schtasks.exe"],
        "cmdline": ["/create", "/sc onlogon", "/sc onstartup", "/ru SYSTEM"],
        "eventid": "4698", "logsource_cat": "process_creation", "logsource_prod": "windows",
        "level": "medium",
    },
    {
        "id": "T1547.001", "tactic": "persistence",
        "title": "Registry Run Key Modification",
        "description": "Detects modification of registry run keys for persistence",
        "keys": ["HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
                 "HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
                 "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon"],
        "eventid": "4657", "logsource_cat": "registry_set", "logsource_prod": "windows",
        "level": "medium",
    },
    {
        "id": "T1071.001", "tactic": "command_and_control",
        "title": "Suspicious User-Agent in HTTP Traffic",
        "description": "Detects HTTP traffic with suspicious or custom user agents used by malware C2",
        "ua": ["python-requests", "curl/", "Go-http-client", "sqlmap", "Nuclei"],
        "eventid": None, "logsource_cat": "proxy", "logsource_prod": None,
        "level": "medium",
    },
    {
        "id": "T1048.001", "tactic": "exfiltration",
        "title": "DNS Query with Unusually Long Subdomain",
        "description": "Detects DNS queries with abnormally long subdomains indicative of DNS tunneling",
        "eventid": None, "logsource_cat": "dns", "logsource_prod": None,
        "level": "medium",
    },
    {
        "id": "T1550.002", "tactic": "lateral_movement",
        "title": "Pass-the-Hash via NTLM LogonType 3",
        "description": "Detects pass-the-hash attacks through anomalous NTLM network logon with zero key length",
        "eventid": "4624", "logsource_cat": "security", "logsource_prod": "windows",
        "level": "high",
    },
    {
        "id": "T1558.003", "tactic": "credential_access",
        "title": "Kerberoasting via TGS-REQ with RC4",
        "description": "Detects Kerberoasting attacks requesting service tickets with weak RC4 encryption",
        "eventid": "4769", "logsource_cat": "security", "logsource_prod": "windows",
        "level": "high",
    },
    {
        "id": "T1021.001", "tactic": "lateral_movement",
        "title": "RDP Brute Force from External Source",
        "description": "Detects repeated RDP login failures from external IP addresses",
        "eventid": "4625", "logsource_cat": "security", "logsource_prod": "windows",
        "level": "medium",
    },
    {
        "id": "T1078.004", "tactic": "initial_access",
        "title": "AWS IAM Key Used from Unusual Region",
        "description": "Detects AWS API calls from regions not previously seen for this IAM user",
        "eventid": None, "logsource_cat": "cloudtrail", "logsource_prod": "aws",
        "level": "high",
    },
    {
        "id": "T1190", "tactic": "initial_access",
        "title": "Web Application Exploit Attempt",
        "description": "Detects common web application exploitation patterns in HTTP logs",
        "patterns": ["../../../", "etc/passwd", "union select", "<script>", "cmd.exe"],
        "eventid": None, "logsource_cat": "webserver", "logsource_prod": None,
        "level": "high",
    },
    {
        "id": "T1486", "tactic": "impact",
        "title": "Mass File Rename Indicating Ransomware",
        "description": "Detects abnormal mass file renaming activity indicative of ransomware encryption",
        "eventid": "4663", "logsource_cat": "file_access", "logsource_prod": "windows",
        "level": "critical",
    },
    {
        "id": "T1136.001", "tactic": "persistence",
        "title": "New Local User Account Created",
        "description": "Detects creation of new local user accounts which may indicate backdoor",
        "eventid": "4720", "logsource_cat": "security", "logsource_prod": "windows",
        "level": "medium",
    },
    {
        "id": "T1562.001", "tactic": "defense_evasion",
        "title": "Windows Defender Disabled via Registry",
        "description": "Detects disabling of Windows Defender real-time protection via registry modification",
        "keys": ["HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender"],
        "eventid": "4657", "logsource_cat": "registry_set", "logsource_prod": "windows",
        "level": "high",
    },
    {
        "id": "T1070.001", "tactic": "defense_evasion",
        "title": "Windows Event Log Cleared",
        "description": "Detects clearing of Windows event logs used to cover attacker tracks",
        "eventid": "1102", "logsource_cat": "security", "logsource_prod": "windows",
        "level": "high",
    },
    {
        "id": "T1505.003", "tactic": "persistence",
        "title": "Web Shell Creation in Web Root",
        "description": "Detects creation of script files in web server directories",
        "extensions": [".php", ".aspx", ".jsp", ".ashx"],
        "paths": ["\\\\wwwroot\\\\", "\\\\inetpub\\\\", "/var/www/", "/srv/http/"],
        "eventid": "11", "logsource_cat": "sysmon", "logsource_prod": "windows",
        "level": "critical",
    },
    {
        "id": "T1027", "tactic": "defense_evasion",
        "title": "Suspicious Base64 Encoded PowerShell",
        "description": "Detects base64 encoded payloads in PowerShell command lines",
        "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows",
        "level": "medium",
    },
    {
        "id": "T1110.001", "tactic": "credential_access",
        "title": "SSH Brute Force Attack",
        "description": "Detects SSH brute force attempts via repeated authentication failures",
        "eventid": None, "logsource_cat": "ssh", "logsource_prod": "linux",
        "level": "medium",
    },
]

# -----------------------------------------------------------------------
# Расширенный банк техник (≈80 дополнительных). Доводим до ~100 техник,
# чтобы новые правила почти не повторялись и покрывали все тактики ATT&CK.
# -----------------------------------------------------------------------
TECHNIQUES += [
    # --- execution ---------------------------------------------------
    {"id": "T1059.005", "tactic": "execution", "title": "Malicious VBScript Execution via WScript",
     "description": "Detects wscript/cscript launching .vbs payloads from temp or download folders",
     "tools": ["wscript.exe", "cscript.exe"], "cmdline": [".vbs", ".vbe", "/e:vbscript"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1059.006", "tactic": "execution", "title": "Suspicious Python One-Liner Execution",
     "description": "Detects python launched with inline -c payloads spawning shells or sockets",
     "tools": ["python.exe", "python3", "python"], "cmdline": ["-c import", "socket", "base64", "exec("],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1047", "tactic": "execution", "title": "WMI Process Creation for Remote Execution",
     "description": "Detects use of wmic process call create commonly used for lateral execution",
     "tools": ["wmic.exe"], "cmdline": ["process call create", "/node:", "/user:"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1218.005", "tactic": "defense_evasion", "title": "Mshta Execution of Remote Payload",
     "description": "Detects mshta.exe loading remote HTA or javascript payloads (LOLBin abuse)",
     "tools": ["mshta.exe"], "cmdline": ["http", "javascript:", "vbscript:", ".hta"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1218.010", "tactic": "defense_evasion", "title": "Regsvr32 Scriptlet Execution (Squiblydoo)",
     "description": "Detects regsvr32 loading remote scriptlets to bypass application whitelisting",
     "tools": ["regsvr32.exe"], "cmdline": ["/i:http", "scrobj.dll", "/s /n /u"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1218.011", "tactic": "defense_evasion", "title": "Rundll32 Suspicious Export Execution",
     "description": "Detects rundll32 invoking suspicious or inline exports used for proxy execution",
     "tools": ["rundll32.exe"], "cmdline": ["javascript:", "url.dll,OpenURL", "shell32.dll,Control_RunDLL", ",#1"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1218.001", "tactic": "defense_evasion", "title": "CHM File Execution via hh.exe",
     "description": "Detects compiled HTML help files used to execute embedded scripts",
     "tools": ["hh.exe"], "cmdline": [".chm", "http"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1127.001", "tactic": "defense_evasion", "title": "MSBuild Inline Task Execution",
     "description": "Detects msbuild.exe compiling and running inline C# tasks to evade controls",
     "tools": ["msbuild.exe"], "cmdline": [".xml", ".csproj", "/noconsolelogger"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1197", "tactic": "defense_evasion", "title": "BITS Job Download of Payload",
     "description": "Detects bitsadmin used to download payloads stealthily",
     "tools": ["bitsadmin.exe"], "cmdline": ["/transfer", "/download", "http"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1105", "tactic": "command_and_control", "title": "Ingress Tool Transfer via certutil",
     "description": "Detects certutil downloading or decoding remote payloads",
     "tools": ["certutil.exe"], "cmdline": ["-urlcache", "-decode", "-f http", "-split"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1490", "tactic": "impact", "title": "Volume Shadow Copy Deletion",
     "description": "Detects deletion of shadow copies, a precursor to ransomware encryption",
     "tools": ["vssadmin.exe", "wmic.exe", "wbadmin.exe"], "cmdline": ["delete shadows", "shadowcopy delete", "delete catalog"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "critical"},
    {"id": "T1489", "tactic": "impact", "title": "Service Stop for Defense Disruption",
     "description": "Detects stopping of security or backup services prior to impact",
     "tools": ["net.exe", "sc.exe", "taskkill.exe"], "cmdline": ["stop", "config", "/f /im"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1112", "tactic": "defense_evasion", "title": "UAC Bypass via Registry Hijack",
     "description": "Detects registry modifications associated with known UAC bypass techniques",
     "keys": ["HKCU\\\\Software\\\\Classes\\\\ms-settings\\\\Shell\\\\Open\\\\command",
              "HKCU\\\\Software\\\\Classes\\\\mscfile\\\\shell\\\\open\\\\command",
              "HKCU\\\\Software\\\\Classes\\\\Folder\\\\shell\\\\open\\\\command"],
     "eventid": "4657", "logsource_cat": "registry_set", "logsource_prod": "windows", "level": "high"},
    {"id": "T1543.003", "tactic": "persistence", "title": "Windows Service Created for Persistence",
     "description": "Detects creation of a new Windows service pointing to suspicious binaries",
     "tools": ["sc.exe"], "cmdline": ["create", "binpath=", "start= auto"],
     "eventid": "7045", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1546.003", "tactic": "persistence", "title": "WMI Event Subscription Persistence",
     "description": "Detects creation of WMI event filters/consumers used for stealthy persistence",
     "eventid": "5861", "logsource_cat": "sysmon", "logsource_prod": "windows", "level": "high"},
    {"id": "T1546.008", "tactic": "persistence", "title": "Accessibility Feature Backdoor (sethc/utilman)",
     "description": "Detects replacement or debugger hijack of accessibility binaries",
     "keys": ["HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\sethc.exe",
              "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\utilman.exe"],
     "eventid": "4657", "logsource_cat": "registry_set", "logsource_prod": "windows", "level": "high"},
    {"id": "T1037.001", "tactic": "persistence", "title": "Logon Script Persistence via Registry",
     "description": "Detects UserInitMprLogonScript registry persistence",
     "keys": ["HKCU\\\\Environment\\\\UserInitMprLogonScript"],
     "eventid": "4657", "logsource_cat": "registry_set", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1574.002", "tactic": "persistence", "title": "DLL Side-Loading from Application Directory",
     "description": "Detects signed applications loading unsigned DLLs from writable paths",
     "eventid": "7", "logsource_cat": "sysmon", "logsource_prod": "windows", "level": "high"},
    {"id": "T1098", "tactic": "persistence", "title": "Account Manipulation — Group Membership Change",
     "description": "Detects addition of accounts to privileged groups",
     "tools": ["net.exe", "net1.exe"], "cmdline": ["localgroup administrators", "group \"Domain Admins\"", "/add"],
     "eventid": "4732", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1136.002", "tactic": "persistence", "title": "Domain Account Created",
     "description": "Detects creation of new domain accounts which may indicate backdoor",
     "eventid": "4720", "logsource_cat": "security", "logsource_prod": "windows", "level": "medium"},
    # --- privilege_escalation ---------------------------------------
    {"id": "T1134.001", "tactic": "privilege_escalation", "title": "Token Impersonation/Theft",
     "description": "Detects tools abusing SeImpersonatePrivilege (Potato family)",
     "tools": ["juicypotato.exe", "printspoofer.exe", "roguepotato.exe", "sweetpotato.exe"],
     "cmdline": ["-t", "-c", "-p cmd"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1055.001", "tactic": "privilege_escalation", "title": "Process Injection via CreateRemoteThread",
     "description": "Detects classic DLL/code injection into remote processes",
     "eventid": "8", "logsource_cat": "sysmon", "logsource_prod": "windows", "level": "high"},
    {"id": "T1548.002", "tactic": "privilege_escalation", "title": "Bypass UAC via fodhelper",
     "description": "Detects fodhelper.exe auto-elevation abuse for UAC bypass",
     "tools": ["fodhelper.exe", "computerdefaults.exe"], "cmdline": [""],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1068", "tactic": "privilege_escalation", "title": "Exploitation for Privilege Escalation (CVE driver)",
     "description": "Detects vulnerable signed driver loads used in BYOVD attacks",
     "eventid": "6", "logsource_cat": "sysmon", "logsource_prod": "windows", "level": "high"},
    # --- credential_access ------------------------------------------
    {"id": "T1003.003", "tactic": "credential_access", "title": "NTDS.dit Extraction via ntdsutil",
     "description": "Detects domain credential database extraction from a domain controller",
     "tools": ["ntdsutil.exe"], "cmdline": ["ac i ntds", "create full", "ifm"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "critical"},
    {"id": "T1003.006", "tactic": "credential_access", "title": "DCSync Replication Request",
     "description": "Detects directory replication requests indicative of DCSync credential theft",
     "eventid": "4662", "logsource_cat": "security", "logsource_prod": "windows", "level": "critical"},
    {"id": "T1558.001", "tactic": "credential_access", "title": "Golden Ticket Anomalous TGT",
     "description": "Detects Kerberos TGTs with anomalous lifetimes indicative of forged tickets",
     "eventid": "4768", "logsource_cat": "security", "logsource_prod": "windows", "level": "critical"},
    {"id": "T1552.001", "tactic": "credential_access", "title": "Credentials in Files Search",
     "description": "Detects mass searching of files for passwords and secrets",
     "tools": ["findstr.exe", "where.exe", "select-string"], "cmdline": ["password", "/si pass", "*.config", "unattend.xml"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1555.003", "tactic": "credential_access", "title": "Browser Credential Store Access",
     "description": "Detects access to browser saved-password databases",
     "eventid": "11", "logsource_cat": "sysmon", "logsource_prod": "windows", "level": "high"},
    {"id": "T1003.008", "tactic": "credential_access", "title": "Linux /etc/shadow Access",
     "description": "Detects unexpected reads of /etc/shadow on Linux hosts",
     "eventid": None, "logsource_cat": "auditd", "logsource_prod": "linux", "level": "high"},
    # --- discovery ---------------------------------------------------
    {"id": "T1087.002", "tactic": "discovery", "title": "Domain Account Discovery",
     "description": "Detects enumeration of domain users/groups via net or AD tools",
     "tools": ["net.exe", "net1.exe", "dsquery.exe"], "cmdline": ["user /domain", "group /domain", "accounts /domain"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "low"},
    {"id": "T1018", "tactic": "discovery", "title": "Remote System Discovery",
     "description": "Detects network host enumeration commonly run after initial access",
     "tools": ["net.exe", "nltest.exe", "arp.exe"], "cmdline": ["view", "/dclist", "-a"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "low"},
    {"id": "T1482", "tactic": "discovery", "title": "Domain Trust Discovery",
     "description": "Detects enumeration of domain trust relationships",
     "tools": ["nltest.exe"], "cmdline": ["/domain_trusts", "/all_trusts", "/trusted_domains"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1046", "tactic": "discovery", "title": "Network Service Scanning",
     "description": "Detects internal port scanning tools",
     "tools": ["nmap.exe", "masscan.exe", "advanced_port_scanner.exe"], "cmdline": ["-sS", "-p ", "--top-ports"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1057", "tactic": "discovery", "title": "Process Discovery via tasklist",
     "description": "Detects enumeration of running processes, often to find AV/EDR",
     "tools": ["tasklist.exe", "qprocess.exe"], "cmdline": ["/v", "/svc", "/fi"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "low"},
    {"id": "T1016", "tactic": "discovery", "title": "System Network Configuration Discovery",
     "description": "Detects ipconfig/route enumeration bursts post-compromise",
     "tools": ["ipconfig.exe", "route.exe", "netsh.exe"], "cmdline": ["/all", "print", "wlan show profile"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "low"},
    # --- lateral_movement -------------------------------------------
    {"id": "T1021.002", "tactic": "lateral_movement", "title": "SMB Admin Share Access (PsExec-like)",
     "description": "Detects service creation over SMB consistent with PsExec lateral movement",
     "tools": ["psexec.exe", "psexesvc.exe", "paexec.exe"], "cmdline": ["\\\\\\\\", "-accepteula", "-s cmd"],
     "eventid": "7045", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1021.006", "tactic": "lateral_movement", "title": "WinRM Remote Execution",
     "description": "Detects remote command execution via WinRM/WSMan",
     "tools": ["wsmprovhost.exe", "winrs.exe"], "cmdline": ["-r:", "invoke-command", "enter-pssession"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1570", "tactic": "lateral_movement", "title": "Lateral Tool Transfer over SMB",
     "description": "Detects copying of executables to remote admin shares",
     "tools": ["robocopy.exe", "xcopy.exe", "copy"], "cmdline": ["\\\\\\\\", "admin$", "c$\\\\"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1563.002", "tactic": "lateral_movement", "title": "RDP Hijacking via tscon",
     "description": "Detects session hijacking using tscon to attach to other RDP sessions",
     "tools": ["tscon.exe"], "cmdline": ["/dest:", "console"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    # --- collection --------------------------------------------------
    {"id": "T1560.001", "tactic": "collection", "title": "Archive Collected Data via 7zip/rar",
     "description": "Detects staging of data into password-protected archives before exfil",
     "tools": ["7z.exe", "rar.exe", "winrar.exe"], "cmdline": ["a -p", "-hp", "-r ", "-v100m"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1114.001", "tactic": "collection", "title": "Local Email Collection (PST export)",
     "description": "Detects bulk export of mailbox data to PST files",
     "eventid": "11", "logsource_cat": "sysmon", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1056.001", "tactic": "collection", "title": "Keylogging Hook Installation",
     "description": "Detects processes installing global keyboard hooks",
     "eventid": "8", "logsource_cat": "sysmon", "logsource_prod": "windows", "level": "high"},
    {"id": "T1113", "tactic": "collection", "title": "Screen Capture Utility Execution",
     "description": "Detects command-line screenshot tools run on endpoints",
     "tools": ["nircmd.exe", "screenshot.exe"], "cmdline": ["savescreenshot", "capture"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "medium"},
    # --- command_and_control ----------------------------------------
    {"id": "T1071.004", "tactic": "command_and_control", "title": "DNS-over-HTTPS C2 Beaconing",
     "description": "Detects suspicious periodic DoH requests to non-standard resolvers",
     "eventid": None, "logsource_cat": "proxy", "logsource_prod": None,
     "ua": ["dns-query", "application/dns-message"], "level": "medium"},
    {"id": "T1219", "tactic": "command_and_control", "title": "Remote Access Software Execution",
     "description": "Detects unsanctioned remote-access tools used for C2",
     "tools": ["anydesk.exe", "teamviewer.exe", " screenconnect.exe", "atera.exe", "ngrok.exe"],
     "cmdline": ["--silent", "--service", "tcp 3389", "authtoken"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1571", "tactic": "command_and_control", "title": "Non-Standard Port C2",
     "description": "Detects outbound connections to uncommon high ports from office hosts",
     "eventid": None, "logsource_cat": "proxy", "logsource_prod": None,
     "ua": [":4444", ":8443", ":1337", ":9001"], "level": "medium"},
    {"id": "T1572", "tactic": "command_and_control", "title": "Protocol Tunneling via SSH/iodine",
     "description": "Detects tunneling utilities used to bypass egress filtering",
     "tools": ["plink.exe", "iodine.exe", "chisel.exe"], "cmdline": ["-R ", "-L ", "client http"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    # --- exfiltration ------------------------------------------------
    {"id": "T1048.003", "tactic": "exfiltration", "title": "Exfiltration over Unencrypted Web to Paste Site",
     "description": "Detects uploads to paste/transfer services often used for exfil",
     "eventid": None, "logsource_cat": "proxy", "logsource_prod": None,
     "ua": ["pastebin.com", "transfer.sh", "anonfiles", "file.io", "0x0.st"], "level": "high"},
    {"id": "T1567.002", "tactic": "exfiltration", "title": "Exfiltration to Cloud Storage",
     "description": "Detects large uploads to personal cloud storage from corporate hosts",
     "eventid": None, "logsource_cat": "proxy", "logsource_prod": None,
     "ua": ["mega.nz", "dropboxapi", "drive.google", "wetransfer"], "level": "medium"},
    {"id": "T1041", "tactic": "exfiltration", "title": "Exfiltration over C2 Channel (large POST)",
     "description": "Detects abnormally large outbound POST bodies to rare domains",
     "eventid": None, "logsource_cat": "proxy", "logsource_prod": None,
     "ua": ["Content-Length: 10", "multipart/form-data"], "level": "medium"},
    # --- initial_access ----------------------------------------------
    {"id": "T1566.001", "tactic": "initial_access", "title": "Office Spawns Suspicious Child Process",
     "description": "Detects Office applications spawning scripting or shell processes from macros",
     "tools": ["cmd.exe", "powershell.exe", "mshta.exe", "wscript.exe"],
     "parent": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"],
     "cmdline": ["", "-enc", "http"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1133", "tactic": "initial_access", "title": "External Remote Service Logon Anomaly",
     "description": "Detects successful VPN/RDP logons from new geolocations",
     "eventid": "4624", "logsource_cat": "security", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1195.002", "tactic": "initial_access", "title": "Supply Chain — Unexpected Update Binary",
     "description": "Detects update agents spawning anomalous children (supply-chain abuse)",
     "eventid": "7", "logsource_cat": "sysmon", "logsource_prod": "windows", "level": "high"},
    {"id": "T1078.001", "tactic": "initial_access", "title": "Default Account Logon",
     "description": "Detects logons using default/guest accounts that should be disabled",
     "eventid": "4624", "logsource_cat": "security", "logsource_prod": "windows", "level": "medium"},
    # --- cloud / saas ------------------------------------------------
    {"id": "T1078.004b", "tactic": "initial_access", "title": "Impossible Travel Cloud Sign-in",
     "description": "Detects cloud sign-ins from two distant regions in a short window",
     "eventid": None, "logsource_cat": "cloudtrail", "logsource_prod": "azure",
     "patterns": ["impossibleTravel", "riskLevel:high"], "level": "high"},
    {"id": "T1098.001", "tactic": "persistence", "title": "Cloud Credential — New Access Key Created",
     "description": "Detects creation of new IAM access keys outside change windows",
     "eventid": None, "logsource_cat": "cloudtrail", "logsource_prod": "aws",
     "patterns": ["CreateAccessKey", "CreateLoginProfile"], "level": "high"},
    {"id": "T1530", "tactic": "collection", "title": "Cloud Storage Bucket Enumeration",
     "description": "Detects mass listing/download of S3 objects by a single principal",
     "eventid": None, "logsource_cat": "cloudtrail", "logsource_prod": "aws",
     "patterns": ["ListBuckets", "GetObject", "ListObjects"], "level": "medium"},
    {"id": "T1098.003", "tactic": "privilege_escalation", "title": "Cloud Role Policy Privilege Grant",
     "description": "Detects attaching of administrative policies to principals",
     "eventid": None, "logsource_cat": "cloudtrail", "logsource_prod": "aws",
     "patterns": ["AttachUserPolicy", "AttachRolePolicy", "AdministratorAccess"], "level": "high"},
    {"id": "T1562.008", "tactic": "defense_evasion", "title": "Cloud Logging Disabled",
     "description": "Detects disabling or deletion of CloudTrail/Audit logging",
     "eventid": None, "logsource_cat": "cloudtrail", "logsource_prod": "aws",
     "patterns": ["StopLogging", "DeleteTrail", "PutEventSelectors"], "level": "high"},
    # --- web / network ----------------------------------------------
    {"id": "T1190.001", "tactic": "initial_access", "title": "Log4Shell Exploitation Attempt",
     "description": "Detects JNDI lookup strings in HTTP requests (Log4Shell)",
     "eventid": None, "logsource_cat": "webserver", "logsource_prod": None,
     "patterns": ["${jndi:ldap", "${jndi:rmi", "${jndi:dns", "Base64"], "level": "critical"},
    {"id": "T1190.002", "tactic": "initial_access", "title": "Path Traversal Exploit Attempt",
     "description": "Detects directory traversal payloads in web requests",
     "eventid": None, "logsource_cat": "webserver", "logsource_prod": None,
     "patterns": ["../../../../", "..%2f", "/etc/passwd", "win.ini"], "level": "high"},
    {"id": "T1190.003", "tactic": "initial_access", "title": "SQL Injection Attempt",
     "description": "Detects common SQL injection signatures in web parameters",
     "eventid": None, "logsource_cat": "webserver", "logsource_prod": None,
     "patterns": ["union select", "' or 1=1", "sleep(", "information_schema"], "level": "high"},
    {"id": "T1190.004", "tactic": "initial_access", "title": "Webshell Access Pattern",
     "description": "Detects access to suspicious single-file scripts with command params",
     "eventid": None, "logsource_cat": "webserver", "logsource_prod": None,
     "patterns": ["cmd=", "/shell.php", "c99", "eval(", "/uploads/"], "level": "critical"},
    {"id": "T1110.003", "tactic": "credential_access", "title": "Password Spraying against OWA/ADFS",
     "description": "Detects single password tried across many accounts",
     "eventid": "4625", "logsource_cat": "security", "logsource_prod": "windows", "level": "high"},
    {"id": "T1110.004", "tactic": "credential_access", "title": "Credential Stuffing on Web Login",
     "description": "Detects high-rate login attempts with rotating credentials",
     "eventid": None, "logsource_cat": "webserver", "logsource_prod": None,
     "patterns": ["POST /login", "401", "403", "/api/auth"], "level": "medium"},
    # --- linux -------------------------------------------------------
    {"id": "T1543.002", "tactic": "persistence", "title": "Linux systemd Service Persistence",
     "description": "Detects creation of suspicious systemd unit files",
     "eventid": None, "logsource_cat": "auditd", "logsource_prod": "linux", "level": "high"},
    {"id": "T1053.003", "tactic": "persistence", "title": "Linux Cron Job Persistence",
     "description": "Detects writes to cron directories by non-admin processes",
     "eventid": None, "logsource_cat": "auditd", "logsource_prod": "linux", "level": "medium"},
    {"id": "T1059.004", "tactic": "execution", "title": "Suspicious Bash Reverse Shell",
     "description": "Detects bash reverse shell one-liners on Linux endpoints",
     "eventid": None, "logsource_cat": "auditd", "logsource_prod": "linux", "level": "high"},
    {"id": "T1548.003", "tactic": "privilege_escalation", "title": "Linux Sudoers Modification",
     "description": "Detects unauthorized modification of sudoers configuration",
     "eventid": None, "logsource_cat": "auditd", "logsource_prod": "linux", "level": "high"},
    {"id": "T1070.004", "tactic": "defense_evasion", "title": "Linux Log Tampering / History Clear",
     "description": "Detects clearing of shell history or system logs",
     "eventid": None, "logsource_cat": "auditd", "logsource_prod": "linux", "level": "medium"},
    {"id": "T1564.001", "tactic": "defense_evasion", "title": "Hidden File/Directory Creation",
     "description": "Detects creation of hidden artifacts in suspicious locations",
     "eventid": None, "logsource_cat": "auditd", "logsource_prod": "linux", "level": "low"},
    # --- impact / misc ----------------------------------------------
    {"id": "T1485", "tactic": "impact", "title": "Data Destruction via cipher/sdelete",
     "description": "Detects secure-wipe utilities used to destroy data",
     "tools": ["cipher.exe", "sdelete.exe", "sdelete64.exe"], "cmdline": ["/w:", "-p ", "-z"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1491.001", "tactic": "impact", "title": "Internal Defacement / Wallpaper Change",
     "description": "Detects ransomware note / wallpaper registry changes",
     "keys": ["HKCU\\\\Control Panel\\\\Desktop\\\\Wallpaper"],
     "eventid": "4657", "logsource_cat": "registry_set", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1496", "tactic": "impact", "title": "Resource Hijacking — Cryptominer",
     "description": "Detects known cryptomining process names and pool connections",
     "tools": ["xmrig.exe", "minerd.exe", "nbminer.exe"], "cmdline": ["--pool", "stratum+tcp", "--donate-level"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1531", "tactic": "impact", "title": "Account Access Removal",
     "description": "Detects mass disabling or password reset of accounts during attack",
     "tools": ["net.exe"], "cmdline": ["/active:no", "user", "/domain"],
     "eventid": "4725", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1562.004", "tactic": "defense_evasion", "title": "Firewall Rule Tampering",
     "description": "Detects netsh advfirewall changes that weaken host protection",
     "tools": ["netsh.exe"], "cmdline": ["advfirewall set", "firewall add rule", "allowinbound"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1218.007", "tactic": "defense_evasion", "title": "Msiexec Remote Package Install",
     "description": "Detects msiexec installing packages from remote URLs",
     "tools": ["msiexec.exe"], "cmdline": ["/i http", "/q", "/quiet"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1140", "tactic": "defense_evasion", "title": "Deobfuscation via certutil/base64",
     "description": "Detects decoding of obfuscated payloads on host",
     "tools": ["certutil.exe", "powershell.exe"], "cmdline": ["-decode", "frombase64string", "[Convert]::"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1216.001", "tactic": "defense_evasion", "title": "Signed Script Proxy (PubPrn)",
     "description": "Detects abuse of signed scripts for proxy execution",
     "tools": ["cscript.exe"], "cmdline": ["pubprn.vbs", "script:http"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "medium"},
    {"id": "T1090.003", "tactic": "command_and_control", "title": "Tor / Multi-hop Proxy Usage",
     "description": "Detects Tor client or proxy chains from corporate endpoints",
     "tools": ["tor.exe"], "cmdline": ["--SocksPort", "9050", "9150"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "high"},
    {"id": "T1135", "tactic": "discovery", "title": "Network Share Discovery",
     "description": "Detects enumeration of network shares post-compromise",
     "tools": ["net.exe", "net1.exe"], "cmdline": ["view \\\\\\\\", "share", "use"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "low"},
    {"id": "T1201", "tactic": "discovery", "title": "Password Policy Discovery",
     "description": "Detects queries of account/password policy settings",
     "tools": ["net.exe"], "cmdline": ["accounts", "accounts /domain"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "low"},
    {"id": "T1614.001", "tactic": "discovery", "title": "System Language/Locale Discovery",
     "description": "Detects locale checks used to skip CIS-region hosts (malware guardrail)",
     "tools": ["reg.exe", "wmic.exe"], "cmdline": ["query", "locale", "Get OSLanguage"],
     "eventid": "4688", "logsource_cat": "process_creation", "logsource_prod": "windows", "level": "low"},
]

# -----------------------------------------------------------------------
# Варианты фолс-позитивов
# -----------------------------------------------------------------------
FALSE_POSITIVES_POOL = [
    "Legitimate system administration tools",
    "Authorized penetration testing activity",
    "IT helpdesk support operations",
    "Vendor-provided management software",
    "Scheduled maintenance scripts",
    "Security team investigation tools",
    "Software deployment via SCCM/Ansible",
    "Cloud backup operations",
    "Antivirus update processes",
    "Domain controller replication",
    "Legacy application compatibility",
    "Database maintenance jobs",
]

# -----------------------------------------------------------------------
# Функции генерации контента
# -----------------------------------------------------------------------

def random_technique() -> dict:
    return random.choice(TECHNIQUES)


def generate_rule_id() -> str:
    return str(uuid.uuid4())


def make_slug(title: str) -> str:
    return title.lower().replace(" ", "_").replace("-", "_")[:40]


def get_rule_path(technique: dict) -> str:
    tactic  = technique["tactic"]
    title   = technique["title"]
    slug    = make_slug(title)
    return f"rules/{tactic}/{slug}.yml"


def generate_sigma_rule(technique: dict, author: str,
                         status: str = "experimental",
                         extra_filters: list = None) -> str:
    today   = simclock.content_date_iso()
    rule_id = generate_rule_id()
    fps     = random.sample(FALSE_POSITIVES_POOL, k=random.randint(1, 3))
    fps_str = "\n".join(f"    - {fp}" for fp in fps)
    tag_tactic = technique["tactic"].replace("_", "-")

    # Строим detection блок в зависимости от техники
    cat = technique.get("logsource_cat", "process_creation")

    if cat == "process_creation":
        tools   = technique.get("tools", ["suspicious.exe"])
        cmdline = technique.get("cmdline", ["malicious"])
        tools_str   = "\n".join(f'            - "{t}"' for t in tools[:4])
        cmdline_str = "\n".join(f'            - "{c}"' for c in cmdline[:4])
        parent  = technique.get("parent", [])
        parent_block = ""
        if parent:
            parent_str = "\n".join(f'            - "{p}"' for p in parent)
            parent_block = """    selection_parent:
        ParentImage|endswith:
{parent_str}
"""
        filter_str = ""
        if extra_filters:
            for i, f in enumerate(extra_filters):
                filter_str += """    filter_{i}:
        {f}
"""
        filter_cond = " and not " + " and not ".join(
            f"filter_{i}" for i in range(len(extra_filters))
        ) if extra_filters else ""

        detection = """detection:
    selection_tools:
        Image|endswith:
{tools_str}
    selection_cmdline:
        CommandLine|contains:
{cmdline_str}
{parent_block}{filter_str}    condition: (selection_tools or selection_cmdline){filter_cond}"""

    elif cat == "security":
        eid = technique.get("eventid", "4624")
        detection = """detection:
    selection:
        EventID: {eid}
        LogonType: 3
        AuthenticationPackageName: NTLM
        KeyLength: 0
    filter_computer:
        SubjectUserName|endswith: "$"
    condition: selection and not filter_computer"""

    elif cat == "dns":
        detection = """detection:
    selection:
        QueryLength|gt: 50
        SubdomainCount|gt: 5
    timeframe: 1m
    condition: selection | count() > 20"""

    elif cat in ("cloudtrail", "proxy", "webserver"):
        patterns = technique.get("patterns", technique.get("ua", ["suspicious"]))
        patterns_str = "\n".join(f'            - "{p}"' for p in patterns[:5])
        detection = """detection:
    selection:
        RequestString|contains:
{patterns_str}
    condition: selection"""

    elif cat == "registry_set":
        keys = technique.get("keys", ["HKLM\\\\SOFTWARE\\\\suspicious"])
        keys_str = "\n".join(f'            - "{k}"' for k in keys)
        detection = """detection:
    selection:
        TargetObject|startswith:
{keys_str}
    condition: selection"""

    else:
        detection = """detection:
    selection:
        EventID: 4663
    condition: selection"""

    extra_note = ""
    if status == "experimental":
        extra_note = "\n# TODO: calibrate thresholds, monitor for false positives"
    elif status == "production":
        extra_note = "\n# Validated: 30 days production, 0 false positives"

    return """title: {technique['title']}
id: {rule_id}
status: {status}
author: {author}
date: {today}{extra_note}
description: {technique['description']}
references:
    - https://attack.mitre.org/techniques/{technique['id'].replace('.', '/')}/
logsource:
    category: {technique.get('logsource_cat', 'process_creation')}{"" if not technique.get('logsource_prod') else chr(10) + "    product: " + technique['logsource_prod']}
{detection}
falsepositives:
{fps_str}
level: {technique['level']}
tags:
    - attack.{tag_tactic}
    - attack.{technique['id'].lower()}
"""


def generate_rule_update(original_content: str, change_type: str,
                          author: str) -> str:
    """Модифицирует существующее правило — добавляет фильтр или меняет статус."""
    today = simclock.content_date_iso()
    lines = original_content.split("\n")
    result = []

    for line in lines:
        # Обновляем дату modified
        if line.startswith("date:") and "modified" not in original_content:
            result.append(line)
            result.append(f"modified: {today}")
            continue
        if line.startswith("modified:"):
            result.append(f"modified: {today}")
            continue

        if change_type == "promote_stable" and line.startswith("status: experimental"):
            result.append("status: stable")
            continue
        if change_type == "promote_production" and line.startswith("status: stable"):
            result.append("status: production")
            continue
        if change_type == "add_reference" and line.startswith("references:"):
            result.append(line)
            result.append("    - https://www.elastic.co/guide/en/siem/guide/current/index.html")
            continue
        if change_type == "tighten_level" and line.startswith("level: medium"):
            result.append("level: high")
            continue

        result.append(line)

    # Добавляем новый false positive
    if change_type == "add_fp" and "falsepositives:" in original_content:
        new_fp = random.choice(FALSE_POSITIVES_POOL)
        for i, line in enumerate(result):
            if line.startswith("level:"):
                result.insert(i, f"    - {new_fp}")
                break

    return "\n".join(result)


def generate_test_sample(technique: dict) -> str:
    import json
    slug = make_slug(technique["title"])
    tools = technique.get("tools", ["tool.exe"])
    sample = {
        "EventID":          technique.get("eventid", "4688"),
        "TimeCreated":      f"{simclock.content_date_iso()}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}Z",
        "Computer":         f"WORKSTATION-{random.randint(1,20):02d}",
        "SubjectUserName":  random.choice(["jsmith", "alee", "mwilson", "kdavis", "rbrown"]),
        "NewProcessName":   f"C:\\\\Windows\\\\Temp\\\\{random.choice(tools)}",
        "CommandLine":      f"{random.choice(tools)} {random.choice(technique.get('cmdline', ['--help']))}",
        "ParentProcessName":"C:\\\\Windows\\\\System32\\\\cmd.exe",
        "expected_match":   True,
        "rule":             slug,
    }
    return json.dumps(sample, indent=2)
