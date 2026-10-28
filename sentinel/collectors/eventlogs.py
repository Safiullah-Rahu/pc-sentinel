"""Windows event-log monitor: Defender, Security (logons, accounts, process creation, file access),
System (new services), DNS client (per-process lookups), Task Scheduler (new tasks)."""
import json
import logging
import os
import subprocess
import time
import xml.etree.ElementTree as ET

from .. import alerts, db, rules, state
from ..osinfo import IS_WIN

if IS_WIN:
    import win32evtlog
from ..config import (AUDIT_REAPPLY_INTERVAL, DEFENDER_STATUS_INTERVAL, EVENTLOG_INTERVAL, GLOBAL_FILE_READERS)
from . import files

log = logging.getLogger("sentinel.evt")
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

CHANNELS = {
    "Microsoft-Windows-Windows Defender/Operational": "defender_log",
    "Security": "security_log",
    "System": None,
    "Microsoft-Windows-DNS-Client/Operational": "dns_log",
    "Microsoft-Windows-TaskScheduler/Operational": None,
}
EVENT_FILTER = {
    "Microsoft-Windows-Windows Defender/Operational": [1006, 1015, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012],
    "Security": [1102, 4624, 4625, 4663, 4688, 4697, 4698, 4720, 4728, 4732, 4756],
    "System": [104, 7045],
    "Microsoft-Windows-DNS-Client/Operational": [3008],
    "Microsoft-Windows-TaskScheduler/Operational": [106],
}
LOGON_TYPES = {"2": "interactive", "3": "network", "7": "unlock", "10": "Remote Desktop", "11": "cached"}


def _query(channel, after_id, max_items=2000):
    ids = " or ".join(f"EventID={i}" for i in EVENT_FILTER[channel])
    xpath = f"*[System[({ids}) and EventRecordID > {after_id}]]"
    h = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection, xpath)
    out = []
    while len(out) < max_items:
        batch = win32evtlog.EvtNext(h, 100, 1000)
        if not batch:
            break
        for ev in batch:
            out.append(win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml))
    return out


def _latest_record_id(channel):
    h = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, "*")
    batch = win32evtlog.EvtNext(h, 1, 1000)
    if not batch:
        return 0
    x = ET.fromstring(win32evtlog.EvtRender(batch[0], win32evtlog.EvtRenderEventXml))  # nosec B314 (XML from the local Windows Event Log API) # noqa: S314
    return int(x.find(f"{NS}System/{NS}EventRecordID").text)


_enabled_cache = {}


def _channel_enabled(channel):
    """Disabled channels can still be queried (empty), so check the real 'enabled' flag (cached 5 min)."""
    hit = _enabled_cache.get(channel)
    if hit and time.time() - hit[1] < 300:
        return hit[0]
    try:
        cp = subprocess.run(["wevtutil", "gl", channel], capture_output=True, text=True, timeout=15,
                            creationflags=subprocess.CREATE_NO_WINDOW)
        on = "enabled: true" in cp.stdout.lower()
    except Exception:  # noqa: BLE001
        on = False
    _enabled_cache[channel] = (on, time.time())
    return on


def _parse(xml):  # XML comes from the Windows Event Log API (EvtRender), not from the network
    x = ET.fromstring(xml)  # nosec B314 (XML from the local Windows Event Log API) # noqa: S314 (trusted local OS API output)
    sysn = x.find(f"{NS}System")
    data = {}
    ed = x.find(f"{NS}EventData")
    if ed is not None:
        for d in ed.findall(f"{NS}Data"):
            data[d.get("Name") or f"_{len(data)}"] = (d.text or "").strip()
    ud = x.find(f"{NS}UserData")
    if ud is not None:
        for el in ud.iter():
            if el.text and el.text.strip() and len(list(el)) == 0:
                data[el.tag.split("}")[-1]] = el.text.strip()
    exe_el = sysn.find(f"{NS}Execution")
    return {
        "id": int(sysn.find(f"{NS}EventID").text),
        "rid": int(sysn.find(f"{NS}EventRecordID").text),
        "time": sysn.find(f"{NS}TimeCreated").get("SystemTime"),
        "pid": int(exe_el.get("ProcessID")) if exe_el is not None and exe_el.get("ProcessID") else None,
        "data": data,
    }


def _pid_name(pid):
    with state.lock:
        p = state.procs.get(pid)
    return (p or {}).get("name") or (f"PID {pid}" if pid else "?")


# ---------------------------------------------------------------- handlers
def h_defender(e):
    d, i = e["data"], e["id"]
    if i in (1006, 1116):
        name = d.get("Threat Name") or d.get("Threat name") or "threat"
        path = d.get("Path") or ""
        alerts.raise_alert(f"def|{i}|{name}|{path[:120]}", "critical", "defender", f"Defender detected {name}",
                           f"Microsoft Defender found {name} ({d.get('Severity Name', '')}) in {path[:300]}",
                           details={"rule": "defender_detection", "event": i, **{k: v for k, v in d.items() if v}})
        with state.lock:
            state.defender["last_detection"] = {"ts": db.now(), "name": name, "path": path}
    elif i in (1117, 1118, 1119):
        alerts.log_event("high" if i != 1117 else "info", "defender",
                         f"Defender action {'succeeded' if i == 1117 else 'FAILED'}: {d.get('Threat Name', '')}",
                         f"{d.get('Action Name', '')} on {d.get('Path', '')[:300]}")
    elif i in (5001, 5010, 5012):
        alerts.raise_alert(f"def|off|{i}|{e['time'][:16]}", "critical", "defender", "Defender protection was turned off",
                           {5001: "Real-time protection disabled.", 5010: "Spyware scanning disabled.",
                            5012: "Virus scanning disabled."}[i], details={"rule": "defender_disabled", "event": i})
    elif i == 5007:
        new = d.get("New Value") or d.get("New value") or ""
        if "\\Exclusions\\" in new:
            alerts.raise_alert(f"def|excl|{new[:200]}", "critical", "defender", "Defender exclusion added",
                               f"Something told Defender to stop scanning: {new[:300]}. Malware does this to hide.",
                               details={"rule": "defender_exclusion", "new": new, "old": d.get("Old Value")})
        elif any(s in new for s in ("DisableRealtimeMonitoring = 0x1", "DisableBehaviorMonitoring = 0x1",
                                    "DisableIOAVProtection = 0x1", "DisableAntiSpyware = 0x1")):
            alerts.raise_alert(f"def|cfg|{new[:200]}", "critical", "defender", "Defender protection setting weakened",
                               new[:300], details={"rule": "defender_weakened", "new": new})


_failed = []


def h_security(e, watch):
    d, i = e["data"], e["id"]
    if i == 1102:
        alerts.raise_alert(f"sec|cleared|{e['time'][:16]}", "critical", "account", "Security log was cleared",
                           f"By {d.get('SubjectUserName', '?')} — attackers clear logs to hide their tracks.",
                           details={"rule": "log_cleared"})
    elif i == 4624:
        lt = d.get("LogonType")
        ip = d.get("IpAddress") or "-"
        if lt in ("10",) or (lt == "3" and ip not in ("-", "::1", "127.0.0.1") and not ip.startswith("fe80")):
            if lt == "3" and rules.is_private(ip) and d.get("TargetUserName", "").endswith("$"):
                return
            sev = "high" if lt == "10" or not rules.is_private(ip) else "medium"
            alerts.raise_alert(f"sec|logon|{lt}|{ip}|{d.get('TargetUserName')}", sev, "account",
                               f"{LOGON_TYPES.get(lt, 'Remote')} logon as {d.get('TargetUserName')} from {ip}",
                               f"Account {d.get('TargetDomainName')}\\{d.get('TargetUserName')} logged on "
                               f"({LOGON_TYPES.get(lt, lt)}) from {d.get('WorkstationName') or ip}.",
                               remote={"ip": ip, "port": None, "host": d.get("WorkstationName")},
                               details={"rule": "remote_logon", "logon_type": lt, "process": d.get("ProcessName")},
                               allow_kind="destination", allow_value=ip)
    elif i == 4625:
        now = time.time()
        _failed.append(now)
        _failed[:] = [t for t in _failed if now - t < 300]
        if len(_failed) >= 5:
            alerts.raise_alert(f"sec|bruteforce|{int(now // 600)}", "high", "account", "Repeated failed logons",
                               f"{len(_failed)} failed logons in 5 minutes (last: {d.get('TargetUserName')} from "
                               f"{d.get('IpAddress') or d.get('WorkstationName')}).", details={"rule": "failed_logons"})
    elif i in (4720,):
        alerts.raise_alert(f"sec|user|{d.get('TargetUserName')}", "critical", "account",
                           f"New user account created: {d.get('TargetUserName')}",
                           f"Created by {d.get('SubjectUserName')}.", details={"rule": "user_created"})
    elif i in (4728, 4732, 4756):
        grp = d.get("TargetUserName") or ""
        sev = "critical" if "admin" in grp.lower() else "medium"
        alerts.raise_alert(f"sec|group|{grp}|{d.get('MemberSid')}", sev, "account",
                           f"Account added to group {grp}", f"{d.get('MemberName') or d.get('MemberSid')} added by "
                           f"{d.get('SubjectUserName')}.", details={"rule": "group_member_added"})
    elif i == 4697:
        alerts.raise_alert(f"sec|svc|{d.get('ServiceName')}", "high", "persistence",
                           f"Service installed: {d.get('ServiceName')}", d.get("ServiceFileName", "")[:300],
                           details={"rule": "service_installed"})
    elif i == 4698:
        alerts.raise_alert(f"sec|task|{d.get('TaskName')}", "high", "persistence",
                           f"Scheduled task created: {d.get('TaskName')}", f"By {d.get('SubjectUserName')}.",
                           details={"rule": "task_created"})
    elif i == 4688:
        exe = d.get("NewProcessName") or ""
        cmd = d.get("CommandLine") or ""
        a = rules.assess(exe, cmd)
        if "lolbin" in a["flags"] or a["trust"] in ("malicious", "suspicious"):
            alerts.raise_alert(f"sec|4688|{exe.lower()}|{cmd[:100]}", "high" if a["trust"] != "malicious" else "critical",
                               "process", f"Suspicious process start: {os.path.basename(exe)}",
                               f"{cmd[:300] or exe} (parent {d.get('ParentProcessName', '?')})",
                               process={"pid": int(d.get("NewProcessId", "0"), 16) if d.get("NewProcessId") else None,
                                        "name": os.path.basename(exe), "exe": exe, "signer": a.get("signer"),
                                        "sig_status": a["sig_status"], "trust": a["trust"], "flags": a["flags"]},
                               details={"rule": "process_creation_audit", "cmdline": cmd,
                                        "parent": d.get("ParentProcessName")},
                               allow_kind="process", allow_value=exe)
    elif i == 4663:
        obj = d.get("ObjectName") or ""
        w = files.match(obj, watch)
        if not w:
            return
        proc_path = d.get("ProcessName") or ""
        pname = os.path.basename(proc_path).lower()
        expected = pname in GLOBAL_FILE_READERS or pname in set(w.get("readers", []))
        pid = int(d.get("ProcessId", "0"), 16) if d.get("ProcessId") else None
        db.execute("INSERT INTO file_access(ts,path,label,kind,process,pid,exe,access,expected) VALUES(?,?,?,?,?,?,?,?,?)",
                   (db.now(), obj, w["label"], w["kind"], os.path.basename(proc_path), pid, proc_path,
                    d.get("AccessList", "").strip() or "ReadData", int(expected)))
        if not expected:
            a = rules.assess(proc_path)
            sev = "critical" if (w["kind"] in ("canary", "wallet") or a["trust"] in ("malicious", "suspicious", "unsigned")) else "high"
            alerts.raise_alert(f"file|{w['path'].lower()}|{proc_path.lower()}", sev, "file",
                               f"{os.path.basename(proc_path)} read {w['label']}",
                               f"{proc_path} ({a['trust']}) opened {obj}. Info-stealing malware targets exactly this file.",
                               process={"pid": pid, "name": os.path.basename(proc_path), "exe": proc_path,
                                        "signer": a.get("signer"), "sig_status": a["sig_status"], "trust": a["trust"],
                                        "flags": a["flags"]},
                               details={"rule": "sensitive_file_read", "file": obj, "kind": w["kind"]},
                               allow_kind="process", allow_value=proc_path)


def h_system(e):
    d, i = e["data"], e["id"]
    if i == 7045:
        img = d.get("ImagePath", "")
        a = rules.assess(files_parse_exe(img))
        sev = {"malicious": "critical", "suspicious": "critical", "unsigned": "high"}.get(a["trust"], "medium")
        alerts.raise_alert(f"sys|svc|{d.get('ServiceName')}|{img[:100]}", sev, "persistence",
                           f"New service installed: {d.get('ServiceName')}", f"{img[:300]} (start: {d.get('StartType')})",
                           details={"rule": "service_installed", "image": img})
    elif i == 104:
        alerts.raise_alert(f"sys|logclear|{e['time'][:16]}", "high", "system", "An event log was cleared",
                           json.dumps(e["data"])[:300], details={"rule": "log_cleared"})


def files_parse_exe(cmd):
    from .persistence import parse_exe
    return parse_exe(cmd)


def h_dns(e):
    d = e["data"]
    q = d.get("QueryName")
    if not q:
        return
    res = (d.get("QueryResults") or "").replace("type:  5 ", "CNAME ").strip(";")
    db.execute("INSERT INTO dns(ts,pid,process,query,type,result) VALUES(?,?,?,?,?,?)",
               (db.now(), e["pid"], _pid_name(e["pid"]), q, d.get("QueryType"), res[:300]))


def h_tasks(e):
    d = e["data"]
    alerts.raise_alert(f"task|new|{d.get('TaskName')}", "medium", "persistence",
                       f"Scheduled task registered: {d.get('TaskName')}", f"By {d.get('UserContext') or d.get('UserName')}.",
                       details={"rule": "task_registered"})


# ---------------------------------------------------------------- defender status (PowerShell)
DEF_PS = r"""
$ErrorActionPreference='SilentlyContinue'
$s = Get-MpComputerStatus; $p = Get-MpPreference
[pscustomobject]@{ rt=$s.RealTimeProtectionEnabled; tp=$s.IsTamperProtected; sig=$s.AntivirusSignatureVersion;
  age=$s.AntivirusSignatureAge; ex=@($p.ExclusionPath) + @($p.ExclusionProcess) } | ConvertTo-Json -Compress
"""


def refresh_defender():
    try:
        cp = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", DEF_PS],
                            capture_output=True, text=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
        j = json.loads(cp.stdout or "{}")
        ex = [x for x in (j.get("ex") or []) if x and not str(x).startswith("N/A")]
        readable = not any(str(x).startswith("N/A") for x in (j.get("ex") or []))
        with state.lock:
            state.defender.update({"realtime": j.get("rt"), "tamper": j.get("tp"), "signatures": j.get("sig"),
                                   "signatures_age_h": (j.get("age") or 0) * 24 if j.get("age") is not None else None,
                                   "exclusions_known": len(ex) if readable else None, "exclusions": ex if readable else []})
        if readable:
            for x in ex:
                if len(x) <= 3 and x.endswith((":\\", ":")):
                    alerts.raise_alert(f"def|wholedrive|{x}", "critical", "defender", f"Defender excludes the whole {x} drive",
                                       "Nothing on that drive is scanned. This is how the 2025 backdoor stayed hidden.",
                                       details={"rule": "defender_whole_drive_exclusion", "exclusions": ex})
        if j.get("rt") is False:
            alerts.raise_alert("def|rt_off_status", "critical", "defender", "Defender real-time protection is OFF",
                               "Turn it back on in Windows Security.", details={"rule": "defender_rt_off"})
    except Exception as e:  # noqa: BLE001
        log.warning("defender status failed: %s", e)


# ---------------------------------------------------------------- loop
def run(stop_event):
    if not IS_WIN:  # Windows event logs only; on macOS/Linux just keep the sensitive-file watchlist current
        while not stop_event.is_set():
            files.write_watchlist()
            stop_event.wait(3600)
        return
    last_def = 0
    last_audit = 0
    watch = files.write_watchlist()
    bookmarks = db.kv_get("evt_bookmarks", {}) or {}
    while not stop_event.is_set():
        now = time.time()
        if now - last_def > DEFENDER_STATUS_INTERVAL:
            last_def = now
            refresh_defender()
        if state.elevated and now - last_audit > AUDIT_REAPPLY_INTERVAL:
            last_audit = now
            files.create_canaries()
            if files.apply_audit_rules():
                with state.lock:
                    state.coverage["file_audit"] = True
            watch = files.write_watchlist()
        for channel, cov in CHANNELS.items():
            try:
                if channel not in bookmarks:
                    bookmarks[channel] = _latest_record_id(channel)  # start from "now", no history flood
                evs = _query(channel, bookmarks[channel])
                if cov:
                    with state.lock:
                        state.coverage[cov] = _channel_enabled(channel) if cov == "dns_log" else True
                for xml in evs:
                    e = _parse(xml)
                    bookmarks[channel] = max(bookmarks[channel], e["rid"])
                    try:
                        if channel.endswith("Defender/Operational"):
                            h_defender(e)
                        elif channel == "Security":
                            h_security(e, watch)
                        elif channel == "System":
                            h_system(e)
                        elif channel.startswith("Microsoft-Windows-DNS"):
                            h_dns(e)
                        else:
                            h_tasks(e)
                    except Exception:  # noqa: BLE001
                        log.exception("handler failed for %s %s", channel, e.get("id"))
            except Exception as ex:  # noqa: BLE001  (channel missing, disabled, or access denied)
                if cov:
                    with state.lock:
                        state.coverage[cov] = False
                log.debug("channel %s unavailable: %s", channel, ex)
        db.kv_set("evt_bookmarks", bookmarks)
        stop_event.wait(EVENTLOG_INTERVAL)
