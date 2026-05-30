#!/usr/bin/env python3
"""


    зависимости: psutil watchdog pywin32 wmi flask
    python dlp_monitor.py [--port 5000] [--db dlp_monitor.db] [--no-browser]

Платформа: Windows 10/11, Python 3.10+
Дашборд:   http://localhost:5000
"""

import argparse
import json
import os
import platform
import sqlite3
import sys
import threading
import time
import webbrowser
from contextlib import contextmanager
from datetime import datetime

# 
# Константы
# 

IS_WINDOWS = platform.system() == "Windows"

# Системные папки, изменения в которых игнорируются (шум)
SKIP_PREFIXES = (
    os.environ.get("SystemRoot", "C:\\Windows"),
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
)

# Процессы, заслуживающие повышенного внимания при детекции
SUSPICIOUS_PROCS = {
    "7z.exe", "winrar.exe", "winzip32.exe", "zip.exe",       # архиваторы
    "telegram.exe", "discord.exe", "whatsapp.exe",            # мессенджеры
    "dropbox.exe", "onedrive.exe", "googledrivesync.exe",     # облако
    "winscp.exe", "filezilla.exe", "putty.exe",               # передача файлов
}

# Риск-скоры событий (0.0 – 1.0)
RISK = {
    "usb_connected":   0.5,
    "file_moved_to":   0.4,
    "file_created":    0.1,
    "file_deleted":    0.3,
    "proc_suspicious": 0.7,
    "proc_started":    0.05,
    "off_hours":       0.3,   # прибавка за работу вне 09:00–21:00
}



#База данных (thread-safe SQLite)

class Database:
    """
    Инкапсулирует работу с SQLite.
    Каждый поток получает собственное соединение через threading.local,
    что обеспечивает потокобезопасность без дополнительных блокировок.

    Схема:
        process_events  — запуск/завершение процессов
        file_events     — операции файловой системы
        usb_events      — подключение/отключение USB-устройств
        user_activity   — смена активного окна (с длительностью)
    """

    def __init__(self, db_path: str = "dlp_monitor.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_schema()

    # ── Соединение ────────────────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        """Возвращает соединение, специфичное для текущего потока."""
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            # WAL-режим: писатели не блокируют читателей
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    @contextmanager
    def _cursor(self):
        conn = self._conn()
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    #  Инициализация схемы 

    def _init_schema(self):
        with self._cursor() as cur:
            cur.executescript("""
                CREATE TABLE IF NOT EXISTS process_events (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp    TEXT    NOT NULL,
                    event_type   TEXT    NOT NULL,
                    process_name TEXT,
                    process_id   INTEGER,
                    username     TEXT,
                    command_line TEXT,
                    parent_pid   INTEGER,
                    risk_score   REAL    DEFAULT 0.0
                );

                CREATE TABLE IF NOT EXISTS file_events (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp    TEXT    NOT NULL,
                    event_type   TEXT    NOT NULL,
                    file_path    TEXT,
                    file_size    INTEGER DEFAULT 0,
                    is_directory INTEGER DEFAULT 0,
                    risk_score   REAL    DEFAULT 0.0
                );

                CREATE TABLE IF NOT EXISTS usb_events (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp    TEXT    NOT NULL,
                    event_type   TEXT    NOT NULL,
                    device_id    TEXT,
                    device_name  TEXT,
                    vendor_id    TEXT,
                    product_id   TEXT,
                    risk_score   REAL    DEFAULT 0.0
                );

                CREATE TABLE IF NOT EXISTS user_activity (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp        TEXT    NOT NULL,
                    window_title     TEXT,
                    process_name     TEXT,
                    process_id       INTEGER,
                    duration_seconds INTEGER DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_pe_ts  ON process_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_fe_ts  ON file_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_ue_ts  ON usb_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_ua_ts  ON user_activity(timestamp);
            """)

    #  Методы логирования 

    def log_process_event(self, event_type: str, name: str, pid: int,
                          username: str = "", cmdline: str = "",
                          ppid: int = None, risk: float = 0.0):
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO process_events "
                "(timestamp,event_type,process_name,process_id,username,command_line,parent_pid,risk_score)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (datetime.now().isoformat(), event_type, name, pid, username, cmdline, ppid, risk),
            )

    def log_file_event(self, event_type: str, file_path: str,
                       file_size: int = 0, is_directory: bool = False,
                       risk: float = 0.0):
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO file_events "
                "(timestamp,event_type,file_path,file_size,is_directory,risk_score)"
                " VALUES (?,?,?,?,?,?)",
                (datetime.now().isoformat(), event_type, file_path,
                 file_size, int(is_directory), risk),
            )

    def log_usb_event(self, event_type: str, device_id: str,
                      device_name: str = "", vendor_id: str = "",
                      product_id: str = "", risk: float = 0.0):
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO usb_events "
                "(timestamp,event_type,device_id,device_name,vendor_id,product_id,risk_score)"
                " VALUES (?,?,?,?,?,?,?)",
                (datetime.now().isoformat(), event_type, device_id,
                 device_name, vendor_id, product_id, risk),
            )

    def log_user_activity(self, window_title: str, process_name: str,
                          process_id: int, duration_seconds: int = 0):
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO user_activity "
                "(timestamp,window_title,process_name,process_id,duration_seconds)"
                " VALUES (?,?,?,?,?)",
                (datetime.now().isoformat(), window_title, process_name,
                 process_id, duration_seconds),
            )

    #  Методы чтения (для дашборда) 

    def get_recent_events(self, limit: int = 100) -> list[dict]:
        """
        UNION ALL по четырем таблицам: возвращает единую ленту событий,
        отсортированную по времени убывания.
        Использование UNION ALL (а не UNION) важно: не убирает дубликаты,
        работает быстрее (нет сортировки для дедупликации).
        """
        with self._cursor() as cur:
            cur.execute(f"""
                SELECT timestamp, 'process'  AS source, event_type,
                       process_name          AS detail,  risk_score
                  FROM process_events
                UNION ALL
                SELECT timestamp, 'file'     AS source, event_type,
                       file_path             AS detail,  risk_score
                  FROM file_events
                UNION ALL
                SELECT timestamp, 'usb'      AS source, event_type,
                       device_name           AS detail,  risk_score
                  FROM usb_events
                UNION ALL
                SELECT timestamp, 'activity' AS source, 'window_focus' AS event_type,
                       window_title          AS detail,  0.0           AS risk_score
                  FROM user_activity
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            return [dict(r) for r in cur.fetchall()]

    def get_statistics(self) -> dict:
        stats = {}
        with self._cursor() as cur:
            for key, tbl in [("processes", "process_events"),
                              ("files",     "file_events"),
                              ("usb",       "usb_events"),
                              ("activity",  "user_activity")]:
                cur.execute(
                    f"SELECT COUNT(*) FROM {tbl} "
                    "WHERE timestamp > datetime('now','-24 hours')"
                )
                stats[key] = cur.fetchone()[0]
            # Количество критических событий (risk >= 0.5)
            cur.execute("""
                SELECT SUM(cnt) FROM (
                    SELECT COUNT(*) cnt FROM process_events WHERE risk_score>=0.5
                    UNION ALL
                    SELECT COUNT(*) cnt FROM file_events    WHERE risk_score>=0.5
                    UNION ALL
                    SELECT COUNT(*) cnt FROM usb_events     WHERE risk_score>=0.5
                )
            """)
            stats["high_risk"] = cur.fetchone()[0] or 0
        return stats

    def get_top_processes(self, limit: int = 10) -> list[dict]:
        with self._cursor() as cur:
            cur.execute("""
                SELECT process_name, COUNT(*) AS cnt
                  FROM process_events
                 WHERE event_type='started'
                   AND timestamp > datetime('now','-24 hours')
                 GROUP BY process_name
                 ORDER BY cnt DESC
                 LIMIT ?
            """, (limit,))
            return [dict(r) for r in cur.fetchall()]

    def get_hourly_activity(self) -> list[dict]:
        """Тепловая карта активности по часам суток (за последние 24 ч)."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT strftime('%H', timestamp) AS hour, COUNT(*) AS cnt
                  FROM user_activity
                 WHERE timestamp > datetime('now','-24 hours')
                 GROUP BY hour
                 ORDER BY hour
            """)
            return [dict(r) for r in cur.fetchall()]

    def get_usb_events(self, limit: int = 50) -> list[dict]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM usb_events ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            return [dict(r) for r in cur.fetchall()]

    def get_high_risk_events(self, threshold: float = 0.5,
                             limit: int = 50) -> list[dict]:
        with self._cursor() as cur:
            cur.execute(f"""
                SELECT timestamp, 'process' AS source, event_type,
                       process_name AS detail, risk_score
                  FROM process_events WHERE risk_score>=?
                UNION ALL
                SELECT timestamp, 'file' AS source, event_type,
                       file_path AS detail, risk_score
                  FROM file_events WHERE risk_score>=?
                UNION ALL
                SELECT timestamp, 'usb' AS source, event_type,
                       device_name AS detail, risk_score
                  FROM usb_events WHERE risk_score>=?
                ORDER BY risk_score DESC, timestamp DESC
                LIMIT ?
            """, (threshold, threshold, threshold, limit))
            return [dict(r) for r in cur.fetchall()]



#Вспомогательный расчёт риск-скора


def _off_hours() -> bool:
    """True, если текущее время вне интервала 09:00–21:00."""
    h = datetime.now().hour
    return h < 9 or h >= 21


def calc_file_risk(event_type: str, file_path: str) -> float:
    score = RISK.get(f"file_{event_type}", 0.1)
    # USB-путь: буква диска, отличная от системных
    sysdrive = os.environ.get("SystemDrive", "C:").upper()
    drive = os.path.splitdrive(file_path)[0].upper()
    if drive and drive != sysdrive:
        score += 0.4           # запись на съёмный диск
    if _off_hours():
        score += RISK["off_hours"]
    return min(score, 1.0)


def calc_proc_risk(process_name: str) -> float:
    score = RISK["proc_started"]
    if process_name.lower() in SUSPICIOUS_PROCS:
        score = RISK["proc_suspicious"]
    if _off_hours():
        score += RISK["off_hours"]
    return min(score, 1.0)


def calc_usb_risk(event_type: str) -> float:
    score = RISK.get(f"usb_{event_type}", 0.2)
    if _off_hours():
        score += RISK["off_hours"]
    return min(score, 1.0)



# Мониторинг активных окон

class UserActivityMonitor:
    """
    Реализует отслеживание активных окон через Windows API.

    Внутренний механизм:
        GetForegroundWindow()  дескриптор (HWND) текущего окна переднего плана.
        GetWindowText(hwnd)    заголовок окна (строка).
        GetWindowThreadProcessId(hwnd)  (thread_id, pid) процесса-владельца.
        psutil.Process(pid).name()  имя исполняемого файла.

    Опрос раз в poll_interval секунд (дефолт 2 с): компромисс между точностью
    и нагрузкой на CPU. Событийный аналог SetWinEventHook  сложнее,
    требует отдельного цикла сообщений Win32.
    """

    def __init__(self, db: Database, poll_interval: float = 2.0):
        self.db = db
        self.poll_interval = poll_interval
        self.running = False
        self._state = {"hwnd": None, "title": "", "proc": "", "pid": 0, "since": None}

    def _active_window(self) -> dict | None:
        try:
            import win32gui, win32process, psutil
            hwnd = win32gui.GetForegroundWindow()
            if not hwnd:
                return None
            title = win32gui.GetWindowText(hwnd)
            # Фильтр: пустые и системные псевдо-окна
            if not title or title in ("Default IME", "MSCTFIME UI", ""):
                return None
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            try:
                proc_name = psutil.Process(pid).name()
            except Exception:
                proc_name = "unknown"
            return {"hwnd": hwnd, "title": title, "proc": proc_name, "pid": pid}
        except Exception:
            return None

    def _loop(self):
        while self.running:
            try:
                info = self._active_window()
                if info and info["hwnd"] != self._state["hwnd"]:
                    if self._state["hwnd"] and self._state["since"]:
                        duration = int(
                            (datetime.now() - self._state["since"]).total_seconds()
                        )
                        self.db.log_user_activity(
                            self._state["title"],
                            self._state["proc"],
                            self._state["pid"],
                            duration,
                        )
                    self._state = {**info, "since": datetime.now()}
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True, name="UAM").start()
        print("[+] UserActivityMonitor запущен")

    def stop(self):
        self.running = False


#Мониторинг процессов


class ProcessMonitor:
    """
    Сравнивает снимки PID-пространства: {pid: Process}.
    Разность множеств new - old = запущенные, old - new = завершенные.

    Технически psutil.process_iter() на Windows вызывает:
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    что возвращает атомарный снимок всего дерева процессов.

    Альтернатива — WMI Win32_ProcessStartTrace нагляднее, но требует
    прав SeSecurityPrivilege и сложнее в обработке ошибок.
    """

    def __init__(self, db: Database, poll_interval: float = 2.0):
        self.db = db
        self.poll_interval = poll_interval
        self.running = False
        self._snapshot: dict[int, object] = {}

    @staticmethod
    def _info(proc) -> dict | None:
        try:
            import psutil
            return {
                "name":    proc.name(),
                "pid":     proc.pid,
                "user":    proc.username(),
                "cmdline": " ".join(proc.cmdline()) if proc.cmdline() else "",
                "ppid":    proc.ppid(),
            }
        except Exception:
            return None

    def _loop(self):
        import psutil
        self._snapshot = {p.pid: p for p in psutil.process_iter()}
        while self.running:
            try:
                new_snap = {p.pid: p for p in psutil.process_iter()}
                new_pids, old_pids = set(new_snap), set(self._snapshot)

                for pid in new_pids - old_pids:
                    info = self._info(new_snap[pid])
                    if info:
                        risk = calc_proc_risk(info["name"])
                        self.db.log_process_event(
                            "started", info["name"], info["pid"],
                            info["user"], info["cmdline"], info["ppid"], risk
                        )
                for pid in old_pids - new_pids:
                    info = self._info(self._snapshot[pid])
                    if info:
                        self.db.log_process_event(
                            "terminated", info["name"], info["pid"],
                            risk=0.0
                        )
                self._snapshot = new_snap
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True, name="PM").start()
        print("[+] ProcessMonitor запущен")

    def stop(self):
        self.running = False


# 
# Модуль 5: Мониторинг файловой системы

class FileSystemMonitor:
    """
    Использует библиотеку watchdog, которая на Windows оборачивает
    ReadDirectoryChangesW нативный асинхронный механизм уведомлений ФС.

    ReadDirectoryChangesW работает через I/O Completion Ports:
        - регистрируется буфер для изменений в директории;
        - ОС записывает FILE_NOTIFY_INFORMATION в буфер при каждом изменении;
        - watchdog читает буфер в отдельном потоке и вызывает обработчики.

    Преимущество перед polling: нулевая нагрузка при отсутствии изменений,
    задержка < 1 мс (против poll_interval при опросе).
    """

    def __init__(self, db: Database, watch_paths: list[str] = None):
        self.db = db
        if watch_paths is None:
            home = os.path.expanduser("~")
            watch_paths = [
                os.path.join(home, "Desktop"),
                os.path.join(home, "Documents"),
                os.path.join(home, "Downloads"),
            ]
        self.watch_paths = [p for p in watch_paths if os.path.exists(p)]
        self.observer = None

    def _build_handler(self):
        from watchdog.events import FileSystemEventHandler
        db = self.db

        def _skip(path: str) -> bool:
            return any(path.startswith(pfx) for pfx in SKIP_PREFIXES)

        def _size(path: str) -> int:
            try:
                return os.path.getsize(path)
            except Exception:
                return 0

        class _Handler(FileSystemEventHandler):
            def on_created(self, event):
                if _skip(event.src_path):
                    return
                size = 0 if event.is_directory else _size(event.src_path)
                risk = calc_file_risk("created", event.src_path)
                db.log_file_event("created", event.src_path, size,
                                  event.is_directory, risk)

            def on_deleted(self, event):
                if _skip(event.src_path):
                    return
                risk = calc_file_risk("deleted", event.src_path)
                db.log_file_event("deleted", event.src_path, 0,
                                  event.is_directory, risk)

            def on_modified(self, event):
                if event.is_directory or _skip(event.src_path):
                    return
                risk = calc_file_risk("modified", event.src_path)
                db.log_file_event("modified", event.src_path,
                                  _size(event.src_path), False, risk)

            def on_moved(self, event):
                if _skip(event.src_path):
                    return
                risk_from = calc_file_risk("moved_from", event.src_path)
                db.log_file_event("moved_from", event.src_path, 0,
                                  event.is_directory, risk_from)
                size = 0 if event.is_directory else _size(event.dest_path)
                risk_to = calc_file_risk("moved_to", event.dest_path)
                db.log_file_event("moved_to", event.dest_path, size,
                                  event.is_directory, risk_to)

        return _Handler()

    def start(self):
        try:
            from watchdog.observers import Observer
            self.observer = Observer()
            handler = self._build_handler()
            for path in self.watch_paths:
                self.observer.schedule(handler, path, recursive=True)
                print(f"[+] FileSystemMonitor: {path}")
            self.observer.start()
        except ImportError:
            print("[!] watchdog не найден — файловый мониторинг отключён")

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()


# 
#   Мониторинг USB
# 

class USBMonitor:
    """
    Подписывается на WMI-события Win32_PnPEntity через COM-объект.

    WMI работает поверх DCOM: клиент (наш код) создаёт IWbemServices,
    вызывает ExecNotificationQuery с WQL-запросом:
        SELECT * FROM __InstanceCreationEvent WITHIN 2
        WHERE TargetInstance ISA 'Win32_PnPEntity'
    Брокер WMI держит подписку и доставляет события без polling.

    Device Instance ID имеет вид: USB\VID_046D&PID_C52B\5&1A2B3C4D&0&3
    Из него парсятся VID (Vendor ID) и PID (Product ID) — 4 hex-символа.
    VID/PID позволяют вести белые/чёрные списки устройств.
    """

    def __init__(self, db: Database):
        self.db = db
        self.running = False

    @staticmethod
    def _parse_vid_pid(device_id: str) -> tuple[str, str]:
        vid = pid = ""
        if "VID_" in device_id:
            i = device_id.index("VID_") + 4
            vid = device_id[i: i + 4]
        if "PID_" in device_id:
            i = device_id.index("PID_") + 4
            pid = device_id[i: i + 4]
        return vid, pid

    def _loop(self):
        try:
            import wmi
            c = wmi.WMI()
            creation_w = c.watch_for(notification_type="Creation",
                                     wmi_class="Win32_PnPEntity", delay_secs=2)
            deletion_w = c.watch_for(notification_type="Deletion",
                                     wmi_class="Win32_PnPEntity", delay_secs=2)
            while self.running:
                try:
                    dev = creation_w(timeout_ms=1000)
                    if dev and dev.DeviceID and dev.DeviceID.startswith("USB"):
                        vid, pid = self._parse_vid_pid(dev.DeviceID)
                        risk = calc_usb_risk("connected")
                        self.db.log_usb_event("connected", dev.DeviceID,
                                              dev.Name or "", vid, pid, risk)
                        print(f"[USB] Подключено: {dev.Name} (VID={vid} PID={pid})")
                except Exception:
                    pass
                try:
                    dev = deletion_w(timeout_ms=1000)
                    if dev and dev.DeviceID and dev.DeviceID.startswith("USB"):
                        risk = calc_usb_risk("disconnected")
                        self.db.log_usb_event("disconnected", dev.DeviceID,
                                              dev.Name or "", risk=risk)
                        print(f"[USB] Отключено: {dev.Name}")
                except Exception:
                    pass
        except ImportError:
            print("[!] wmi не найден — мониторинг USB отключён")
        except Exception as e:
            print(f"[!] USBMonitor ошибка: {e}")

    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True, name="USB").start()
        print("[+] USBMonitor запущен")

    def stop(self):
        self.running = False


# 
# веб-дашборд (Flask)
# 

# HTML/CSS/JS дашборда встроен как строка — один файл без внешних ресурсов.
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DLP Monitor</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@700;800&display=swap');

  :root {
    --bg:       #0a0c10;
    --surface:  #111318;
    --border:   #1e2230;
    --accent:   #00e5ff;
    --danger:   #ff3b5c;
    --warn:     #ffb830;
    --ok:       #00e676;
    --muted:    #4a5568;
    --text:     #c9d1e0;
    --heading:  #ffffff;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    line-height: 1.6;
    min-height: 100vh;
  }

  /* ── Шапка ── */
  header {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 18px 28px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
  }
  .logo-icon {
    width: 38px; height: 38px;
    background: var(--accent);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 18px;
  }
  header h1 {
    font-family: 'Syne', sans-serif;
    font-size: 20px;
    font-weight: 800;
    color: var(--heading);
    letter-spacing: -0.5px;
  }
  header .sub {
    font-size: 11px;
    color: var(--muted);
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }
  .spacer { flex: 1; }
  .live-badge {
    display: flex; align-items: center; gap: 7px;
    background: rgba(0,229,255,.08);
    border: 1px solid rgba(0,229,255,.2);
    border-radius: 20px;
    padding: 5px 14px;
    font-size: 11px;
    color: var(--accent);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .live-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: var(--accent);
    animation: pulse 1.4s ease-in-out infinite;
  }
  @keyframes pulse {
    0%,100% { opacity: 1; transform: scale(1); }
    50%      { opacity: .4; transform: scale(1.5); }
  }

  /* ── Главная сетка ── */
  .main {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr 1fr;
    grid-template-rows: auto auto auto;
    gap: 14px;
    padding: 20px 24px;
    max-width: 1600px;
    margin: 0 auto;
  }

  /* ── Карточка ── */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px 20px;
    position: relative;
    overflow: hidden;
  }
  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--accent) 0%, transparent 60%);
    opacity: .6;
  }
  .card.danger::before { background: linear-gradient(90deg, var(--danger) 0%, transparent 60%); }
  .card.warn::before   { background: linear-gradient(90deg, var(--warn) 0%, transparent 60%); }
  .card.ok::before     { background: linear-gradient(90deg, var(--ok) 0%, transparent 60%); }

  .card-label {
    font-size: 10px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
  }
  .card-value {
    font-size: 34px;
    font-weight: 700;
    color: var(--heading);
    font-family: 'Syne', sans-serif;
    line-height: 1;
  }
  .card-value.red  { color: var(--danger); }
  .card-value.cyan { color: var(--accent); }
  .card-value.yellow { color: var(--warn); }

  /* ── Таблицы событий ── */
  .col-wide  { grid-column: span 2; }
  .col-full  { grid-column: span 4; }

  .section-title {
    font-family: 'Syne', sans-serif;
    font-size: 13px;
    font-weight: 700;
    color: var(--heading);
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .section-title .dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--accent);
  }

  .event-table { width: 100%; border-collapse: collapse; }
  .event-table th {
    font-size: 10px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.8px;
    text-align: left;
    padding: 0 8px 10px;
    border-bottom: 1px solid var(--border);
  }
  .event-table td {
    padding: 7px 8px;
    border-bottom: 1px solid rgba(30,34,48,.6);
    color: var(--text);
    font-size: 12px;
    vertical-align: middle;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 280px;
  }
  .event-table tr:last-child td { border-bottom: none; }
  .event-table tr:hover td { background: rgba(255,255,255,.02); }

  /* ── Бейджи ── */
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .badge-process  { background: rgba(0,229,255,.1);  color: var(--accent); }
  .badge-file     { background: rgba(0,230,118,.1);  color: var(--ok); }
  .badge-usb      { background: rgba(255,184,48,.1); color: var(--warn); }
  .badge-activity { background: rgba(100,100,200,.12); color: #a0aec0; }
  .badge-started    { background: rgba(0,229,255,.07);  color: var(--accent); }
  .badge-terminated { background: rgba(100,100,100,.15); color: var(--muted); }
  .badge-connected  { background: rgba(255,184,48,.15); color: var(--warn); }

  /* ── Риск-индикатор ── */
  .risk-bar {
    display: flex; align-items: center; gap: 6px;
  }
  .risk-fill {
    height: 6px;
    border-radius: 3px;
    min-width: 4px;
  }
  .risk-label { font-size: 10px; color: var(--muted); }

  /* ── Часовая тепловая карта ── */
  .heatmap {
    display: grid;
    grid-template-columns: repeat(24, 1fr);
    gap: 3px;
    margin-top: 10px;
  }
  .hm-cell {
    height: 28px;
    border-radius: 4px;
    background: var(--border);
    position: relative;
    cursor: default;
    transition: transform .15s;
  }
  .hm-cell:hover { transform: scaleY(1.15); }
  .hm-cell .hm-tip {
    display: none;
    position: absolute;
    bottom: calc(100% + 6px);
    left: 50%;
    transform: translateX(-50%);
    background: #1e2230;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 10px;
    white-space: nowrap;
    pointer-events: none;
    z-index: 10;
  }
  .hm-cell:hover .hm-tip { display: block; }
  .hm-hours {
    display: grid;
    grid-template-columns: repeat(24, 1fr);
    gap: 3px;
    margin-top: 4px;
  }
  .hm-h {
    text-align: center;
    font-size: 9px;
    color: var(--muted);
  }

  /* ── Top-процессы бар-чарт ── */
  .proc-bar-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 8px;
  }
  .proc-name {
    width: 150px;
    flex-shrink: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    font-size: 12px;
    color: var(--text);
  }
  .proc-track {
    flex: 1;
    height: 10px;
    background: var(--border);
    border-radius: 5px;
    overflow: hidden;
  }
  .proc-fill {
    height: 100%;
    border-radius: 5px;
    background: linear-gradient(90deg, var(--accent), #0077ff);
    transition: width .5s ease;
  }
  .proc-cnt {
    width: 36px;
    text-align: right;
    font-size: 11px;
    color: var(--muted);
  }

  /* ── USB секция ── */
  .usb-icon { font-size: 16px; }

  /* ── Timestamp ── */
  .ts { color: var(--muted); font-size: 11px; font-family: 'JetBrains Mono', monospace; }

  /* ── Скролл в карточках ── */
  .scrollable { max-height: 320px; overflow-y: auto; }
  .scrollable::-webkit-scrollbar { width: 4px; }
  .scrollable::-webkit-scrollbar-track { background: var(--surface); }
  .scrollable::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  /* ── Обновление ── */
  #refresh-timer { font-size: 10px; color: var(--muted); }
</style>
</head>
<body>

<header>
  <div class="logo-icon">🛡</div>
  <div>
    <h1>DLP Monitor</h1>
    <div class="sub">Data Loss Prevention · Prototype</div>
  </div>
  <div class="spacer"></div>
  <span id="refresh-timer">обновление через 10 с</span>
  &nbsp;
  <div class="live-badge"><div class="live-dot"></div> Live</div>
</header>

<div class="main" id="grid">
  <!-- Статистика (заполняется JS) -->
  <div class="card ok"    id="s-proc">
    <div class="card-label">Процессы / 24ч</div>
    <div class="card-value cyan" id="v-proc">—</div>
  </div>
  <div class="card ok"    id="s-file">
    <div class="card-label">Файловые события / 24ч</div>
    <div class="card-value" style="color:var(--ok)" id="v-file">—</div>
  </div>
  <div class="card warn"  id="s-usb">
    <div class="card-label">USB-события / 24ч</div>
    <div class="card-value yellow" id="v-usb">—</div>
  </div>
  <div class="card danger" id="s-risk">
    <div class="card-label">Критические инциденты</div>
    <div class="card-value red" id="v-risk">—</div>
  </div>

  <!-- Тепловая карта активности -->
  <div class="card col-wide">
    <div class="section-title"><div class="dot" style="background:var(--accent)"></div>Активность по часам (сегодня)</div>
    <div class="heatmap" id="heatmap"></div>
    <div class="hm-hours" id="hm-hours"></div>
  </div>

  <!-- Top-процессы -->
  <div class="card col-wide">
    <div class="section-title"><div class="dot" style="background:var(--ok)"></div>Топ-процессы (24 ч)</div>
    <div id="top-procs"></div>
  </div>

  <!-- Лента событий -->
  <div class="card col-wide">
    <div class="section-title"><div class="dot" style="background:var(--accent)"></div>Последние события</div>
    <div class="scrollable">
      <table class="event-table">
        <thead><tr>
          <th>Время</th><th>Тип</th><th>Событие</th><th>Детали</th><th>Риск</th>
        </tr></thead>
        <tbody id="events-body"></tbody>
      </table>
    </div>
  </div>

  <!-- Инциденты высокого риска -->
  <div class="card col-wide">
    <div class="section-title"><div class="dot" style="background:var(--danger)"></div>Инциденты (risk ≥ 0.5)</div>
    <div class="scrollable">
      <table class="event-table">
        <thead><tr>
          <th>Время</th><th>Тип</th><th>Событие</th><th>Детали</th><th>Риск</th>
        </tr></thead>
        <tbody id="risks-body"></tbody>
      </table>
    </div>
  </div>

  <!-- USB история -->
  <div class="card col-full">
    <div class="section-title"><div class="dot" style="background:var(--warn)"></div>История USB-устройств</div>
    <div class="scrollable">
      <table class="event-table">
        <thead><tr>
          <th>Время</th><th>Событие</th><th>Устройство</th><th>Device ID</th><th>VID</th><th>PID</th><th>Риск</th>
        </tr></thead>
        <tbody id="usb-body"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
const fmt = (ts) => ts ? ts.slice(0,19).replace('T',' ') : '—';

const badgeSource = {
  process:  'badge-process',
  file:     'badge-file',
  usb:      'badge-usb',
  activity: 'badge-activity'
};
const badgeEvent = (t) => {
  if (t==='started')     return 'badge-started';
  if (t==='terminated')  return 'badge-terminated';
  if (t==='connected')   return 'badge-connected';
  return '';
};

const riskColor = (r) => {
  if (r >= 0.7) return '#ff3b5c';
  if (r >= 0.4) return '#ffb830';
  return '#00e676';
};

const riskBar = (r) => {
  const pct = Math.round(r * 100);
  return `<div class="risk-bar">
    <div class="risk-fill" style="width:${pct}px;background:${riskColor(r)}"></div>
    <span class="risk-label">${pct}%</span>
  </div>`;
};

const makeRow = (e) => `<tr>
  <td class="ts">${fmt(e.timestamp)}</td>
  <td><span class="badge ${badgeSource[e.source]||''}">${e.source}</span></td>
  <td><span class="badge ${badgeEvent(e.event_type)}">${e.event_type}</span></td>
  <td title="${e.detail||''}">${(e.detail||'').slice(-60)}</td>
  <td>${riskBar(e.risk_score||0)}</td>
</tr>`;

const makeUsbRow = (u) => `<tr>
  <td class="ts">${fmt(u.timestamp)}</td>
  <td><span class="badge ${u.event_type==='connected'?'badge-connected':''}">${u.event_type}</span></td>
  <td>${u.device_name||'—'}</td>
  <td class="ts" title="${u.device_id||''}">${(u.device_id||'').slice(0,40)}</td>
  <td>${u.vendor_id||'—'}</td>
  <td>${u.product_id||'—'}</td>
  <td>${riskBar(u.risk_score||0)}</td>
</tr>`;

// Тепловая карта
function buildHeatmap(data) {
  const hours = {};
  data.forEach(d => { hours[d.hour] = d.cnt; });
  const max = Math.max(1, ...Object.values(hours));
  const hm = document.getElementById('heatmap');
  const hl = document.getElementById('hm-hours');
  hm.innerHTML = ''; hl.innerHTML = '';
  for (let h=0; h<24; h++) {
    const cnt = hours[String(h).padStart(2,'0')] || 0;
    const pct = cnt / max;
    const col = pct > 0.7 ? '#ff3b5c' : pct > 0.3 ? '#ffb830' : '#00e5ff';
    const opacity = 0.1 + pct * 0.85;
    const cell = document.createElement('div');
    cell.className = 'hm-cell';
    cell.style.background = pct > 0 ? col : 'var(--border)';
    cell.style.opacity = opacity;
    cell.innerHTML = `<div class="hm-tip">${h}:00 — ${cnt} событий</div>`;
    hm.appendChild(cell);
    const lbl = document.createElement('div');
    lbl.className = 'hm-h';
    lbl.textContent = h % 3 === 0 ? h : '';
    hl.appendChild(lbl);
  }
}

// Топ-процессы
function buildTopProcs(data) {
  const max = data.length > 0 ? data[0].cnt : 1;
  document.getElementById('top-procs').innerHTML =
    data.map(p => `<div class="proc-bar-row">
      <div class="proc-name" title="${p.process_name}">${p.process_name}</div>
      <div class="proc-track">
        <div class="proc-fill" style="width:${Math.round(p.cnt/max*100)}%"></div>
      </div>
      <div class="proc-cnt">${p.cnt}</div>
    </div>`).join('');
}

// Таймер обновления
let remaining = 10;
const timerEl = document.getElementById('refresh-timer');
setInterval(() => {
  remaining--;
  timerEl.textContent = `обновление через ${remaining} с`;
  if (remaining <= 0) remaining = 10;
}, 1000);

async function refresh() {
  try {
    const [stats, events, risks, hourly, topProcs, usbEvents] = await Promise.all([
      fetch('/api/stats').then(r=>r.json()),
      fetch('/api/events?limit=60').then(r=>r.json()),
      fetch('/api/high_risk?limit=40').then(r=>r.json()),
      fetch('/api/hourly').then(r=>r.json()),
      fetch('/api/top_procs').then(r=>r.json()),
      fetch('/api/usb?limit=30').then(r=>r.json()),
    ]);

    document.getElementById('v-proc').textContent = stats.processes ?? '—';
    document.getElementById('v-file').textContent = stats.files ?? '—';
    document.getElementById('v-usb').textContent  = stats.usb ?? '—';
    document.getElementById('v-risk').textContent = stats.high_risk ?? '—';

    document.getElementById('events-body').innerHTML = events.map(makeRow).join('');
    document.getElementById('risks-body').innerHTML  = risks.length
      ? risks.map(makeRow).join('')
      : '<tr><td colspan="5" style="color:var(--ok);padding:12px 8px">Инцидентов не обнаружено</td></tr>';
    document.getElementById('usb-body').innerHTML = usbEvents.length
      ? usbEvents.map(makeUsbRow).join('')
      : '<tr><td colspan="7" style="color:var(--muted);padding:12px 8px">USB-событий нет</td></tr>';

    buildHeatmap(hourly);
    buildTopProcs(topProcs);
  } catch(e) {
    console.error('Refresh error:', e);
  }
}

refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>"""


def start_dashboard(db: Database, port: int = 5000):
    """Запускает Flask-сервер в отдельном потоке."""
    try:
        from flask import Flask, jsonify, request
    except ImportError:
        print("[!] Flask не найден — дашборд недоступен. pip install flask")
        return

    app = Flask(__name__)
    app.config["JSON_ENSURE_ASCII"] = False

    @app.route("/")
    def index():
        from flask import Response
        return Response(DASHBOARD_HTML, mimetype="text/html")

    @app.route("/api/stats")
    def api_stats():
        return jsonify(db.get_statistics())

    @app.route("/api/events")
    def api_events():
        limit = int(request.args.get("limit", 100))
        return jsonify(db.get_recent_events(limit))

    @app.route("/api/high_risk")
    def api_high_risk():
        limit = int(request.args.get("limit", 50))
        return jsonify(db.get_high_risk_events(limit=limit))

    @app.route("/api/hourly")
    def api_hourly():
        return jsonify(db.get_hourly_activity())

    @app.route("/api/top_procs")
    def api_top_procs():
        return jsonify(db.get_top_processes())

    @app.route("/api/usb")
    def api_usb():
        limit = int(request.args.get("limit", 50))
        return jsonify(db.get_usb_events(limit))

    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)   # убираем спам запросов Flask

    t = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, debug=False),
        daemon=True,
        name="Flask",
    )
    t.start()
    print(f"[+] Дашборд: http://127.0.0.1:{port}")


#точка входа

def parse_args():
    p = argparse.ArgumentParser(
        description="DLP-агент + веб-дашборд",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--port",       type=int,  default=5000,             help="Порт дашборда (default: 5000)")
    p.add_argument("--db",         type=str,  default="dlp_monitor.db", help="Путь к SQLite-файлу")
    p.add_argument("--no-browser", action="store_true",                 help="Не открывать браузер")
    p.add_argument("--no-proc",    action="store_true",                 help="Отключить мониторинг процессов")
    p.add_argument("--no-file",    action="store_true",                 help="Отключить мониторинг ФС")
    p.add_argument("--no-usb",     action="store_true",                 help="Отключить мониторинг USB")
    p.add_argument("--no-activity",action="store_true",                 help="Отключить мониторинг окон")
    return p.parse_args()


def main():
    args = parse_args()

    print("=" * 62)
    print("  DLP-монитор — прототип агента сбора данных")
    print(f"  БД: {os.path.abspath(args.db)}")
    print(f"  Платформа: {platform.system()} {platform.release()}")
    print("=" * 62)

    if not IS_WINDOWS:
        print("[WARN] Система не Windows. Модули win32/wmi будут пропущены.")

    # Инициализация БД
    db = Database(args.db)
    print(f"[+] База данных: {args.db}")

    # Запуск агентов
    monitors = []

    if not args.no_activity and IS_WINDOWS:
        m = UserActivityMonitor(db)
        m.start()
        monitors.append(m)

    if not args.no_proc:
        try:
            import psutil  # noqa
            m = ProcessMonitor(db)
            m.start()
            monitors.append(m)
        except ImportError:
            print("[!] psutil не найден — мониторинг процессов отключён")

    if not args.no_file:
        m = FileSystemMonitor(db)
        m.start()
        monitors.append(m)

    if not args.no_usb and IS_WINDOWS:
        m = USBMonitor(db)
        m.start()
        monitors.append(m)

    # Дашборд
    start_dashboard(db, args.port)

    if not args.no_browser:
        time.sleep(1.0)
        webbrowser.open(f"http://127.0.0.1:{args.port}")

    print("\n[DLP] Все агенты запущены. Ctrl+C для остановки.\n")

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[DLP] Остановка агентов...")
        for m in monitors:
            m.stop()
        print("[DLP] Завершено.")


if __name__ == "__main__":
    main()
