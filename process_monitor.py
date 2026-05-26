"""
Модуль мониторинга процессов.

Технические детали Windows API:
1. CreateToolhelp32Snapshot - создаёт "снимок" системы
2. Process32First/Process32Next - итерация по процессам
3. OpenProcess - получение handle к процессу
4. GetProcessImageFileName - получение пути к EXE

Структуры данных:
- EPROCESS (kernel) - executive process block
- PEB (user-mode) - process environment block  
- Handle Table - таблица дескрипторов процесса
"""

import psutil
import threading
import time
from datetime import datetime


class ProcessMonitor:
    """
    Мониторинг запуска и завершения процессов.
    
    Техническая реализация:
    - Polling approach: периодическое сканирование списка процессов
    - Сравнение snapshot'ов для определения изменений
    - Альтернатива: WMI Win32_ProcessStartTrace (event-driven)
    """
    
    def __init__(self, database, poll_interval=2):
        """
        Инициализация монитора процессов.
        
        Параметры:
        - database: экземпляр Database для логирования
        - poll_interval: интервал опроса в секундах
        """
        self.database = database
        self.poll_interval = poll_interval
        self.running = False
        self.monitor_thread = None
        
        # Кэш текущих процессов: {pid: psutil.Process}
        # Используется для определения новых/завершённых процессов
        self.current_processes = {}
        
        # Инициализация начального состояния
        self._update_process_cache()
    
    def _update_process_cache(self):
        """
        Обновление кэша процессов.
        
        Техническая деталь:
        psutil.process_iter() внутренне вызывает:
        - Windows: CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)
        - Затем Process32First() и Process32Next() для итерации
        """
        try:
            self.current_processes = {
                p.pid: p for p in psutil.process_iter(['pid', 'name', 'username', 
                                                       'cmdline', 'ppid', 'create_time'])
            }
        except Exception as e:
            print(f"[ProcessMonitor] Ошибка обновления кэша: {e}")
    
    def _get_process_info(self, process):
        """
        Извлечение детальной информации о процессе.
        
        Windows API детали:
        - process.name() -> GetModuleFileNameEx() -> образ EXE
        - process.username() -> OpenProcessToken() + GetTokenInformation()
        - process.cmdline() -> ReadProcessMemory() чтение PEB
        - process.ppid() -> PROCESSENTRY32.th32ParentProcessID
        """
        try:
            return {
                'name': process.name(),
                'pid': process.pid,
                'username': process.username() if hasattr(process, 'username') else 'N/A',
                'cmdline': ' '.join(process.cmdline()) if process.cmdline() else '',
                'ppid': process.ppid() if hasattr(process, 'ppid') else None,
                'create_time': datetime.fromtimestamp(process.create_time()).isoformat()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
    
    def _detect_new_processes(self, new_snapshot):
        """
        Определение новых процессов (запущенных).
        
        Алгоритм:
        1. Сравнение PID'ов в старом и новом snapshot
        2. Процессы в new но не в old = новые процессы
        3. Логирование события 'started'
        """
        new_pids = set(new_snapshot.keys())
        old_pids = set(self.current_processes.keys())
        
        started_pids = new_pids - old_pids
        
        for pid in started_pids:
            try:
                proc_info = self._get_process_info(new_snapshot[pid])
                if proc_info:
                    print(f"[ProcessMonitor] Процесс запущен: {proc_info['name']} (PID: {pid})")
                    
                    self.database.log_process_event(
                        event_type='started',
                        process_name=proc_info['name'],
                        process_id=pid,
                        username=proc_info['username'],
                        command_line=proc_info['cmdline'],
                        parent_pid=proc_info['ppid']
                    )
            except Exception as e:
                print(f"[ProcessMonitor] Ошибка обработки нового процесса {pid}: {e}")
    
    def _detect_terminated_processes(self, new_snapshot):
        """
        Определение завершённых процессов.
        
        Алгоритм:
        1. Процессы в old но не в new = завершённые
        2. Логирование события 'terminated'
        
        Техническая деталь:
        Процесс может завершиться:
        - TerminateProcess() API
        - ExitProcess() из самого процесса
        - Kernel terminates (unhandled exception)
        """
        new_pids = set(new_snapshot.keys())
        old_pids = set(self.current_processes.keys())
        
        terminated_pids = old_pids - new_pids
        
        for pid in terminated_pids:
            try:
                proc_info = self._get_process_info(self.current_processes[pid])
                if proc_info:
                    print(f"[ProcessMonitor] Процесс завершён: {proc_info['name']} (PID: {pid})")
                    
                    self.database.log_process_event(
                        event_type='terminated',
                        process_name=proc_info['name'],
                        process_id=pid,
                        username=proc_info['username'],
                        command_line=proc_info['cmdline'],
                        parent_pid=proc_info['ppid']
                    )
            except Exception as e:
                print(f"[ProcessMonitor] Ошибка обработки завершённого процесса {pid}: {e}")
    
    def _monitor_loop(self):
        """
        Основной цикл мониторинга.
        
        Техническая деталь:
        Polling approach имеет ограничения:
        - Race condition: процесс может запуститься и завершиться между опросами
        - Нагрузка на CPU: постоянные системные вызовы
        
        Для production лучше использовать:
        - ETW (Event Tracing for Windows)
        - WMI event subscriptions
        - Kernel-mode callbacks (PsSetCreateProcessNotifyRoutine)
        """
        print("[ProcessMonitor] Мониторинг процессов запущен")
        
        while self.running:
            try:
                # Получение нового snapshot'а системы
                new_snapshot = {
                    p.pid: p for p in psutil.process_iter(['pid', 'name', 'username',
                                                           'cmdline', 'ppid', 'create_time'])
                }
                
                # Определение изменений
                self._detect_new_processes(new_snapshot)
                self._detect_terminated_processes(new_snapshot)
                
                # Обновление кэша
                self.current_processes = new_snapshot
                
            except Exception as e:
                print(f"[ProcessMonitor] Ошибка в цикле мониторинга: {e}")
            
            # Ожидание следующего цикла
            time.sleep(self.poll_interval)
        
        print("[ProcessMonitor] Мониторинг процессов остановлен")
    
    def start(self):
        """Запуск мониторинга в отдельном потоке."""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            print("[ProcessMonitor] Поток мониторинга запущен")
    
    def stop(self):
        """Остановка мониторинга."""
        if self.running:
            self.running = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=5)
            print("[ProcessMonitor] Мониторинг процессов остановлен")
    
    def get_current_processes(self):
        """
        Получение списка текущих процессов для dashboard.
        
        Возвращает список словарей с информацией о процессах.
        """
        processes = []
        for pid, proc in self.current_processes.items():
            try:
                info = self._get_process_info(proc)
                if info:
                    # Добавление дополнительных метрик
                    info['cpu_percent'] = proc.cpu_percent(interval=0.1)
                    info['memory_mb'] = proc.memory_info().rss / (1024 * 1024)
                    processes.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return processes


# === Дополнительный функционал для расширенного мониторинга ===

class AdvancedProcessMonitor:
    """
    Расширенный мониторинг с использованием Windows API напрямую.
    
    Требует: pywin32
    
    Возможности:
    - Мониторинг network connections процесса
    - Открытые файлы процесса
    - Загруженные DLL/модули
    - Приоритет и affinity
    """
    
    @staticmethod
    def get_process_network_connections(pid):
        """
        Получение сетевых соединений процесса.
        
        Техническая деталь:
        - Windows: GetExtendedTcpTable() и GetExtendedUdpTable()
        - Возвращает список TUPLE с локальным и удалённым адресами
        """
        try:
            proc = psutil.Process(pid)
            return proc.connections()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []
    
    @staticmethod
    def get_process_open_files(pid):
        """
        Получение открытых файлов процесса.
        
        Техническая деталь:
        - Windows: NtQuerySystemInformation(SystemHandleInformation)
        - Итерация по handle table процесса
        - Определение типа handle (File, Registry, Event, etc.)
        """
        try:
            proc = psutil.Process(pid)
            return proc.open_files()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []
    
    @staticmethod
    def get_process_memory_maps(pid):
        """
        Получение карты памяти процесса (загруженные модули).
        
        Техническая деталь:
        - Windows: EnumProcessModules() + GetModuleFileNameEx()
        - Возвращает список DLL и их адреса в виртуальной памяти
        """
        try:
            proc = psutil.Process(pid)
            return proc.memory_maps()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []
