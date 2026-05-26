"""
Модуль работы с базой данных SQLite.

Технические детали:
- SQLite хранит всю базу в одном файле (database.db)
- Использует B-tree структуру для индексирования
- ACID-транзакции через журнал rollback journal
- WAL (Write-Ahead Logging) для повышения производительности
"""

import sqlite3
import threading
from datetime import datetime
from contextlib import contextmanager


class Database:
    """
    Класс для управления SQLite базой данных.
    
    Технические особенности:
    - Thread-local соединения (SQLite не thread-safe по умолчанию)
    - Connection pooling через threading.local()
    - Автоматическое закрытие соединений через context manager
    """
    
    def __init__(self, db_path='dlp_monitor.db'):
        self.db_path = db_path
        self._local = threading.local()
        self.init_database()
    
    def get_connection(self):
        """
        Получение thread-local соединения.
        
        Техническая деталь:
        SQLite использует одно соединение на поток, чтобы избежать
        конфликтов блокировок (database is locked errors).
        """
        if not hasattr(self._local, 'connection'):
            self._local.connection = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                isolation_level=None  # Autocommit mode для производительности
            )
            self._local.connection.row_factory = sqlite3.Row
        return self._local.connection
    
    @contextmanager
    def get_cursor(self):
        """Context manager для безопасной работы с курсором."""
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
    
    def init_database(self):
        """
        Инициализация структуры базы данных.
        
        Техническая деталь:
        CREATE TABLE IF NOT EXISTS использует внутренний механизм
        проверки sqlite_master таблицы, где хранятся метаданные схемы.
        """
        with self.get_cursor() as cursor:
            # Таблица событий процессов
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS process_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    process_name TEXT,
                    process_id INTEGER,
                    username TEXT,
                    command_line TEXT,
                    parent_pid INTEGER
                )
            ''')
            
            # Индекс на timestamp для быстрого поиска по времени
            # B-tree индекс ускоряет операции WHERE, ORDER BY
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_process_timestamp 
                ON process_events(timestamp)
            ''')
            
            # Таблица файловых событий
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size INTEGER,
                    is_directory INTEGER DEFAULT 0
                )
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_file_timestamp 
                ON file_events(timestamp)
            ''')
            
            # Таблица событий USB устройств
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS usb_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    device_id TEXT,
                    device_name TEXT,
                    device_type TEXT,
                    vendor_id TEXT,
                    product_id TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_usb_timestamp 
                ON usb_events(timestamp)
            ''')
            
            # Таблица активности пользователя (активные окна)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    window_title TEXT,
                    process_name TEXT,
                    process_id INTEGER,
                    duration_seconds INTEGER DEFAULT 0
                )
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_activity_timestamp 
                ON user_activity(timestamp)
            ''')
    
    # === Методы для процессов ===
    
    def log_process_event(self, event_type, process_name, process_id, 
                          username='', command_line='', parent_pid=None):
        """
        Логирование события процесса.
        
        Параметры:
        - event_type: 'started' или 'terminated'
        - process_name: имя исполняемого файла
        - process_id: PID (Process ID из kernel)
        - username: владелец процесса
        - command_line: полная командная строка запуска
        - parent_pid: PID родительского процесса
        """
        with self.get_cursor() as cursor:
            cursor.execute('''
                INSERT INTO process_events 
                (timestamp, event_type, process_name, process_id, username, 
                 command_line, parent_pid)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                event_type,
                process_name,
                process_id,
                username,
                command_line,
                parent_pid
            ))
    
    # === Методы для файловых событий ===
    
    def log_file_event(self, event_type, file_path, file_size=0, is_directory=False):
        """
        Логирование файлового события.
        
        Параметры:
        - event_type: 'created', 'modified', 'deleted', 'moved'
        - file_path: полный путь к файлу
        - file_size: размер в байтах
        - is_directory: True если это директория
        """
        with self.get_cursor() as cursor:
            cursor.execute('''
                INSERT INTO file_events 
                (timestamp, event_type, file_path, file_size, is_directory)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                event_type,
                file_path,
                file_size,
                1 if is_directory else 0
            ))
    
    # === Методы для USB событий ===
    
    def log_usb_event(self, event_type, device_id, device_name='', 
                     device_type='', vendor_id='', product_id=''):
        """
        Логирование USB события.
        
        Параметры:
        - event_type: 'connected' или 'disconnected'
        - device_id: уникальный ID устройства из Windows PnP
        - device_name: понятное имя устройства
        - device_type: тип (USB Mass Storage, HID, etc.)
        - vendor_id: VID из USB дескриптора
        - product_id: PID из USB дескриптора
        """
        with self.get_cursor() as cursor:
            cursor.execute('''
                INSERT INTO usb_events 
                (timestamp, event_type, device_id, device_name, 
                 device_type, vendor_id, product_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                event_type,
                device_id,
                device_name,
                device_type,
                vendor_id,
                product_id
            ))
    
    # === Методы для активности пользователя ===
    
    def log_user_activity(self, window_title, process_name, process_id, 
                          duration_seconds=0):
        """
        Логирование активности пользователя (активное окно).
        
        Параметры:
        - window_title: заголовок активного окна
        - process_name: имя процесса окна
        - process_id: PID процесса
        - duration_seconds: время активности
        """
        with self.get_cursor() as cursor:
            cursor.execute('''
                INSERT INTO user_activity 
                (timestamp, window_title, process_name, process_id, duration_seconds)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                window_title,
                process_name,
                process_id,
                duration_seconds
            ))
    
    # === Методы запросов для dashboard ===
    
    def get_recent_events(self, event_type='all', limit=100):
        """
        Получение последних событий для отображения в dashboard.
        
        Техническая деталь:
        UNION ALL объединяет результаты без удаления дубликатов (быстрее чем UNION)
        ORDER BY работает на объединённом результате
        """
        with self.get_cursor() as cursor:
            if event_type == 'all':
                query = '''
                    SELECT timestamp, 'process' as category, event_type, 
                           process_name as details FROM process_events
                    UNION ALL
                    SELECT timestamp, 'file' as category, event_type, 
                           file_path as details FROM file_events
                    UNION ALL
                    SELECT timestamp, 'usb' as category, event_type, 
                           device_name as details FROM usb_events
                    UNION ALL
                    SELECT timestamp, 'activity' as category, 'window_focus' as event_type, 
                           window_title as details FROM user_activity
                    ORDER BY timestamp DESC LIMIT ?
                '''
                cursor.execute(query, (limit,))
            else:
                # Запрос конкретной категории
                tables = {
                    'process': 'process_events',
                    'file': 'file_events',
                    'usb': 'usb_events',
                    'activity': 'user_activity'
                }
                if event_type in tables:
                    cursor.execute(f'''
                        SELECT * FROM {tables[event_type]} 
                        ORDER BY timestamp DESC LIMIT ?
                    ''', (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self):
        """
        Получение статистики для dashboard.
        
        Использует агрегатные функции SQL (COUNT, SUM)
        для эффективного подсчёта без загрузки всех данных в память.
        """
        stats = {}
        with self.get_cursor() as cursor:
            # Статистика процессов
            cursor.execute('''
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN event_type='started' THEN 1 ELSE 0 END) as started,
                       SUM(CASE WHEN event_type='terminated' THEN 1 ELSE 0 END) as terminated
                FROM process_events
                WHERE timestamp > datetime('now', '-24 hours')
            ''')
            stats['processes'] = dict(cursor.fetchone())
            
            # Статистика файлов
            cursor.execute('''
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN event_type='created' THEN 1 ELSE 0 END) as created,
                       SUM(CASE WHEN event_type='modified' THEN 1 ELSE 0 END) as modified,
                       SUM(CASE WHEN event_type='deleted' THEN 1 ELSE 0 END) as deleted
                FROM file_events
                WHERE timestamp > datetime('now', '-24 hours')
            ''')
            stats['files'] = dict(cursor.fetchone())
            
            # Статистика USB
            cursor.execute('''
                SELECT COUNT(*) as total,
                       COUNT(DISTINCT device_id) as unique_devices
                FROM usb_events
                WHERE timestamp > datetime('now', '-24 hours')
            ''')
            stats['usb'] = dict(cursor.fetchone())
            
            # Статистика активности
            cursor.execute('''
                SELECT COUNT(*) as total_windows,
                       COUNT(DISTINCT process_name) as unique_apps
                FROM user_activity
                WHERE timestamp > datetime('now', '-24 hours')
            ''')
            stats['activity'] = dict(cursor.fetchone())
        
        return stats
    
    def close(self):
        """Закрытие всех соединений."""
        if hasattr(self._local, 'connection'):
            self._local.connection.close()
