"""
Модуль мониторинга файловой системы.

Технические детали:
1. NTFS Change Journal - $Extend\$UsnJrnl (USN = Update Sequence Number)
2. ReadDirectoryChangesW - Win32 API для асинхронного мониторинга
3. FILE_NOTIFY_INFORMATION структура возвращает изменения
4. IOCP (I/O Completion Port) для эффективной обработки

Watchdog library:
- Использует ReadDirectoryChangesW с overlapped I/O
- Создаёт отдельный поток для Windows message pump
- Обрабатывает FILE_NOTIFY_CHANGE_* flags
"""

import os
import threading
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FileSystemMonitor(FileSystemEventHandler):
    """
    Мониторинг изменений файловой системы.
    
    Наследует FileSystemEventHandler для обработки событий watchdog.
    
    События watchdog:
    - on_created: FILE_NOTIFY_CHANGE_FILE_NAME (FILE_ACTION_ADDED)
    - on_deleted: FILE_NOTIFY_CHANGE_FILE_NAME (FILE_ACTION_REMOVED)
    - on_modified: FILE_NOTIFY_CHANGE_LAST_WRITE
    - on_moved: FILE_NOTIFY_CHANGE_FILE_NAME (FILE_ACTION_RENAMED_OLD/NEW_NAME)
    """
    
    def __init__(self, database, watch_path=None):
        """
        Инициализация монитора файловой системы.
        
        Параметры:
        - database: экземпляр Database для логирования
        - watch_path: путь для мониторинга (по умолчанию Desktop пользователя)
        """
        super().__init__()
        self.database = database
        
        # Определение пути для мониторинга
        if watch_path is None:
            # По умолчанию мониторим Desktop пользователя
            desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
            self.watch_path = desktop if os.path.exists(desktop) else os.path.expanduser('~')
        else:
            self.watch_path = watch_path
        
        self.observer = None
        self.running = False
        
        print(f"[FileSystemMonitor] Будет мониториться: {self.watch_path}")
    
    def on_created(self, event):
        """
        Обработчик события создания файла/директории.
        
        Техническая деталь:
        ReadDirectoryChangesW возвращает FILE_ACTION_ADDED когда:
        - Файл создаётся (CreateFile с CREATE_NEW)
        - Файл копируется в директорию
        - Файл переименовывается в директорию (appears as 'created')
        
        Параметры event:
        - src_path: полный путь к созданному объекту
        - is_directory: True если это директория
        """
        if event.is_directory:
            print(f"[FileSystem] Создана директория: {event.src_path}")
        else:
            print(f"[FileSystem] Создан файл: {event.src_path}")
            
        # Получение размера файла (если это файл)
        file_size = 0
        if not event.is_directory:
            try:
                file_size = os.path.getsize(event.src_path)
            except OSError:
                pass
        
        self.database.log_file_event(
            event_type='created',
            file_path=event.src_path,
            file_size=file_size,
            is_directory=event.is_directory
        )
    
    def on_deleted(self, event):
        """
        Обработчик события удаления файла/директории.
        
        Техническая деталь:
        FILE_ACTION_REMOVED генерируется когда:
        - DeleteFile() или RemoveDirectory() вызывается
        - Файл перемещается из monitored directory
        
        Внимание: размер файла недоступен (файл уже удалён)
        """
        if event.is_directory:
            print(f"[FileSystem] Удалена директория: {event.src_path}")
        else:
            print(f"[FileSystem] Удалён файл: {event.src_path}")
        
        self.database.log_file_event(
            event_type='deleted',
            file_path=event.src_path,
            file_size=0,
            is_directory=event.is_directory
        )
    
    def on_modified(self, event):
        """
        Обработчик события изменения файла.
        
        Техническая деталь:
        FILE_NOTIFY_CHANGE_LAST_WRITE срабатывает когда:
        - Данные файла изменяются (WriteFile)
        - SetFileTime() изменяет timestamp
        - Атрибуты файла изменяются (SetFileAttributes)
        
        Внимание: может генерироваться несколько раз для одной операции
        (например, текстовый редактор может сохранять частями)
        """
        # Игнорируем события изменения директорий (шумно)
        if not event.is_directory:
            print(f"[FileSystem] Изменён файл: {event.src_path}")
            
            # Получение нового размера
            file_size = 0
            try:
                file_size = os.path.getsize(event.src_path)
            except OSError:
                pass
            
            self.database.log_file_event(
                event_type='modified',
                file_path=event.src_path,
                file_size=file_size,
                is_directory=False
            )
    
    def on_moved(self, event):
        """
        Обработчик события перемещения/переименования.
        
        Техническая деталь:
        ReadDirectoryChangesW возвращает пару событий:
        - FILE_ACTION_RENAMED_OLD_NAME (старое имя)
        - FILE_ACTION_RENAMED_NEW_NAME (новое имя)
        
        Watchdog автоматически объединяет их в одно событие 'moved'
        
        Параметры event:
        - src_path: старый путь
        - dest_path: новый путь
        """
        if event.is_directory:
            print(f"[FileSystem] Перемещена директория: {event.src_path} -> {event.dest_path}")
        else:
            print(f"[FileSystem] Перемещён файл: {event.src_path} -> {event.dest_path}")
        
        # Логируем как два события: удаление старого и создание нового
        self.database.log_file_event(
            event_type='moved_from',
            file_path=event.src_path,
            file_size=0,
            is_directory=event.is_directory
        )
        
        file_size = 0
        if not event.is_directory:
            try:
                file_size = os.path.getsize(event.dest_path)
            except OSError:
                pass
        
        self.database.log_file_event(
            event_type='moved_to',
            file_path=event.dest_path,
            file_size=file_size,
            is_directory=event.is_directory
        )
    
    def start(self):
        """
        Запуск мониторинга файловой системы.
        
        Техническая деталь:
        Observer создаёт отдельный поток, который:
        1. Вызывает ReadDirectoryChangesW с флагом OVERLAPPED
        2. Ожидает завершения через GetQueuedCompletionStatus (IOCP)
        3. Парсит FILE_NOTIFY_INFORMATION структуру
        4. Диспетчеризует события в обработчики
        """
        if not self.running:
            try:
                self.observer = Observer()
                # recursive=True мониторит все подпапки
                self.observer.schedule(self, self.watch_path, recursive=True)
                self.observer.start()
                self.running = True
                print(f"[FileSystemMonitor] Мониторинг запущен: {self.watch_path}")
            except Exception as e:
                print(f"[FileSystemMonitor] Ошибка запуска: {e}")
    
    def stop(self):
        """Остановка мониторинга файловой системы."""
        if self.running:
            try:
                self.observer.stop()
                self.observer.join(timeout=5)
                self.running = False
                print("[FileSystemMonitor] Мониторинг файловой системы остановлен")
            except Exception as e:
                print(f"[FileSystemMonitor] Ошибка остановки: {e}")


# === Расширенный мониторинг с использованием Win32 API напрямую ===

class AdvancedFileSystemMonitor:
    """
    Прямое использование Win32 API для более детального мониторинга.
    
    Преимущества перед watchdog:
    - Доступ к security information (кто изменил файл)
    - Мониторинг extended attributes
    - Более детальная информация о типе изменения
    
    Требует: pywin32
    """
    
    @staticmethod
    def get_file_security_info(file_path):
        """
        Получение информации о безопасности файла.
        
        Использует Win32 API:
        - GetFileSecurity() - получение security descriptor
        - GetSecurityDescriptorOwner() - владелец файла
        - GetSecurityDescriptorDacl() - список управления доступом
        
        Важно для DLP: определение кто имеет доступ к файлу
        """
        try:
            import win32security
            
            # Получение security descriptor
            sd = win32security.GetFileSecurity(
                file_path,
                win32security.OWNER_SECURITY_INFORMATION | 
                win32security.DACL_SECURITY_INFORMATION
            )
            
            # Получение SID владельца
            owner_sid = sd.GetSecurityDescriptorOwner()
            owner_name = win32security.LookupAccountSid(None, owner_sid)[0]
            
            return {
                'owner': owner_name,
                'sid': str(owner_sid)
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_file_attributes_detailed(file_path):
        """
        Получение детальных атрибутов файла.
        
        Windows файл имеет:
        - Basic attributes: ReadOnly, Hidden, System, Archive
        - Extended attributes: Encrypted, Compressed, Offline, NotContentIndexed
        - Timestamps: Creation, LastAccess, LastWrite, ChangeTime
        - Alternate Data Streams (ADS) - скрытые потоки данных
        """
        try:
            import win32file
            import win32con
            
            attrs = win32file.GetFileAttributes(file_path)
            
            return {
                'readonly': bool(attrs & win32con.FILE_ATTRIBUTE_READONLY),
                'hidden': bool(attrs & win32con.FILE_ATTRIBUTE_HIDDEN),
                'system': bool(attrs & win32con.FILE_ATTRIBUTE_SYSTEM),
                'archive': bool(attrs & win32con.FILE_ATTRIBUTE_ARCHIVE),
                'encrypted': bool(attrs & win32con.FILE_ATTRIBUTE_ENCRYPTED),
                'compressed': bool(attrs & win32con.FILE_ATTRIBUTE_COMPRESSED),
                'temporary': bool(attrs & win32con.FILE_ATTRIBUTE_TEMPORARY),
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def check_alternate_data_streams(file_path):
        """
        Проверка наличия Alternate Data Streams (ADS).
        
        Техническая деталь:
        ADS - feature NTFS, позволяющая хранить дополнительные данные:
        - file.txt:stream_name:$DATA
        - Часто используется malware для сокрытия данных
        - Не отображается в Explorer по умолчанию
        
        Важно для DLP: обнаружение скрытой информации
        """
        try:
            import win32file
            
            handle = win32file.CreateFile(
                file_path,
                win32file.GENERIC_READ,
                win32file.FILE_SHARE_READ,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )
            
            # Не реализовано в pywin32, нужен ctypes для FindFirstStreamW
            # TODO: использовать ctypes для полной реализации
            
            win32file.CloseHandle(handle)
            return []
        except Exception as e:
            return []
