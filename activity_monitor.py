"""
Модуль мониторинга активности пользователя.

Технические детали Windows windowing system:
1. HWND - handle к окну (уникальный идентификатор)
2. GetForegroundWindow() - получение активного окна
3. Window Station и Desktop - контейнеры для окон
4. Message Queue - очередь сообщений для каждого потока GUI

Desktop Window Manager (DWM):
- С Windows Vista используется композиция окон
- Все окна рендерятся в off-screen buffers
- DWM компонует финальное изображение

Window Messages:
- WM_ACTIVATE - окно активировано/деактивировано
- WM_SETFOCUS - окно получило фокус ввода
- WM_KILLFOCUS - окно потеряло фокус
"""

import threading
import time
from datetime import datetime

# Platform-specific imports
import sys
if sys.platform == 'win32':
    try:
        import win32gui
        import win32process
        WIN32_AVAILABLE = True
    except ImportError:
        WIN32_AVAILABLE = False
        print("[ActivityMonitor] Предупреждение: pywin32 не установлен")
else:
    WIN32_AVAILABLE = False


class UserActivityMonitor:
    """
    Мониторинг активности пользователя (активные окна).
    
    Техническая реализация:
    - Polling GetForegroundWindow() каждые N секунд
    - Определение смены активного окна
    - Расчёт времени, проведённого в каждом окне
    
    Альтернативные подходы:
    - SetWinEventHook(EVENT_SYSTEM_FOREGROUND) - event-driven
    - UI Automation API - более современный подход
    - Accessibility API - для assistive technologies
    """
    
    def __init__(self, database, poll_interval=2):
        """
        Инициализация монитора активности.
        
        Параметры:
        - database: экземпляр Database для логирования
        - poll_interval: интервал опроса активного окна
        """
        self.database = database
        self.poll_interval = poll_interval
        self.running = False
        self.monitor_thread = None
        
        # Текущее активное окно
        self.current_window = {
            'hwnd': None,
            'title': '',
            'process_name': '',
            'pid': 0,
            'start_time': None
        }
    
    def _get_active_window_info(self):
        """
        Получение информации об активном окне.
        
        Windows API последовательность:
        1. GetForegroundWindow() -> HWND активного окна
        2. GetWindowText(HWND) -> заголовок окна (из window memory)
        3. GetWindowThreadProcessId(HWND) -> PID владеющего процесса
        4. OpenProcess() + QueryFullProcessImageName() -> путь к EXE
        
        Техническая деталь:
        HWND (Handle to Window) - это индекс в user32.dll handle table.
        Kernel mode компонент (win32k.sys) управляет реальными window objects.
        """
        if not WIN32_AVAILABLE:
            return None
        
        try:
            # Получение HWND активного окна
            # Техническая деталь: обращается к thread input queue
            hwnd = win32gui.GetForegroundWindow()
            
            if not hwnd:
                return None
            
            # Получение заголовка окна
            # Читает из window structure в памяти процесса
            try:
                title = win32gui.GetWindowText(hwnd)
            except Exception:
                title = ''
            
            # Получение PID процесса, которому принадлежит окно
            # Техническая деталь: HWND -> Thread ID -> Process ID mapping
            try:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
            except Exception:
                pid = 0
            
            # Получение имени процесса через psutil
            process_name = ''
            if pid:
                try:
                    import psutil
                    proc = psutil.Process(pid)
                    process_name = proc.name()
                except Exception:
                    pass
            
            return {
                'hwnd': hwnd,
                'title': title,
                'process_name': process_name,
                'pid': pid
            }
            
        except Exception as e:
            print(f"[ActivityMonitor] Ошибка получения активного окна: {e}")
            return None
    
    def _log_window_activity(self, window_info, duration_seconds):
        """
        Логирование активности в окне.
        
        Параметры:
        - window_info: информация об окне
        - duration_seconds: время активности в секундах
        """
        if not window_info or not window_info.get('title'):
            return
        
        self.database.log_user_activity(
            window_title=window_info['title'],
            process_name=window_info['process_name'],
            process_id=window_info['pid'],
            duration_seconds=duration_seconds
        )
    
    def _monitor_loop(self):
        """
        Основной цикл мониторинга активности.
        
        Алгоритм:
        1. Получение текущего активного окна
        2. Сравнение с предыдущим активным окном
        3. Если изменилось - логирование времени в предыдущем окне
        4. Обновление текущего окна
        
        Техническая деталь:
        Смена активного окна может происходить:
        - Пользователь кликнул на другое окно (mouse input)
        - Alt+Tab (keyboard input)
        - Программно через SetForegroundWindow()
        - Новое окно создано с WS_VISIBLE style
        """
        print("[ActivityMonitor] Мониторинг активности пользователя запущен")
        
        self.current_window['start_time'] = datetime.now()
        
        while self.running:
            try:
                # Получение информации об активном окне
                window_info = self._get_active_window_info()
                
                if window_info:
                    # Проверка, изменилось ли активное окно
                    # Используем HWND для сравнения (уникальный handle)
                    if window_info['hwnd'] != self.current_window['hwnd']:
                        # Окно изменилось - логируем активность в предыдущем окне
                        if self.current_window['hwnd'] and self.current_window['start_time']:
                            duration = (datetime.now() - self.current_window['start_time']).total_seconds()
                            
                            print(f"[ActivityMonitor] Смена окна: '{self.current_window['title']}' " 
                                  f"({self.current_window['process_name']}) -> "
                                  f"'{window_info['title']}' ({window_info['process_name']}), "
                                  f"длительность: {duration:.1f}с")
                            
                            self._log_window_activity(self.current_window, int(duration))
                        
                        # Обновление текущего окна
                        self.current_window = window_info.copy()
                        self.current_window['start_time'] = datetime.now()
                
            except Exception as e:
                print(f"[ActivityMonitor] Ошибка в цикле мониторинга: {e}")
            
            time.sleep(self.poll_interval)
        
        # Логирование последнего окна при остановке
        if self.current_window['hwnd'] and self.current_window['start_time']:
            duration = (datetime.now() - self.current_window['start_time']).total_seconds()
            self._log_window_activity(self.current_window, int(duration))
        
        print("[ActivityMonitor] Мониторинг активности остановлен")
    
    def start(self):
        """Запуск мониторинга активности."""
        if not WIN32_AVAILABLE:
            print("[ActivityMonitor] pywin32 не установлен, мониторинг недоступен")
            return
        
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            print("[ActivityMonitor] Поток мониторинга активности запущен")
    
    def stop(self):
        """Остановка мониторинга активности."""
        if self.running:
            self.running = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=5)
            print("[ActivityMonitor] Мониторинг активности остановлен")
    
    def get_current_activity(self):
        """
        Получение текущей активности для dashboard.
        
        Возвращает информацию о текущем активном окне и времени активности.
        """
        if not self.current_window['hwnd']:
            return None
        
        duration = 0
        if self.current_window['start_time']:
            duration = (datetime.now() - self.current_window['start_time']).total_seconds()
        
        return {
            'window_title': self.current_window['title'],
            'process_name': self.current_window['process_name'],
            'process_id': self.current_window['pid'],
            'duration_seconds': int(duration)
        }


# === Расширенный функционал для детального мониторинга ===

class AdvancedActivityMonitor:
    """
    Расширенный мониторинг активности с дополнительными метриками.
    
    Дополнительные возможности:
    - Мониторинг idle time (время неактивности пользователя)
    - Отслеживание ввода с клавиатуры и мыши (keystroke/mouse tracking)
    - Screenshot на смену окна (для visual activity log)
    
    Важно: требует дополнительных разрешений и этических соображений
    """
    
    @staticmethod
    def get_idle_time():
        """
        Получение времени неактивности пользователя.
        
        Техническая деталь:
        Windows API: GetLastInputInfo()
        - Возвращает tick count последнего input event
        - Input events: keyboard, mouse movement, mouse clicks
        - System tick count из GetTickCount()
        
        Idle time = Current tick count - Last input tick count
        """
        if not WIN32_AVAILABLE:
            return 0
        
        try:
            import ctypes
            from ctypes import Structure, windll, c_uint, sizeof, byref
            
            class LASTINPUTINFO(Structure):
                _fields_ = [
                    ('cbSize', c_uint),
                    ('dwTime', c_uint),
                ]
            
            lastInputInfo = LASTINPUTINFO()
            lastInputInfo.cbSize = sizeof(lastInputInfo)
            
            # GetLastInputInfo заполняет структуру
            windll.user32.GetLastInputInfo(byref(lastInputInfo))
            
            # GetTickCount возвращает миллисекунды с boot time
            millis = windll.kernel32.GetTickCount() - lastInputInfo.dwTime
            
            return millis / 1000.0  # конвертация в секунды
            
        except Exception as e:
            print(f"[AdvancedActivityMonitor] Ошибка получения idle time: {e}")
            return 0
    
    @staticmethod
    def get_window_rect(hwnd):
        """
        Получение размеров и позиции окна.
        
        Windows API: GetWindowRect(HWND)
        - Возвращает RECT структуру (left, top, right, bottom)
        - Координаты в screen space (относительно экрана)
        """
        if not WIN32_AVAILABLE:
            return None
        
        try:
            rect = win32gui.GetWindowRect(hwnd)
            return {
                'left': rect[0],
                'top': rect[1],
                'width': rect[2] - rect[0],
                'height': rect[3] - rect[1]
            }
        except Exception:
            return None
    
    @staticmethod
    def is_window_visible(hwnd):
        """
        Проверка видимости окна.
        
        Windows API: IsWindowVisible(HWND)
        - Проверяет WS_VISIBLE style bit
        - Окно может быть не visible если minimized или hidden
        """
        if not WIN32_AVAILABLE:
            return False
        
        try:
            return win32gui.IsWindowVisible(hwnd)
        except Exception:
            return False
