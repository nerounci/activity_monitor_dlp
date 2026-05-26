"""
Модуль мониторинга USB устройств.

Технические детали Windows USB stack:
1. Plug and Play (PnP) Manager - kernel component
2. USB Host Controller (UHCI/OHCI/EHCI/xHCI)
3. USB Hub Driver - управляет портами
4. USB Device Driver - функциональный драйвер устройства

Device Instance ID format:
USB\VID_xxxx&PID_yyyy\SerialNumber

WMI классы:
- Win32_USBControllerDevice - связь контроллера с устройством
- Win32_PnPEntity - информация о PnP устройстве
- Win32_DiskDrive - для USB mass storage
"""

import threading
import time
try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False
    print("[USBMonitor] Предупреждение: модуль wmi не установлен")


class USBMonitor:
    """
    Мониторинг подключения и отключения USB устройств.
    
    Техническая реализация:
    - WMI event subscriptions (асинхронные уведомления)
    - Подписка на __InstanceCreationEvent и __InstanceDeletionEvent
    - Фильтрация по USB устройствам через WHERE clause
    
    Альтернативные подходы:
    - RegisterDeviceNotification() Win32 API
    - SetupAPI для прямой работы с device information set
    - Raw WM_DEVICECHANGE messages
    """
    
    def __init__(self, database, poll_interval=3):
        """
        Инициализация монитора USB устройств.
        
        Параметры:
        - database: экземпляр Database для логирования
        - poll_interval: интервал опроса для polling mode (если WMI недоступен)
        """
        self.database = database
        self.poll_interval = poll_interval
        self.running = False
        self.monitor_thread = None
        
        # Кэш текущих USB устройств {device_id: device_info}
        self.current_devices = {}
        
        if WMI_AVAILABLE:
            try:
                self.wmi_connection = wmi.WMI()
                self.use_wmi_events = True
                self._update_device_cache()
            except Exception as e:
                print(f"[USBMonitor] WMI недоступен: {e}, переход на polling")
                self.use_wmi_events = False
        else:
            self.use_wmi_events = False
    
    def _parse_device_id(self, device_id):
        """
        Парсинг Device Instance ID для извлечения VID/PID.
        
        Формат USB Device ID:
        USB\VID_046D&PID_C52B\5&1234ABCD&0&3
        
        Где:
        - VID (Vendor ID): идентификатор производителя (USB-IF assigned)
        - PID (Product ID): идентификатор продукта (vendor assigned)
        - Серийный номер: уникальный идентификатор экземпляра
        
        Техническая деталь:
        VID/PID берутся из USB Device Descriptor, который устройство
        отправляет хосту во время enumeration process.
        """
        vid = pid = ''
        
        try:
            if 'VID_' in device_id:
                vid_start = device_id.index('VID_') + 4
                vid = device_id[vid_start:vid_start+4]
            
            if 'PID_' in device_id:
                pid_start = device_id.index('PID_') + 4
                pid = device_id[pid_start:pid_start+4]
        except Exception:
            pass
        
        return vid, pid
    
    def _get_usb_devices(self):
        """
        Получение списка USB устройств через WMI.
        
        Техническая деталь:
        WMI запрос к CIM (Common Information Model) database:
        - Win32_PnPEntity представляет устройства в device tree
        - DeviceID начинается с "USB\" для USB устройств
        - ConfigManagerErrorCode: 0 = устройство работает корректно
        
        Device tree hierarchy:
        Root -> USB Host Controller -> USB Hub -> USB Device
        """
        devices = {}
        
        if not WMI_AVAILABLE:
            return devices
        
        try:
            # Запрос USB устройств через WMI
            # WHERE clause фильтрует только USB устройства
            for device in self.wmi_connection.query(
                "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'"
            ):
                device_id = device.DeviceID
                
                # Извлечение VID/PID из Device ID
                vid, pid = self._parse_device_id(device_id)
                
                # Определение типа устройства
                device_type = 'Unknown'
                if device.PNPClass:
                    device_type = device.PNPClass
                
                devices[device_id] = {
                    'device_id': device_id,
                    'name': device.Name if device.Name else 'Unknown Device',
                    'description': device.Description if device.Description else '',
                    'manufacturer': device.Manufacturer if device.Manufacturer else '',
                    'device_type': device_type,
                    'status': device.Status if device.Status else 'Unknown',
                    'vendor_id': vid,
                    'product_id': pid
                }
        except Exception as e:
            print(f"[USBMonitor] Ошибка получения USB устройств: {e}")
        
        return devices
    
    def _update_device_cache(self):
        """Обновление кэша USB устройств."""
        self.current_devices = self._get_usb_devices()
    
    def _detect_new_devices(self, new_devices):
        """
        Определение новых USB устройств (подключенных).
        
        Алгоритм:
        1. Сравнение Device ID в новом и старом snapshot
        2. Устройства в new но не в old = подключенные устройства
        3. Логирование события 'connected'
        """
        new_ids = set(new_devices.keys())
        old_ids = set(self.current_devices.keys())
        
        connected_ids = new_ids - old_ids
        
        for device_id in connected_ids:
            device = new_devices[device_id]
            print(f"[USBMonitor] USB подключён: {device['name']} (VID: {device['vendor_id']}, PID: {device['product_id']})")
            
            self.database.log_usb_event(
                event_type='connected',
                device_id=device_id,
                device_name=device['name'],
                device_type=device['device_type'],
                vendor_id=device['vendor_id'],
                product_id=device['product_id']
            )
    
    def _detect_removed_devices(self, new_devices):
        """
        Определение отключённых USB устройств.
        
        Алгоритм:
        1. Устройства в old но не в new = отключённые устройства
        2. Логирование события 'disconnected'
        
        Техническая деталь:
        Отключение происходит:
        - Физическое извлечение устройства
        - "Safely Remove Hardware" (удаление из device tree)
        - Driver unload или disable
        """
        new_ids = set(new_devices.keys())
        old_ids = set(self.current_devices.keys())
        
        removed_ids = old_ids - new_ids
        
        for device_id in removed_ids:
            device = self.current_devices[device_id]
            print(f"[USBMonitor] USB отключён: {device['name']} (VID: {device['vendor_id']}, PID: {device['product_id']})")
            
            self.database.log_usb_event(
                event_type='disconnected',
                device_id=device_id,
                device_name=device['name'],
                device_type=device['device_type'],
                vendor_id=device['vendor_id'],
                product_id=device['product_id']
            )
    
    def _monitor_loop_polling(self):
        """
        Цикл мониторинга через polling (резервный метод).
        
        Используется когда WMI events недоступны.
        Периодически запрашивает список устройств и сравнивает.
        """
        print("[USBMonitor] Мониторинг USB (polling mode) запущен")
        
        while self.running:
            try:
                new_devices = self._get_usb_devices()
                
                self._detect_new_devices(new_devices)
                self._detect_removed_devices(new_devices)
                
                self.current_devices = new_devices
                
            except Exception as e:
                print(f"[USBMonitor] Ошибка в цикле мониторинга: {e}")
            
            time.sleep(self.poll_interval)
        
        print("[USBMonitor] Мониторинг USB остановлен")
    
    def _monitor_loop_wmi_events(self):
        """
        Цикл мониторинга через WMI event subscriptions (оптимальный).
        
        Техническая деталь:
        WMI создаёт event sink, который получает асинхронные уведомления:
        - __InstanceCreationEvent - новое устройство в CIM database
        - __InstanceDeletionEvent - устройство удалено из CIM database
        
        Преимущества:
        - Нет polling overhead
        - Мгновенное уведомление (event-driven)
        - Меньше нагрузки на CPU
        """
        print("[USBMonitor] Мониторинг USB (WMI events) запущен")
        
        try:
            # Создание watchers для подключения и отключения
            # WITHIN 2 - проверка каждые 2 секунды для новых событий
            creation_watcher = self.wmi_connection.watch_for(
                notification_type="Creation",
                wmi_class="Win32_PnPEntity",
                delay_secs=2,
                fields=["DeviceID", "Name", "Description"]
            )
            
            deletion_watcher = self.wmi_connection.watch_for(
                notification_type="Deletion",
                wmi_class="Win32_PnPEntity",
                delay_secs=2,
                fields=["DeviceID"]
            )
            
            while self.running:
                # Проверка событий подключения
                try:
                    new_device = creation_watcher(timeout_ms=1000)
                    if new_device and new_device.DeviceID.startswith('USB'):
                        device_id = new_device.DeviceID
                        vid, pid = self._parse_device_id(device_id)
                        
                        print(f"[USBMonitor] USB подключён (event): {new_device.Name}")
                        
                        self.database.log_usb_event(
                            event_type='connected',
                            device_id=device_id,
                            device_name=new_device.Name or 'Unknown',
                            device_type=new_device.PNPClass if hasattr(new_device, 'PNPClass') else '',
                            vendor_id=vid,
                            product_id=pid
                        )
                except wmi.x_wmi_timed_out:
                    pass
                
                # Проверка событий отключения
                try:
                    removed_device = deletion_watcher(timeout_ms=1000)
                    if removed_device and removed_device.DeviceID.startswith('USB'):
                        print(f"[USBMonitor] USB отключён (event): {removed_device.DeviceID}")
                        
                        self.database.log_usb_event(
                            event_type='disconnected',
                            device_id=removed_device.DeviceID,
                            device_name='Unknown',
                            device_type='',
                            vendor_id='',
                            product_id=''
                        )
                except wmi.x_wmi_timed_out:
                    pass
                
        except Exception as e:
            print(f"[USBMonitor] Ошибка WMI events: {e}, переход на polling")
            self._monitor_loop_polling()
    
    def start(self):
        """Запуск мониторинга USB устройств."""
        if not self.running:
            self.running = True
            
            if self.use_wmi_events:
                self.monitor_thread = threading.Thread(
                    target=self._monitor_loop_wmi_events,
                    daemon=True
                )
            else:
                self.monitor_thread = threading.Thread(
                    target=self._monitor_loop_polling,
                    daemon=True
                )
            
            self.monitor_thread.start()
            print("[USBMonitor] Поток мониторинга USB запущен")
    
    def stop(self):
        """Остановка мониторинга USB устройств."""
        if self.running:
            self.running = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=5)
            print("[USBMonitor] Мониторинг USB остановлен")
    
    def get_current_devices(self):
        """Получение списка текущих USB устройств для dashboard."""
        return list(self.current_devices.values())
