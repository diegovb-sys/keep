from threading import Lock, Thread
import asyncio
from typing import Type, Dict, Any

from keep.api.tasks import process_watcher_task


class WatcherManagerMeta(type):
    _instances: Dict[Type, Any] = {}
    _lock: Lock = Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if cls not in cls._instances:
                cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]


class WatcherManager(metaclass=WatcherManagerMeta):
    def __init__(self):
        self.loop = None
        self.thread = None
        self.stop_event = asyncio.Event()
        self.watcher_task = None

    def __run_watcher_in_thread(self):
        asyncio.set_event_loop(self.loop)
        self.watcher_task = self.loop.create_task(process_watcher_task.async_process_watcher(self.stop_event))
        self.loop.run_forever()

    def start(self):
        self.loop = asyncio.new_event_loop()
        self.thread = Thread(target=self.__run_watcher_in_thread, daemon=True, name="WatcherThread")
        self.thread.start()

    def stop(self):
        if self.loop:
            self.loop.call_soon_threadsafe(self.stop_event.set)
            if self.watcher_task:
                self.loop.call_soon_threadsafe(self.watcher_task.cancel)
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)