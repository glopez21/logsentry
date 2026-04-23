#!/usr/bin/env python3
"""
File Tail Collector - Watches log files and processes new lines in real-time.
"""

import os
import time
import signal
import threading
from pathlib import Path
from typing import Callable, Optional

try:
    from rich.console import Console
    from rich.theme import Theme
except ImportError:
    Console = None
    Theme = None


DEFAULT_THEME = Theme({
    "critical": "red bold",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "blue"
})


class FileTailCollector:
    """Watches a log file and processes new lines in real-time."""
    
    def __init__(
        self,
        filepath: str,
        parser: Optional[Callable] = None,
        callback: Optional[Callable] = None,
        console: Optional[Console] = None,
        follow_delay: float = 0.1
    ):
        self.filepath = filepath
        self.parser = parser
        self.callback = callback
        self.console = console or (Console(theme=DEFAULT_THEME) if Console else None)
        self.follow_delay = follow_delay
        
        self._running = False
        self._position = 0
        self._file = None
        self._lock = threading.Lock()
        
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print("\n[+] Shutting down...")
        self.stop()
    
    def start(self, process_existing: bool = False) -> None:
        """Start watching the file."""
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"File not found: {self.filepath}")
        
        self._running = True
        self._file = open(self.filepath, 'r')
        
        # Seek to end or beginning
        if process_existing:
            self._position = 0
        else:
            self._file.seek(0, os.SEEK_END)
            self._position = self._file.tell()
        
        print(f"[*] Watching: {self.filepath}")
        print(f"[*] Process existing: {process_existing}")
        
        # Inotify-style polling loop
        while self._running:
            line = self._file.readline()
            if not line:
                time.sleep(self.follow_delay)
                continue
            
            self._position = self._file.tell()
            self._process_line(line.strip())
    
    def stop(self) -> None:
        """Stop watching the file."""
        self._running = False
        if self._file:
            self._file.close()
            self._file = None
    
    def _process_line(self, line: str) -> None:
        """Process a single log line."""
        if not line:
            return
        
        record = None
        
        # Parse if parser provided
        if self.parser:
            try:
                record = self.parser(line)
            except Exception as e:
                pass
        
        # Invoke callback if provided
        if self.callback:
            try:
                self.callback(line, record)
            except Exception as e:
                pass
        
        # Default: print alerts
        if record and self.console:
            severity = record.get('severity', 'info').upper()
            msg = record.get('raw_message', '') or record.get('message', '') or line
            
            if severity in ['CRITICAL', 'HIGH']:
                self.console.print(f"[{severity.lower()}] ALERT: {msg}")
            elif severity == 'MEDIUM':
                self.console.print(f"[yellow] WARNING: {msg}")


class BatchFileCollector:
    """Collects events and batches them for processing."""
    
    def __init__(
        self,
        filepath: str,
        parser: Optional[Callable] = None,
        batch_size: int = 10,
        batch_timeout: float = 5.0,
        callback: Optional[Callable] = None
    ):
        self.filepath = filepath
        self.parser = parser
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.callback = callback
        
        self._collector = FileTailCollector(filepath, parser, self._batch_callback)
        self._batch = []
        self._batch_lock = threading.Lock()
        self._running = False
    
    def start(self, process_existing: bool = False) -> None:
        """Start batch collecting."""
        self._running = True
        self._collector.start(process_existing=process_existing)
    
    def stop(self) -> None:
        """Stop collecting."""
        self._running = False
        self._collector.stop()
        self._flush_batch()
    
    def _batch_callback(self, line: str, record: Optional[dict]) -> None:
        """Callback for batch processing."""
        with self._batch_lock:
            self._batch.append((line, record))
            
            if len(self._batch) >= self.batch_size:
                self._flush_batch()
    
    def _flush_batch(self) -> None:
        """Flush batch to callback."""
        if not self._batch:
            return
        
        batch_to_process = self._batch[:]
        self._batch.clear()
        
        if self.callback:
            try:
                self.callback(batch_to_process)
            except Exception as e:
                pass