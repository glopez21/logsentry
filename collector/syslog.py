#!/usr/bin/env python3
"""
Syslog Listener - Listens for syslog messages over UDP/TCP.
"""

import socket
import threading
import signal
import time
from typing import Callable, Optional, Tuple


class SyslogListener:
    """Listens for syslog messages on UDP or TCP."""
    
    def __init__(
        self,
        port: int = 514,
        protocol: str = "udp",
        parser: Optional[Callable] = None,
        callback: Optional[Callable] = None,
        bind_address: str = "0.0.0.0",
        buffer_size: int = 4096
    ):
        self.port = port
        self.protocol = protocol.lower()
        self.parser = parser
        self.callback = callback
        self.bind_address = bind_address
        self.buffer_size = buffer_size
        
        self._running = False
        self._socket = None
        self._thread = None
        
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print("\n[+] Shutting down...")
        self.stop()
    
    def start(self) -> None:
        """Start listening for syslog messages."""
        self._running = True
        
        if self.protocol == "udp":
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        self._socket.bind((self.bind_address, self.port))
        self._socket.settimeout(1.0)
        
        print(f"[*] Listening on {self.bind_address}:{self.port}/{self.protocol.upper()}")
        
        if self.protocol == "tcp":
            self._socket.listen(5)
        
        # Start listener thread
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()
    
    def stop(self) -> None:
        """Stop listening."""
        self._running = False
        if self._socket:
            self._socket.close()
            self._socket = None
    
    def _listen_loop(self) -> None:
        """Main listening loop."""
        while self._running:
            try:
                if self.protocol == "udp":
                    self._handle_udp()
                else:
                    self._handle_tcp()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    pass
    
    def _handle_udp(self) -> None:
        """Handle incoming UDP messages."""
        try:
            data, addr = self._socket.recvfrom(self.buffer_size)
            if data:
                message = data.decode('utf-8', errors='ignore').strip()
                self._process_message(message, addr)
        except socket.timeout:
            pass
        except Exception as e:
            pass
    
    def _handle_tcp(self) -> None:
        """Handle incoming TCP connections."""
        try:
            client, addr = self._socket.accept()
            client.settimeout(5.0)
            
            try:
                while True:
                    data = client.recv(self.buffer_size)
                    if not data:
                        break
                    message = data.decode('utf-8', errors='ignore').strip()
                    if message:
                        self._process_message(message, addr)
            finally:
                client.close()
        except socket.timeout:
            pass
        except Exception as e:
            pass
    
    def _process_message(self, message: str, source: Tuple) -> None:
        """Process a syslog message."""
        if not message:
            return
        
        record = None
        
        if self.parser:
            try:
                record = self.parser(message)
            except Exception as e:
                pass
        
        if self.callback:
            try:
                self.callback(message, record, source)
            except Exception as e:
                pass
    
    def is_running(self) -> bool:
        """Check if listener is running."""
        return self._running


class SyslogForwarder:
    """Forwards syslog messages to another destination."""
    
    def __init__(
        self,
        destination: str,
        port: int = 514,
        protocol: str = "udp"
    ):
        self.destination = destination
        self.port = port
        self.protocol = protocol.lower()
        self._socket = None
    
    def start(self) -> None:
        """Initialize forwarder."""
        if self.protocol == "udp":
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    def forward(self, message: str) -> None:
        """Forward a message."""
        if not self._socket:
            return
        
        try:
            self._socket.sendto(
                message.encode('utf-8'),
                (self.destination, self.port)
            )
        except Exception as e:
            pass
    
    def stop(self) -> None:
        """Stop forwarder."""
        if self._socket:
            self._socket.close()
            self._socket = None