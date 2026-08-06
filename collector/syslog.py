#!/usr/bin/env python3
"""
Syslog Listener - Listens for syslog messages over UDP/TCP.
"""

from __future__ import annotations

import socket
import threading
import signal
import time
from collections import defaultdict
from typing import Callable, Optional, Tuple


class TokenBucket:
    """Token bucket rate limiter — per-source-IP rate control."""

    def __init__(self, rate: float = 100.0, burst: int = 200):
        self.rate = rate
        self.burst = burst
        self._tokens: dict[str, float] = defaultdict(float)
        self._last: dict[str, float] = defaultdict(float)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        elapsed = now - self._last[key]
        self._last[key] = now
        self._tokens[key] = min(self.burst, self._tokens[key] + elapsed * self.rate)
        if self._tokens[key] >= 1.0:
            self._tokens[key] -= 1.0
            return True
        return False

    def reset(self, key: str) -> None:
        self._tokens.pop(key, None)
        self._last.pop(key, None)


class SyslogListener:
    """Listens for syslog messages on UDP or TCP with per-source rate limiting."""

    def __init__(
        self,
        port: int = 514,
        protocol: str = "udp",
        parser: Optional[Callable] = None,
        callback: Optional[Callable] = None,
        bind_address: str = "0.0.0.0",
        buffer_size: int = 4096,
        rate_limit: float = 100.0,
        rate_burst: int = 200,
        register_signals: bool = True,
    ):
        self.port = port
        self.protocol = protocol.lower()
        self.parser = parser
        self.callback = callback
        self.bind_address = bind_address
        self.buffer_size = buffer_size
        self.rate_limit = rate_limit
        self.rate_burst = rate_burst

        self._running = False
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._limiter = TokenBucket(rate=rate_limit, burst=rate_burst)

        # Only register signal handlers when running standalone (CLI mode).
        # In daemon mode the parent process owns the signal handlers.
        if register_signals:
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
            except Exception:
                if self._running:
                    pass
    
    def _handle_udp(self) -> None:
        """Handle incoming UDP messages."""
        sock = self._socket
        if sock is None:
            return
        try:
            data, addr = sock.recvfrom(self.buffer_size)
            if data:
                message = data.decode('utf-8', errors='ignore').strip()
                self._process_message(message, addr)
        except socket.timeout:
            pass
        except Exception:
            pass
    
    def _handle_tcp(self) -> None:
        """Handle incoming TCP connections."""
        sock = self._socket
        if sock is None:
            return
        try:
            client, addr = sock.accept()
            client.settimeout(5.0)

            try:
                buffer = ""
                while True:
                    data = client.recv(self.buffer_size)
                    if not data:
                        break
                    buffer += data.decode('utf-8', errors='ignore')
                    # Process complete newline-delimited messages so a sender
                    # that batches multiple syslog lines in one send is handled.
                    lines = buffer.split('\n')
                    buffer = lines.pop()
                    for raw in lines:
                        message = raw.strip()
                        if message:
                            self._process_message(message, addr)
                    if len(buffer) > self.buffer_size * 8:
                        buffer = ""
            finally:
                client.close()
        except socket.timeout:
            pass
        except Exception:
            pass
    
    def _process_message(self, message: str, source: Tuple) -> None:
        """Process a syslog message with rate limiting."""
        if not message:
            return

        source_ip = source[0] if source else "unknown"

        if not self._limiter.allow(source_ip):
            return

        record = None

        if self.parser:
            try:
                record = self.parser(message)
            except Exception:
                pass

        if self.callback:
            try:
                self.callback(message, record, source)
            except Exception:
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
        self._socket: socket.socket | None = None
    
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
        except Exception:
            pass
    
    def stop(self) -> None:
        """Stop forwarder."""
        if self._socket:
            self._socket.close()
            self._socket = None