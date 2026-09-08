from __future__ import annotations

import socket
import threading
from typing import Callable


class OneShotTCPServer:
    def __init__(self, handler: Callable[[socket.socket], None]):
        self.handler = handler
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(1)
        self.port = self.socket.getsockname()[1]
        self.error = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            connection, _ = self.socket.accept()
            with connection:
                connection.settimeout(2)
                self.handler(connection)
        except Exception as exc:
            self.error = exc
        finally:
            self.socket.close()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.thread.join(timeout=3)
        if self.error and exc is None:
            raise self.error
