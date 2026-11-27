"""Report service state transitions without repeating every health poll."""
import logging
import threading
import time


class StateLog:
    def __init__(self, logger, label):
        self.logger = logger
        self.label = label
        self.state = None
        self.since = 0
        self.warned = False
        self.lock = threading.Lock()

    def failure(self, error):
        message = str(error)
        with self.lock:
            pending = message == "Waiting for initial route policy"
            now = time.monotonic()
            if self.state == message:
                if not pending or self.warned or now - self.since < 60:
                    return
            else:
                self.since = now
                self.warned = False
            self.state = message
            level = logging.INFO if pending and now - self.since < 60 else logging.WARNING
            self.warned = level == logging.WARNING
            self.logger.log(level, "%s: %s", self.label, message)

    def healthy(self):
        with self.lock:
            if self.state is not None:
                self.logger.info("%s: recovered", self.label)
                self.state = None
