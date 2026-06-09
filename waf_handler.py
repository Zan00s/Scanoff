import time
import random

class WafHandler:
    def __init__(self, initial_delay=0.1, max_delay=5.0, jitter=0.5, proxy_list=None):
        self.current_delay = initial_delay
        self.max_delay = max_delay
        self.jitter = jitter
        self.proxy_list = proxy_list or []
        self.current_proxy_index = 0
        self.consecutive_success = 0

    def before_request(self):
        if self.current_delay > 0:
            sleep_time = self.current_delay + random.uniform(0, self.jitter)
            time.sleep(sleep_time)

        proxy = None
        if self.proxy_list and self.current_delay > 1.0:
            proxy = self.proxy_list[self.current_proxy_index % len(self.proxy_list)]
        return proxy

    def report_response(self, status_code):
        if status_code in (429, 403):
            self.current_delay = min(self.current_delay * 2 + 0.5, self.max_delay)
            if self.proxy_list and status_code == 403:
                self.current_proxy_index += 1
            self.consecutive_success = 0
        else:
            self.consecutive_success += 1
            if self.consecutive_success >= 5:
                self.current_delay = max(self.current_delay / 2, 0.1)
                self.consecutive_success = 0
