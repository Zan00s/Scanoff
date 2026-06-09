import time
import schedule

class Scheduler:
    def __init__(self, config, main_func):
        self.config = config
        self.main_func = main_func
        self.interval = config.schedule_interval

    def start(self):
        if self.interval is None or self.interval == 0:
            print("[*] No schedule configured, running once.")
            self.main_func()
            return

        print(f"[*] Scheduling scan every {self.interval} seconds.")
        schedule.every(self.interval).seconds.do(self.main_func)

        while True:
            schedule.run_pending()
            time.sleep(1)
