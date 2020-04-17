import datetime as dt
import logging as log


class Chronometer():
    def __init__(self, report_every):
        self.report_every = report_every
        self.n_laps = 0
        self.period_start = {}
        self.elapsed_time = {}
        self.last_name = None

    def start(self, name):
        self.period_start[name] = dt.datetime.now()
        self.last_name = name

    def stop(self, name=None):
        if name is None: name = self.last_name
        if name in self.elapsed_time:
            self.elapsed_time[name] +=  0.001 * (dt.datetime.now() - self.period_start[name]).microseconds / 1000
        else:
            self.elapsed_time[name] = (dt.datetime.now() - self.period_start[name]).microseconds / 1000
        self.last_name = None

    def lap(self):
        for name in self.elapsed_time:
            self.elapsed_time[name] /=  1.001

        if self.n_laps >= self.report_every:
            self.n_laps = 0
            mess = 'Chronometer:'
            for k, v in self.elapsed_time.items():
                mess += f"\t{k}: {v:.4}"
            log.debug(mess)
        else:
            self.n_laps += 1
