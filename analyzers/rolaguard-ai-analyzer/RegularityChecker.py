from analyzers.rolaguard_ai_analyzer.VariableProfilers import (
    LogNormalVariableProfiler,
    NormalVariableProfiler
)
from utils import AlertGenerator

import logging as log
import datetime as dt
import math as mt
import datetime


MIN_PROFILED_TIME = 30

class RegularityChecker():
    def __init__(self, parameters):
        self.parameters = parameters
        self.tdiff_profiler = LogNormalVariableProfiler(0.5, 30, 1)
        self.fcount_profiler = NormalVariableProfiler(0.5, 30, 1)
        self.join_requested = None
        self.lastDate = None
        self.last_fcount = None

    def is_anomaly(self, packet, device, policy):
        try:
            if (
                self.lastDate is not None and
                self.tdiff_profiler.initialized and
                self.fcount_profiler.initialized and
                packet.m_type == "JoinRequest"
            ):
                tdiff = self.calculate_time_difference(packet)
                mean_tdiff = mt.exp(self.tdiff_profiler.gmm.means_.item())
                fcount = self.last_fcount
                mean_fcount = self.fcount_profiler.gmm.means_.item()
                if tdiff > MIN_PROFILED_TIME and tdiff < mean_tdiff and fcount < mean_fcount:
                    probability_tdiff = self.tdiff_profiler.predict(tdiff)
                    probability_fcount = self.fcount_profiler.predict(tdiff) 
                    suspicious_packet = mt.sqrt(probability_fcount*probability_tdiff) < self.parameters['jr_tdiff_sensitivity']
                    log.debug(f"JR analyzed:\n\ttdiff prob: {probability_tdiff}\n\tfcount prob: {probability_fcount}\n\tsuspicious: {suspicious_packet}")
                    if suspicious_packet and policy.is_enabled("LAF-501"):
                        AlertGenerator.emit_alert(
                            "LAF-501", packet,
                            device = device,
                            delta = tdiff,
                            median = mean_tdiff,
                            last_fcount = fcount,
                            mean_last_fcount = mean_fcount
                            )

            if (
                self.join_requested is not None and
                self.join_requested and
                packet.m_type in ["ConfirmedDataUp", "UnconfirmedDataUp"] and
                packet.f_count is not None and
                packet.f_count > 16 and
                policy.is_enabled("LAF-501")
            ):
                log.debug(f"JR between data packets. Data packet has a f_count={packet.f_count}")
                AlertGenerator.emit_alert(
                    "LAF-501", packet,
                    device = device,
                    )
                self.join_requested = False
        except Exception as exc:
            log.error("Error predicting if JR is abnormal: {0}".format(exc))


    def profile(self, packet):
        try:
            if packet.m_type == "JoinRequest":
                if self.lastDate is not None:
                    tdiff = self.calculate_time_difference(packet)
                    if tdiff > MIN_PROFILED_TIME:
                        self.tdiff_profiler.profile(tdiff)
                        if self.last_fcount is not None:
                            self.fcount_profiler.profile(self.last_fcount)
                self.lastDate = packet.date
                self.join_requested = True
            if packet.m_type in ["ConfirmedDataUp", "UnconfirmedDataUp"]:
                self.last_fcount = packet.f_count
                if packet.f_count < 16:
                    self.join_requested = False

        except Exception as exc:
            log.error("Error profiling JRs: {0}".format(exc))


    def calculate_time_difference(self, packet):
        try:
            return (packet.date - self.lastDate).seconds
        except Exception as exc:
            log.error("Error calculating time difference between JR: {0}".format(exc))


    def time_inactive(self, today):
        if self.lastDate is None:
            return datetime.timedelta(0)
        else:
            return (today - self.lastDate)


    def is_inactive(self, today):
        median = self.tdiff_profiler.get_mean()
        inactive_time =  self.time_inactive(today)
        return (median is None and inactive_time > dt.timedelta(days=16)) or \
               (median and inactive_time.seconds > 50 * median)