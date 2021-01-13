from analyzers.rolaguard_ai_analyzer.VariableProfilers import (
    NormalVariableProfiler, IntegerVaribleProfiler, TriangleVariableProfiler)
from db.Models import Device

from collections import defaultdict
import datetime as dt
import logging as log
import math as mt
import datetime



class DeviceSessionProfiler():
    def __init__(self, parameters):
        self.parameters = parameters
        self.initialized = False
        self.rssi_profiler = defaultdict(lambda: NormalVariableProfiler(0.5, 41, 1))
        self.tdiff_profiler = TriangleVariableProfiler(0.5, 29)
        self.size_profiler = IntegerVaribleProfiler(0.95, 59)
        self.cdiff_profiler = IntegerVaribleProfiler(0.9, 61)

        self.last_count = None
        self.last_tmst = None
        self.last_date = None

        self.db_object = None

        self.normal_packets_count = {'rssi' : 0, 'tdiff' : 0, 
                                     'cdiff' : 0, 'size' : 0}
        self.active_profiler = {'rssi' : True, 'tdiff' : True, 
                                'cdiff' : True, 'size' : True}
        self.n_active = 0

    def is_anomaly(self, packet):
        try:
            if not self.initialized:
                return False, {}, []
            
            tdiff, cdiff = self.calculate_differences(packet)
            if cdiff <= 0:
                return False, {}, []

            probabilities = {'rssi' : mt.sqrt(self.rssi_profiler[packet.gateway].predict(packet.rssi)),
                             'size' : self.size_profiler.predict(packet.size),
                             'tdiff' : mt.sqrt(self.tdiff_profiler.predict(tdiff)),
                             'cdiff' : mt.sqrt(self.cdiff_profiler.predict(cdiff))}
            abnormal = []
            n_suspicious = 0
            self.n_active = 0
            for variable, prob in probabilities.items():
                if prob < self.parameters[variable + "_sensitivity"]:
                    self.active_profiler[variable] = (self.normal_packets_count[variable] > self.parameters['grace_period'])
                    self.normal_packets_count[variable] = 0
                    if self.active_profiler[variable]:
                        n_suspicious += 1
                        abnormal.append(variable)
                else:
                    self.normal_packets_count[variable] += 1
                    if self.normal_packets_count[variable] > self.parameters['grace_period']:
                        self.active_profiler[variable] = True

                self.n_active += self.active_profiler[variable]
            
            is_anomaly = (n_suspicious >= self.parameters['max_suspicious'])
            return is_anomaly, probabilities, abnormal

        except Exception as exc:
            log.error("Error predicting if packet is abnormal:\n {0}".format(exc))
            return False, [], []


    def profile(self, packet):
        try:
            if self.db_object is None and packet.dev_eui and packet.data_collector_id:
                self.db_object = Device.find_with(dev_eui = packet.dev_eui, data_collector_id=packet.data_collector_id)

            if (packet.tmst is None) or (packet.f_count is None):
                return

            if self.last_count is None or self.last_tmst is None:
                self.last_count = packet.f_count
                self.last_tmst = packet.tmst
            else:
                tdiff, cdiff = self.calculate_differences(packet)
                if cdiff > 0:
                    new_measure = self.tdiff_profiler.profile(tdiff)
                    if new_measure and self.db_object:
                        self.db_object.activity_freq = self.tdiff_profiler.median

                    self.cdiff_profiler.profile(cdiff)

                    self.rssi_profiler[packet.gateway].profile(packet.rssi)
                    self.size_profiler.profile(packet.size)
                    
                    self.initialized = True
                    self.last_count = packet.f_count
                    self.last_tmst = packet.tmst
                    self.last_date = packet.date

        except Exception as exc:
            log.error("Error profiling packet:\n{0}".format(exc))

    def calculate_differences(self, packet):
        cdiff = int(packet.f_count - self.last_count) % (2**16)
        if cdiff > 0:
            tdiff = (int(packet.tmst - self.last_tmst) % (2**32)) / cdiff / 1e6
            return tdiff, cdiff
        else:
            return 0, 0

    def time_inactive(self, today):
        if self.last_date is None:
            return datetime.timedelta(0)
        else:
            return (today - self.last_date)

    def is_inactive(self, today):
        median = self.tdiff_profiler.median
        inactive_time =  self.time_inactive(today)
        return (median is None and inactive_time > dt.timedelta(hours=25))  or \
               (median and inactive_time.seconds > 30 * median)
