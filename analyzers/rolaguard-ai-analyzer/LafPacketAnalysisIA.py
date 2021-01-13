import warnings
import os, json
import logging as log
import datetime as dt
from collections import defaultdict, namedtuple

from utils import AlertGenerator
from analyzers.rolaguard_ai_analyzer.DeviceSessionProfiler import DeviceSessionProfiler
from analyzers.rolaguard_ai_analyzer.RegularityChecker import RegularityChecker
from db.Models import Gateway, Device, DeviceSession, Packet, DataCollector


parameters = {'rssi_sensitivity' : 0.05,
              'size_sensitivity' : 0.05,
              'tdiff_sensitivity': 0.9,
              'cdiff_sensitivity': 0.05,
              'max_suspicious' : 2,
              'grace_period' : 10,
              'jr_tdiff_sensitivity' : 0.1,
              }

device_profilers = defaultdict(lambda: DeviceSessionProfiler(parameters))
jr_regularity_checker = defaultdict(lambda: RegularityChecker(parameters))


def process_packet(packet, policy):

    device = Device.find_with(dev_eui = packet.dev_eui, data_collector_id = packet.data_collector_id)

    if device:
        parameters.update(policy.get_parameters("LAF-501"))
        jr_regularity_checker[device.id].is_anomaly(packet, device = device, policy = policy)
        jr_regularity_checker[device.id].profile(packet)

    if packet.m_type  == "ConfirmedDataUp":
        device_session = DeviceSession.find_with(dev_addr=packet.dev_addr, data_collector_id=packet.data_collector_id)
        if device_session is None: return

        parameters.update(policy.get_parameters("LAF-503"))

        profiler = device_profilers[device_session.id]
        is_outlier, probabilities, _ = profiler.is_anomaly(packet)
        if is_outlier and policy.is_enabled("LAF-503"):
            AlertGenerator.emit_alert("LAF-503", packet,
                                      device_session=device_session) 

        device_profilers[device_session.id].profile(packet)

    garbage_collection(packet.date)



last_gc = dt.datetime.now()
def garbage_collection(packet_date):
    global last_gc
    try:
        if (dt.datetime.now() - last_gc).seconds < 60:
            return
        to_delete = []
        for device_session_id, profiler in device_profilers.items():
            if profiler.is_inactive(packet_date):
                to_delete.append(device_session_id)

        for device_session_id in to_delete:
            del device_profilers[device_session_id]

        to_delete = []
        for device_id, profiler in jr_regularity_checker.items():
            if profiler.is_inactive(packet_date):
                to_delete.append(device_id)
        for device_id in to_delete:
            del jr_regularity_checker[device_id]

        last_gc = dt.datetime.now()
    except Exception as exc:
        log.error(f"Error trying to collect garbage: {exc}")
