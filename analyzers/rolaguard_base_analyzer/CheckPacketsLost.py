from collections import defaultdict
import logging as log

from utils.AlertGenerator import emit_alert
from db.Models import  DeviceCounters, CounterType



class CheckPacketsLost():
    def __init__(self):
        # Dict structure that stores device ids as keys and estimated number of lost packets as values.
        # Also, it stores the date in which the last update for this value has been made, to be used
        # in garbage collection
        # Works like a cached version of lost packets counter stored in database (device_counters table)
        self.devices_packets_lost = defaultdict(lambda: {})
        self.last_gc = None

    def __call__(self, packet, device_session, device, gateway, policy_manager):
        if not self.last_gc: self.last_gc = packet.date
        if (packet.date - self.last_gc).seconds > 3600: # Garbage collect every hour
            self.garbage_collection(today = packet.date) 

        if packet.npackets_lost_found > 0:
            # Initialize dict entry if it not exists, increment it otherwise
            if device.id not in self.devices_packets_lost:
                stored_packets_lost = DeviceCounters.get_device_counter(
                    device_id=device.id,
                    packet_date=packet.date,
                    counter_type=CounterType.PACKETS_LOST,
                    window=policy_manager.get_parameters("LAF-101")["time_window"]
                )

                self.devices_packets_lost[device.id]["packets_lost"] = stored_packets_lost
            else:
                self.devices_packets_lost[device.id]["packets_lost"] += packet.npackets_lost_found
        
            cached_packets_lost = self.devices_packets_lost[device.id]["packets_lost"]
            max_packets_lost = policy_manager.get_parameters("LAF-101")["max_packets_lost"]
            if cached_packets_lost > max_packets_lost:
                # Cached packets lost counter was greater than allowed, look in database
                stored_packets_lost = DeviceCounters.get_device_counter(
                    device_id=device.id,
                    packet_date=packet.date,
                    counter_type=CounterType.PACKETS_LOST,
                    window=policy_manager.get_parameters("LAF-101")["time_window"]
                )
        
                # Check alert LAF-101
                if(
                    stored_packets_lost > max_packets_lost and \
                    policy_manager.is_enabled("LAF-101")
                ):
                    emit_alert(
                        alert_type="LAF-101",
                        packet=packet,
                        device=device,
                        device_session=device_session,
                        gateway=gateway,
                        packets_lost=stored_packets_lost
                    )
                
                # Update in-memory structure
                cached_packets_lost = stored_packets_lost
                self.devices_packets_lost[device.id]["packets_lost"] = cached_packets_lost

            self.devices_packets_lost[device.id]["last_updated"] = packet.date

    def garbage_collection(self, today):
        todel = [k for k, v in self.devices_packets_lost.items() if (today - v['last_updated']).seconds > (24 * 3600)]
        for k in todel: del self.devices_packets_lost[k]
        self.last_gc = today
