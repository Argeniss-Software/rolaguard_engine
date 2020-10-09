from collections import defaultdict
import logging as log

from utils.AlertGenerator import emit_alert
from db.Models import  DeviceCounters, CounterType



class CheckRetransmissions():
    def __init__(self):
        # Dict structure that stores device ids as keys and estimated number of retransmissions as values.
        # Also, it stores the date in which the last update for this value has been made, to be used
        # in garbage collection
        # Works like a cached version of retransmission counters stored in database (device_counters table)
        self.devices_retransmissions = defaultdict(lambda: {})
        self.last_gc = None

    def __call__(self, packet, device_session, device, gateway, policy_manager):
        if not self.last_gc: self.last_gc = packet.date
        if (packet.date - self.last_gc).seconds > 3600: # Garbage collect every hour
            self.garbage_collection(today = packet.date) 
        
        if packet.is_retransmission:
            # Initialize dict entry if it not exists, increment it otherwise
            if device.id not in self.devices_retransmissions:
                stored_retransmissions = DeviceCounters.get_device_counter(
                    device_id=device.id,
                    packet_date=packet.date,
                    counter_type=CounterType.RETRANSMISSIONS,
                    window=policy_manager.get_parameters("LAF-103")["time_window"]
                )

                self.devices_retransmissions[device.id]["retransmissions"] = stored_retransmissions
            else:
                self.devices_retransmissions[device.id]["retransmissions"] += 1
        
            cached_retransmissions = self.devices_retransmissions[device.id]["retransmissions"]
            max_retransmissions = policy_manager.get_parameters("LAF-103")["max_retransmissions"]
            if cached_retransmissions > max_retransmissions:
                # Cached retransmission counter was greater than allowed, look in database
                stored_retransmissions = DeviceCounters.get_device_counter(
                    device_id=device.id,
                    packet_date=packet.date,
                    counter_type=CounterType.RETRANSMISSIONS,
                    window=policy_manager.get_parameters("LAF-103")["time_window"]
                )
        
                # Check alert LAF-103
                if(
                    stored_retransmissions > max_retransmissions and \
                    policy_manager.is_enabled("LAF-103")
                ):
                    emit_alert(
                        alert_type="LAF-103",
                        packet=packet,
                        device=device,
                        device_session=device_session,
                        gateway=gateway,
                        retransmissions=stored_retransmissions
                    )
                
                # Update in-memory structure
                cached_retransmissions = stored_retransmissions
                self.devices_retransmissions[device.id]["retransmissions"] = cached_retransmissions

            self.devices_retransmissions[device.id]["last_updated"] = packet.date

    def garbage_collection(self, today):
        todel = [k for k, v in self.devices_retransmissions.items() if (today - v['last_updated']).seconds > (24 * 3600)]
        for k in todel: del self.devices_retransmissions[k]
        self.last_gc = today
