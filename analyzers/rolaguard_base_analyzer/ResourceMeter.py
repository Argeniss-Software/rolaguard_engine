from db.Models import Device, Gateway, Quarantine, AlertType
from datetime import date
from utils import emit_alert
import logging

class ResourceMeter():
    # Moving average weight, must be between 0 and 1.
    # The greater the value is, the longer is the period averaged to calculate stats.
    maw = 0.5

    def __init__(self):
        self.device_stats = {}  # in memory dict that stores statistics for all the recognized devices
                                # indexed by device id
        self.gateway_stats = {}
        self.last_gc = date.today()

    def __call__(self, asset, packet, policy_manager):
        """
        Main function of the ResourceMeter. It calculates some stats for the assets
        and update the corresponding fields in the DB object (it doesn't commit the
        changes in the DB).
        Parameters:
        - asset: a gateway or device object
        - packet: the current packet processed
        """
        if not asset or not packet: return
        if not packet.f_count or not packet.date: return
        if packet.m_type in ["JoinRequest", "JoinAccept"]: return
        
        packet.uplink = packet.m_type in ["ConfirmedDataUp", "UnconfirmedDataUp"]

        if type(asset) == Device:
            if asset.id in self.device_stats: # entry for this device already created in device stats dict, update values
                if self.device_resource_usage(asset, packet, policy_manager):
                    if packet.uplink:
                        self.device_stats[asset.id]["last_fcount"] = packet.f_count
                    else:
                        self.device_stats[asset.id]["last_fcount_down"] = packet.f_count
                    self.device_stats[asset.id]["last_date"][packet.gateway] = packet.date
            else: # initialize device_stats dict entry with default values
                self.device_stats[asset.id] = {
                    "last_fcount" : packet.f_count if packet.uplink else None,
                    "last_fcount_down" : packet.f_count if not packet.uplink else None,
                    "last_date" : {},   # dict containing the gateway hex ids in which the device is connected as key, and most recent date of packet as values 
                    "rssi" : {},        # dict containing the gateway hex ids in which the device is connected as key, and rssi numbers as values 
                    "lsnr" : {}         # dict containing the gateway hex ids in which the device is connected as key, and lsnr numbers as values 
                }
                if packet.rssi is not None:
                    self.device_stats[asset.id]["rssi"][packet.gateway] = packet.rssi
                if packet.lsnr is not None:
                    self.device_stats[asset.id]["lsnr"][packet.gateway] = packet.lsnr
                if packet.gateway:
                    self.device_stats[asset.id]["last_date"][packet.gateway] = packet.date
        if type(asset) == Gateway:
            if asset.id in self.gateway_stats:
                self.gateway_resource_usage(asset, packet)
            self.gateway_stats[asset.id] = {
                "last_fcount" : packet.f_count,
                "last_date" : packet.date
            }


    def device_resource_usage(self, device, packet, policy_manager):
        if packet.uplink and packet.f_count == self.device_stats[device.id]["last_fcount"]: 
            return # Repeated uplink packet
        if not packet.uplink and packet.f_count == self.device_stats[device.id]["last_fcount_down"]: 
            return # Repeated downlink packet

        device.npackets_up += 1 if packet.uplink else 0
        device.npackets_down += 1 if not packet.uplink else 0

        if packet.uplink and self.device_stats[device.id]["last_fcount"]:
            device.last_activity = packet.date

            # If device is reconnecting, then resolve every "not transmitting"
            # issue for this device, with reason_id 0 (problem solved automatically)
            if not device.connected:
                issues = Quarantine.find_open_by_type_dev_coll(alert_type='LAF-401', device_id=device.id, returnAll=True)
                for issue in issues:
                    issue.resolve(
                        reason_id=0,
                        comment="The device has transmitted again",
                        commit=False
                    )
                    emit_alert(
                        "LAF-600",
                        packet,
                        device = device,
                        alert_solved_type = "LAF-401",
                        alert_solved = AlertType.find_one_by_code("LAF-401").name,
                        resolution_reason = "The device has transmitted again"
                    )

            device.connected = True

            last_fcount = self.device_stats[device.id]["last_fcount"]
            count_diff = int(packet.f_count - last_fcount) % (2**16)

            # The counter changed a lot, probably the session was restarted
            if count_diff > 64 or count_diff < 1:
                del self.device_stats[device.id]
                return False

            # Update activity_freq (which is the time between packets)
            most_recent_date = (max(self.device_stats[device.id]["last_date"].values())) if self.device_stats[device.id].get("last_date") else packet.date 
            time_diff = (packet.date - most_recent_date).seconds / count_diff
            if device.activity_freq:
                device.activity_freq = self.maw * device.activity_freq + (1-self.maw) * time_diff
            else:
                device.activity_freq = time_diff

            # Update the mean number of packets lost
            if device.npackets_lost:
                device.npackets_lost = self.maw * device.npackets_lost + (1-self.maw) * (count_diff-1)
            else:
                device.npackets_lost = count_diff-1

            # Update the max (from all the gateways) rssi of the device
            if packet.rssi is not None:
                if packet.gateway in self.device_stats[device.id]["rssi"]:
                    self.device_stats[device.id]["rssi"][packet.gateway] = \
                        self.maw *  self.device_stats[device.id]["rssi"][packet.gateway] + \
                        (1 - self.maw) * packet.rssi
                else:
                    self.device_stats[device.id]["rssi"][packet.gateway] = packet.rssi

            try:
                device.max_rssi = max(self.device_stats[device.id]["rssi"].values())
            except: pass

            # Update the max lsnr value of the device, considering all the gateways
            if packet.lsnr is not None:
                if packet.gateway in self.device_stats[device.id]["lsnr"]:
                    self.device_stats[device.id]["lsnr"][packet.gateway] = \
                        self.maw *  self.device_stats[device.id]["lsnr"][packet.gateway] + \
                        (1 - self.maw) * packet.lsnr
                else:
                    self.device_stats[device.id]["lsnr"][packet.gateway] = packet.lsnr

            try:
                device.max_lsnr = max(self.device_stats[device.id]["lsnr"].values())
            except: pass

            # Delete gateways that are not listening to this device for
            # more than 1/disconnection_sensitivity times the device frequency
            current_gw = set([packet.gateway])
            other_gws = set(self.device_stats[device.id]["last_date"].keys())
            gws_to_check = other_gws - current_gw
            gws_to_del = []
            disconnection_sensitivity = 1/policy_manager.get_parameters("LAF-401").get("disconnection_sensitivity")

            for gw_to_check in list(gws_to_check):
                if self.device_stats[device.id]["last_date"].get(gw_to_check) and\
                    (packet.date - self.device_stats[device.id]["last_date"].get(gw_to_check)).seconds >\
                    disconnection_sensitivity * device.activity_freq:

                    gws_to_del.append(gw_to_check)

            for gw_to_del in gws_to_del:
                self.device_stats[device.id]["last_date"].pop(gw_to_del, None)
                self.device_stats[device.id]["rssi"].pop(gw_to_del, None)
                self.device_stats[device.id]["lsnr"].pop(gw_to_del, None)

            # Update number of gateways that are listening to the device 
            rssi_gw = set(self.device_stats.get(device.id).get("rssi").keys())
            lsnr_gw = set(self.device_stats.get(device.id).get("lsnr").keys())
            device.ngateways_connected_to = len(list((rssi_gw | lsnr_gw))) 

            # Update size of payload
            device.payload_size = len(packet.data)
            
        return True


    def gateway_resource_usage(self, gateway, packet):
        gateway.npackets_up += 1 if packet.uplink else 0
        gateway.npackets_down += 1 if not packet.uplink else 0
        gateway.last_activity = packet.date

        # If gateway is reconnecting, then resolve every "not transmitting"
        # issue for this gateway, with reason_id 0 (problem solved automatically)
        if not gateway.connected:
            issues = Quarantine.find_open_by_type_dev_coll(alert_type='LAF-403', gateway_id=gateway.id, returnAll=True)
            for issue in issues:
                issue.resolve(
                    reason_id=0,
                    comment="The gateway has transmitted again",
                    commit=False
                )
                emit_alert(
                    "LAF-600",
                    packet,
                    gateway = gateway,
                    alert_solved_type = "LAF-403",
                    alert_solved = AlertType.find_one_by_code("LAF-403").name,
                    resolution_reason = "The gateway has transmitted again"
                )

        gateway.connected = True

        # Update activity_freq (which is the time between packets)
        time_diff = (packet.date - self.gateway_stats[gateway.id]["last_date"]).seconds
        if gateway.activity_freq:
            gateway.activity_freq = self.maw * gateway.activity_freq + (1-self.maw) * time_diff
        else:
            gateway.activity_freq = time_diff

    def gc(self, today):
        """
        This function deletes the stats from assets that hasn't send a packet in
        the last 30 days. This data is no longer used since the assets are probably 
        disconnected. This way we prevent filling the RAM memory of the node. 
        The function doesn't do anything if the last gc was run less than an hour ago,
        therefore, it can be called for each packet without a hit in performance.
        Parameter:
        - today: date of the packet thats being procesed.
        """
        if (date.today() - self.last_gc).seconds > 3600:
            todel = [k for k, v in self.device_stats.items() if (today - v['last_date']).days > 30]
            for k in todel: del self.device_stats[k]
            todel = [k for k, v in self.gateway_stats.items() if (today - v['last_date']).days > 30]
            for k in todel: del self.gateway_stats[k]
            self.last_gc = date.today()
            

        