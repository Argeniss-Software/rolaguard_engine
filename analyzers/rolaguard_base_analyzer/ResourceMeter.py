from db.Models import Device, Gateway
from datetime import date


class ResourceMeter():
    maw = 0.9 # Moving average weight

    def __init__(self):
        self.device_stats = {}
        self.gateway_stats = {}
        self.last_gc = date.today()

    def __call__(self, asset, packet):
        if not asset or not packet: return
        if not packet.f_count or not packet.date: return
        if packet.m_type in ["JoinRequest", "JoinAccept"]: return
        
        packet.uplink = packet.m_type in ["ConfirmedDataUp", "UnconfirmedDataUp"]

        if type(asset) == Device:
            if asset.id in self.device_stats:
                self.measure_device_stats(asset, packet)
                if packet.uplink:
                    self.device_stats[asset.id]["last_fcount"] = packet.f_count
                else:
                    self.device_stats[asset.id]["last_fcount_down"] = packet.f_count
                self.device_stats[asset.id]["last_date"] = packet.date
            else:
                self.device_stats[asset.id] = {
                    "last_fcount" : packet.f_count if packet.uplink else None,
                    "last_fcount_down" : packet.f_count if not packet.uplink else None,
                    "last_date" : packet.date,
                    "rssi" : {packet.gateway : packet.rssi}
                }
        if type(asset) == Gateway:
            if asset.id in self.gateway_stats:
                self.measure_gateway_stats(asset, packet)
            self.gateway_stats[asset.id] = {
                "last_fcount" : packet.f_count,
                "last_tmst" : packet.tmst,
                "last_date" : packet.date
            }


    def measure_device_stats(self, device, packet):
        if packet.uplink and packet.f_count == self.device_stats[device.id]["last_fcount"]: 
            return # Repeated uplink packet
        if not packet.uplink and packet.f_count == self.device_stats[device.id]["last_fcount_down"]: 
            return # Repeated downlink packet

        device.npackets_up += 1 if packet.uplink else 0
        device.npackets_down += 1 if not packet.uplink else 0

        if packet.uplink and self.device_stats[device.id]["last_fcount"]:
            device.last_activity = packet.date
            device.connected = True

            last_fcount = self.device_stats[device.id]["last_fcount"]
            count_diff = int(packet.f_count - last_fcount) % (2**16)

            # The counter changed a lot, probably the session was restarted
            if count_diff > 64 or count_diff < 0:
                del self.device_stats[device.id]
                return

            time_diff = (packet.date - self.device_stats[device.id]["last_date"]).seconds / count_diff

            if device.activity_freq:
                device.activity_freq = self.maw * device.activity_freq + (1-self.maw) * time_diff
            else:
                device.activity_freq = time_diff

            if device.npackets_lost:
                device.npackets_lost = self.maw * device.npackets_lost + (1-self.maw) * (count_diff-1)
            else:
                device.npackets_lost = count_diff-1
            
            if packet.gateway in self.device_stats[device.id]["rssi"]:
                self.device_stats[device.id]["rssi"][packet.gateway] = \
                    self.maw *  self.device_stats[device.id]["rssi"][packet.gateway] + \
                    (1 - self.maw) * packet.rssi
            else:
                self.device_stats[device.id]["rssi"][packet.gateway] = packet.rssi
            device.max_rssi = max(self.device_stats[device.id]["rssi"].values())


    def measure_gateway_stats(self, gateway, packet):
        gateway.npackets_up += 1 if packet.uplink else 0
        gateway.npackets_down += 1 if not packet.uplink else 0
        gateway.last_activity = packet.date
        gateway.connected = True

        last_tmst = self.gateway_stats[gateway.id]["last_tmst"]
        time_diff = (int(packet.tmst - last_tmst) % (2**32)) / 1e9

        if gateway.activity_freq:
            gateway.activity_freq = self.maw * gateway.activity_freq + (1-self.maw) * time_diff
        else:
            gateway.activity_freq = time_diff

    def gc(self, today):
        if (date.today() - self.last_gc).seconds > 3600:
            todel = [k for k, v in self.device_stats.items() if (today - v['last_date']).days > 7]
            for k in todel: del self.device_stats[k]
            todel = [k for k, v in self.gateway_stats.items() if (today - v['last_date']).days > 7]
            for k in todel: del self.gateway_stats[k]
            self.last_gc = date.today()
            

        