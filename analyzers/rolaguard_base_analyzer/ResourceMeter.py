from db.Models import Device, Gateway


class ResourceMeter():
    maw = 0.9 # Moving average weight

    def __init__(self):
        self.device_stats = {}
        self.gateway_stats = {}

    def __call__(self, asset, packet):
        if not asset or not packet: return
        if not packet.f_count or not packet.date: return
        if packet.m_type in ["JoinRequest", "JoinAccept"]: return

        if type(asset) == Device:
            if asset.id in self.device_stats:
                self.measure_device_stats(asset, packet)
            self.device_stats[asset.id] = {
                "last_fcount" : packet.f_count,
                "last_date" : packet.date
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
        count_diff = time_diff = None
        uplink = packet.m_type in ["ConfirmedDataUp", "UnconfirmedDataUp"]
        # TODO: ignore repeated packets?
        device.npackets_up += 1 if uplink else 0
        device.npackets_down += 1 if not uplink else 0

        if not uplink: return
        
        device.last_activity = packet.date
        device.connected = True

        last_fcount = self.device_stats[device.id]["last_fcount"]
        count_diff = int(packet.f_count - last_fcount) % (2**16)

        if count_diff > 64 or count_diff < 0: # Session restarted
            del self.device_stats[device.id]
            return
        elif count_diff == 0: # Repeated packet
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


    def measure_gateway_stats(self, gateway, packet):
        uplink = packet.m_type in ["ConfirmedDataUp", "UnconfirmedDataUp"]
        gateway.npackets_up += 1 if uplink else 0
        gateway.npackets_down += 1 if not uplink else 0
        gateway.last_activity = packet.date
        gateway.connected = True

        last_tmst = self.gateway_stats[gateway.id]["last_tmst"]
        time_diff = (int(packet.tmst - last_tmst) % (2**32)) / 1e6

        if gateway.activity_freq:
            gateway.activity_freq = self.maw * gateway.activity_freq + (1-self.maw) * time_diff
        else:
            gateway.activity_freq = time_diff


    def gc(self, today):
        todel = [k for k, v in self.device_stats.items() if (today - v['last_date']).days > 7]
        for k in todel: del self.device_stats[k]
        todel = [k for k, v in self.gateway_stats.items() if (today - v['last_date']).days > 7]
        for k in todel: del self.gateway_stats[k]