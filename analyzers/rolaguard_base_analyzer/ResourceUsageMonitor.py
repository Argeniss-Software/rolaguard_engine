



class ResourceUsageMeter():
    maw = 0.5 # Moving average weight

    def __init__(self):
        self.session = {}

    def measure_usage(self, device, gateway, device_session, packet):
        if not device_session:
            return

        sess_id = device_session.id
        if sess_id not in self.session:
            self.register_packet(sess_id, packet)
            return

        count_diff = int(packet.f_count - self.session[sess_id]["last_fcount"]) % (2**16)
        if count_diff > 16:
            del self.session[sess_id]
            return

        if count_diff > 0:
            time_diff = (int(packet.tmst - self.last_tmst[device_session.id]) % (2**32)) / count_diff
            time_diff /= 1e6

        self.write_stats(device, packet.m_type, count_diff, time_diff)
        self.write_stats(gateway, packet.m_type, count_diff, time_diff)
        self.register_packet(device_session.id, packet)


    def calc_diffs(self, count, tmst):


    def save_stats(self, asset, m_type, count_diff, time_diff):
        if asset:
            asset.npackets_up += 1 if "Up" in m_type else 0
            asset.npackets_down += 1 if "Down" in m_type else 0
            asset.npackets_lost += count_diff if count_diff > 1 else 0
            asset.activity_freq = maw * asset.activity_freq + (1-maw) * time_diff


    def register_packet(self, session_id, packet):
        self.session[device_session.id] = {
                "last_fcount" : packet.f_count,
                "last_tmst" : packet.tmst,
                "last_seen" : packet.date
            }

    def gc(self, ):
        todel = []
        for k, v in self.session.items():
            if 