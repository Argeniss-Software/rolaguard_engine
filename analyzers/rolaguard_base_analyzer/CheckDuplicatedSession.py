from collections import defaultdict
import logging as log

from utils.AlertGenerator import emit_alert
from db.Models import DataCollector



class CheckDuplicatedSession():
    def __init__(self):
        self.last_packet = defaultdict(lambda: {})
        self.last_gc = None


    def __call__(self, packet, device_session, device, gateway, policy):
        if self.last_gc is None: self.last_gc = packet.date
        if (packet.date - self.last_gc).seconds > 3600: self.garbage_collection(today = packet.date)
        if (
            packet.m_type not in ["UnconfirmedDataUp", "ConfirmedDataUp"] or
            device_session is None or
            gateway is None or
            packet.f_count is None
        ): return # Do nothing, ignore the packet

        # Used to identify a "connection" to check. Here for connection we are 
        # talking about the flow of packets between a gateway and a device in
        # in the context of a stablished device_session.
        lpacket_uid = (device_session.id, gateway.id)

        if (
            lpacket_uid in self.last_packet and
            policy.is_enabled("LAF-007") and
            self.is_session_duplicated(
                counter = packet.f_count,
                prev_counter = self.last_packet[lpacket_uid]["f_count"],
                mic = packet.mic,
                prev_mic = self.last_packet[lpacket_uid]["mic"],
                date = packet.date,
                prev_date = self.last_packet[lpacket_uid]['date'],
                ) and
            not DataCollector.get(packet.data_collector_id).is_ttn()
            ) :
                emit_alert(
                    "LAF-007", packet, device=device,
                    device_session=device_session, gateway=gateway,
                    counter=device_session.up_link_counter,
                    new_counter=packet.f_count,
                    prev_packet_id=device_session.last_packet_id
                    )

        # For each "connection" (see definition in previous comment), we save
        # the counter, mic and date.
        self.last_packet[lpacket_uid] = {
            'f_count' : packet.f_count,
            'mic' : packet.mic,
            'date' : packet.date,
        }


    def is_session_duplicated(self, counter, prev_counter, mic, prev_mic, date, prev_date):
        """
        Check if the counter and mic of two consecutive packets indicates the 
        possible existance of a duplicated session.
        """
        if (
            (counter > 8 and prev_counter < 65528) and \
            (
                (counter < prev_counter) or \
                ((counter == prev_counter) and (mic != prev_mic) and (date - prev_date).seconds > 30)
            )
        ): return True
        else: return False


    def garbage_collection(self, today):
        todel = [k for k, v in self.last_packet.items() if (today - v['date']).seconds > (24 * 3600)]
        for k in todel: del self.last_packet[k]
        self.last_gc = today
