from collections import defaultdict
import logging as log

from utils.AlertGenerator import emit_alert
from db.Models import DataCollector, Quarantine, AlertType



class CheckSessionRegeneration():
    def __init__(self):
        self.last_packet = defaultdict(lambda: {})
        self.last_gc = None

    def __call__(self, packet, device_session, device, gateway, policy):
        if self.last_gc is None: self.last_gc = packet.date
        if (packet.date - self.last_gc).seconds > 3600: self.garbage_collection(today = packet.date)

        if (
            device is None or
            gateway is None or
            packet.f_count is None or
            not device.is_otaa
        ): return # Can't be done anything without these data or with an ABP device

        # Used to identify a "connection" to check. Here for connection we are 
        # talking about the flow of packets between a gateway and a device
        # in the context of a stablished device_session.
        lpacket_uid = (device.id, gateway.id)
        if lpacket_uid not in self.last_packet: # first packet for this device
            self.last_packet[lpacket_uid] = {
                'f_count' : packet.f_count,
                'dev_addr' : packet.dev_addr,
                'has_joined' : packet.m_type in ["JoinRequest", "JoinAccept"],
                'date' : packet.date
            }
            return


        if ( # The device has regenerated the session
            packet.m_type in ["JoinRequest", "JoinAccept"] or
            (
                packet.dev_addr is not None and
                self.last_packet[lpacket_uid]["dev_addr"] != packet.dev_addr
            )
        ):
            res_comment = "The device has regenerated the session"
            issue_solved = Quarantine.remove_from_quarantine(
                "LAF-011",
                device_id = device.id,
                data_collector_id = packet.data_collector_id,
                res_reason_id = 3,
                res_comment = res_comment
                )
            if issue_solved:
                emit_alert(
                    "LAF-600",
                    packet,
                    device = device,
                    alert_solved_type = "LAF-011",
                    alert_solved = AlertType.find_one_by_code("LAF-011").name,
                    resolution_reason = res_comment
                )
            self.last_packet[lpacket_uid]["has_joined"] = True
            return

        if (
            packet.m_type not in ["UnconfirmedDataUp", "ConfirmedDataUp"] or
            packet.dev_addr is None
        ): return # The packet is not important for the rest of this check

        if ( # The counter has restarted
            lpacket_uid in self.last_packet and
            packet.f_count == 0 and
            self.last_packet[lpacket_uid]["f_count"] > 65500 
        ) :
            if ( # It hasn't regenerated the session
                not self.last_packet[lpacket_uid]["has_joined"] and
                policy.is_enabled("LAF-011")
                ) :
                    emit_alert("LAF-011", packet,
                                device=device,
                                device_session=device_session,
                                gateway=gateway,
                                counter=device_session.up_link_counter,
                                new_counter=packet.f_count,
                                prev_packet_id=device_session.last_packet_id)
            # After the restart the join request was "used", for another restart
            # we need another JR. Therefore, the flag is set to false.
            self.last_packet[lpacket_uid]["has_joined"] = False
        
        self.last_packet[lpacket_uid]['f_count'] = packet.f_count
        self.last_packet[lpacket_uid]['dev_addr']= packet.dev_addr
        self.last_packet[lpacket_uid]['date']= packet.date


    def garbage_collection(self, today):
        todel = [k for k, v in self.last_packet.items() if (today - v['date']).seconds > (72 * 3600)]
        for k in todel: del self.last_packet[k]
        self.last_gc = today
