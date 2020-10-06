from collections import defaultdict
import logging as log

from utils.AlertGenerator import emit_alert
from db.Models import DataCollector, Quarantine, AlertType



class ABPDetector():
    def __init__(self):
        self.last_packet = defaultdict(lambda: {})

    def __call__(self, packet, device_session, device, gateway, policy):
        if (
            device is None or
            gateway is None or
            packet.f_count is None
        ): return

        if device.is_otaa: return # It's already detected as OTAA

        if (
            packet.m_type in ["JoinRequest", "JoinAccept"] or
            (
                packet.dev_addr is not None and
                self.last_packet["dev_addr"] != packet.dev_addr
            )
        ): # This indicates that the device is OTAA
            res_comment = "The device has sent a join request"
            issue_solved = Quarantine.remove_from_quarantine(
                "LAF-006",
                device_id = device.id,
                device_session_id = device_session.id,
                data_collector_id = packet.data_collector_id,
                res_reason_id = 3,
                res_comment = res_comment
                )
            if issue_solved:
                emit_alert(
                    "LAF-600",
                    packet,
                    device = device,
                    alert_solved_type = "LAF-006",
                    alert_solved = AlertType.find_one_by_code("LAF-006").name,
                    resolution_reason = res_comment
                )
            device.is_otaa = True
            return

        if packet.m_type in ["UnconfirmedDataUp", "ConfirmedDataUp"] and packet.dev_addr is not None:
            # Used to identify a "connection" to check. Here for connection we are 
            # talking about the flow of packets between a gateway and a device in
            # in the context of a stablished device_session.
            lpacket_uid = (device.id, gateway.id)

            if (
                lpacket_uid in self.last_packet and
                policy.is_enabled("LAF-006") and
                packet.f_count == 0 and
                self.last_packet[lpacket_uid]["f_count"] > 0 and
                self.last_packet[lpacket_uid]["dev_addr"] == packet.dev_addr
                ) :
                    emit_alert(
                        "LAF-006", packet, device=device,
                        device_session=device_session,
                        gateway=gateway,
                        counter = self.last_packet[lpacket_uid]["f_count"],
                        new_counter = packet.f_count
                        )
                    device.is_otaa = False

            # For each "connection" (see definition in previous comment), we save
            # the counter and dev_addr.
            self.last_packet[lpacket_uid] = {
                'f_count' : packet.f_count,
                'dev_addr' : packet.dev_addr
            }

