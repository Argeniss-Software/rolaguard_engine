from collections import defaultdict
import logging as log

from utils.AlertGenerator import emit_alert
from db.Models import DataCollector, Issue, AlertType



class ABPDetector():
    def __init__(self):
        self.last_packet = defaultdict(lambda: {})
        self.last_gc = None

    def __call__(self, packet, device_session, device, gateway, policy):
        if self.last_gc is None: self.last_gc = packet.date
        if (packet.date - self.last_gc).seconds > 3600: self.garbage_collection(today = packet.date)

        if (
            device is None or
            gateway is None or
            packet.f_count is None
        ): return # Can't be done anything without these data.

        if device.is_otaa: return # It's already detected as OTAA, nothing to do.

        # Used to identify a "connection" to check. Here for connection we are 
        # talking about the flow of packets between a gateway and a device in
        # in the context of a stablished device_session.
        lpacket_uid = (device.id, gateway.id)

        if ( # This indicates that the device is OTAA
            packet.m_type in ["JoinRequest", "JoinAccept"] or
            (
                packet.dev_addr is not None and
                lpacket_uid in self.last_packet and
                self.last_packet[lpacket_uid]["dev_addr"] != packet.dev_addr
            )
        ):
            res_comment = "The device has sent a join request"
            issue_solved = Issue.solve(
                resolution_reason=res_comment,
                date=packet.date,
                issue_type="LAF-006",
                device_id=device.id,
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
            if ( # This indicates that the device is ABP
                lpacket_uid in self.last_packet and
                policy.is_enabled("LAF-006") and
                packet.f_count == 0 and
                self.last_packet[lpacket_uid]["f_count"] > 0 and
                self.last_packet[lpacket_uid]["dev_addr"] == packet.dev_addr
                ) :
                    emit_alert(
                        "LAF-006", packet, device=device,
                        device_session=device_session,
                        gateway = gateway,
                        counter = self.last_packet[lpacket_uid]["f_count"],
                        new_counter = packet.f_count
                        )
                    device.is_otaa = False

            # For each "connection" (see definition in previous comment), we save
            # the counter and dev_addr.
            self.last_packet[lpacket_uid] = {
                'f_count' : packet.f_count,
                'dev_addr' : packet.dev_addr,
                'date' : packet.date
            }


    def garbage_collection(self, today):
        todel = [k for k, v in self.last_packet.items() if (today - v['date']).seconds > (24 * 3600)]
        for k in todel: del self.last_packet[k]
        self.last_gc = today
