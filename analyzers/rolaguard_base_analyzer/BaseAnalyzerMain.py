import logging as log
from collections import defaultdict
from db.Models import DevNonce, Gateway, Device, DeviceSession, GatewayToDevice, \
    Packet, DataCollector, Issue, AlertType
from utils import emit_alert
from db.TableCache import ObjectTableCache, AssociationTableCache
from analyzers.rolaguard_base_analyzer.ResourceMeter import ResourceMeter
from analyzers.rolaguard_base_analyzer.DeviceIdentifier import DeviceIdentifier
from analyzers.rolaguard_base_analyzer.CheckDuplicatedSession import CheckDuplicatedSession
from analyzers.rolaguard_base_analyzer.CheckSessionRegeneration import CheckSessionRegeneration
from analyzers.rolaguard_base_analyzer.ABPDetector import ABPDetector
from analyzers.rolaguard_base_analyzer.CheckRetransmissions import CheckRetransmissions
from analyzers.rolaguard_base_analyzer.CheckPacketsLost import CheckPacketsLost

from utils import Chronometer

# comment to disable caching
Gateway = ObjectTableCache(Gateway, max_cached_items=10000)
Device = ObjectTableCache(Device, max_cached_items=10000)
DeviceSession = ObjectTableCache(DeviceSession, max_cached_items=10000)
# GatewayToDevice = AssociationTableCache(GatewayToDevice, max_cached_items=10000)

# TODO: delete unused mics to avoid fill up memory.
# Dict containing (device_session_id:last_uplink_mic). Here it will be saved last uplink messages' MIC 
last_uplink_mic = {}
jr_counters = defaultdict(lambda: 0)

resource_meter = ResourceMeter()
device_identifier = DeviceIdentifier()
check_duplicated_session = CheckDuplicatedSession()
check_session_regeneration = CheckSessionRegeneration()
abp_detector = ABPDetector()
check_retransmissions = CheckRetransmissions()
check_packets_lost = CheckPacketsLost()

chrono = Chronometer(report_every=1000, chrono_name="base")

def process_packet(packet, policy):
    chrono.start("total")

    chrono.start("dev id")
    packet = device_identifier(packet)
    chrono.stop()

    chrono.start("search objs")
    gateway = Gateway.find_with(gw_hex_id = packet.gateway, data_collector_id = packet.data_collector_id)
    device = Device.find_with(dev_eui = packet.dev_eui, data_collector_id = packet.data_collector_id)
    device_session = DeviceSession.find_with(dev_addr = packet.dev_addr, data_collector_id = packet.data_collector_id)
    chrono.stop()

    chrono.start("instantiation")
    ## Gateway instantiation
    if gateway is None and packet.gateway:
        gateway = Gateway.create_from_packet(packet)
        gateway.save()
        if policy.is_enabled("LAF-402"):
            emit_alert("LAF-402", packet, gateway = gateway)

    ## Device instantiation
    if device is None and packet.dev_eui:
        device = Device.create_from_packet(packet)
        device.save()

    ## Session instantiation
    if device_session is None and packet.dev_addr:
        device_session = DeviceSession.create_from_packet(packet)
        device_session.save()
        
        if device:
            issue_solved = Issue.solve(
                resolution_reason="Device connected",
                date=packet.date,
                issue_type="LAF-404",
                device_id=device.id,
                )
            if issue_solved:
                emit_alert(
                    "LAF-600",
                    packet,
                    device = device,
                    alert_solved_type = "LAF-404",
                    alert_solved = AlertType.find_one_by_code("LAF-404").name,
                    resolution_reason = "Device connected"
                )


    ## Emit new device alert if it is the first data packet
    if device and device_session and device.pending_first_connection:
        device.pending_first_connection = False
        device.db_update()
        if policy.is_enabled("LAF-400"):
            emit_alert("LAF-400", packet, device=device, gateway=gateway, device_session=device_session,
                    number_of_devices = DataCollector.number_of_devices(packet.data_collector_id))

    chrono.stop()

    ## Associations
    chrono.start("gw2dev")
    if device and gateway:
        GatewayToDevice.associate(gateway.id, device.id)
    chrono.stop()

    ## Associate device with device_session
    chrono.start("dev2sess")
    if device and device_session:   
        # Check if this DeviceSession hadn't previously a Device (LAF-002)
        if device_session.device_id is not None and device.id != device_session.device_id and policy.is_enabled("LAF-002"):   
                conflict_device_obj = Device.get(device_session.device_id)
                emit_alert("LAF-002", packet, device=device, device_session=device_session, gateway=gateway,
                            old_dev_eui = conflict_device_obj.dev_eui,
                            new_dev_eui = device.dev_eui,
                            prev_packet_id = device_session.last_packet_id)
        device_session.device_id = device.id
    chrono.stop()

    chrono.start("guesses")
    ## If the packet does not have a gateway, try to guess from the device
    if gateway is None and device:
        possible_gateways = GatewayToDevice.associated_with(device.id)
        if len(possible_gateways) == 1:
            gateway = Gateway.get(possible_gateways[0])

    ## If the packet does not have a dev_eui, try to guess from the device_session
    if device is None and device_session and device_session.device_id:
        device = Device.get(device_session.device_id)
    chrono.stop()


    chrono.start("checks")
    ## Check alert

    ## LAF-404
    # The data_collector and dev_eui is used as UID to count JRs.
    if packet.dev_eui:
        if packet.m_type == 'JoinRequest':
            # If the previos packet was also a JR, then it is considered as failed
            if jr_counters[(packet.data_collector_id, packet.dev_eui)] > 0:
                packet.failed_jr_found = True
            jr_counters[(packet.data_collector_id, packet.dev_eui)] += 1
        else:
            jr_counters[(packet.data_collector_id, packet.dev_eui)] = 0

        if (
            policy.is_enabled("LAF-404") and
            jr_counters[(packet.data_collector_id, packet.dev_eui)] > policy.get_parameters("LAF-404")["max_join_request_fails"]
        ):
            if device:
                emit_alert("LAF-404", packet, device=device, gateway=gateway)
            else:
                log.warning(f"Device not found in DB when LAF-404 detected for device {packet.dev_eui} from data collector {packet.data_collector_id}")
    

    ## Check alert LAF-010
    if gateway and policy.is_enabled("LAF-010"):
        location_accuracy = policy.get_parameters("LAF-010")["location_accuracy"]
        location_change = gateway.distance_to(packet.latitude, packet.longitude)
        if location_change > location_accuracy:
            emit_alert("LAF-010", packet, gateway = gateway,
                        old_latitude = gateway.location_latitude,
                        old_longitude = gateway.location_longitude,
                        new_latitude = packet.latitude,
                        new_longitude = packet.longitude)

    if packet.m_type == "JoinRequest" and device:
        # Check if DevNonce is repeated and save it
        prev_packet_id = DevNonce.saveIfNotExists(packet.dev_nonce, device.id, packet.id) 
        if prev_packet_id and (device.has_joined or device.join_inferred):
            device.repeated_dev_nonce = True
        
            if policy.is_enabled("LAF-001"):
                emit_alert("LAF-001", packet, device=device, gateway=gateway,
                            dev_nonce=packet.dev_nonce,
                            prev_packet_id=prev_packet_id)
        elif not(prev_packet_id):
            device.has_joined=False
            device.join_inferred=False

    
    elif packet.m_type == "JoinAccept":
        # If we don't know the deveui, check if the last packet received in that datacollector is a JoinReq
        if packet.dev_eui is None:
            last_packet= Packet.find_previous_by_data_collector_and_dev_eui(packet.date, packet.data_collector_id, None)
            if last_packet is not None and last_packet.m_type == "JoinRequest":
                    device = Device.find_with(dev_eui = last_packet.dev_eui, data_collector_id = last_packet.organization_id)
                    if device is not None:
                        device.join_accept_counter+= 1
                        device.join_inferred= True


    is_uplink_packet = packet.m_type in ["UnconfirmedDataUp", "ConfirmedDataUp"]
    if device_session and is_uplink_packet and packet.f_count is not None:
        # Check counter
        if packet.f_count == 0:
            # Make sure we have processed at least one packet for this device in this run before firing the alarm
            if device_session.id in last_uplink_mic:
                # Skip if received the same counter as previous packet and mics are equal
                if not (packet.f_count == device_session.up_link_counter and last_uplink_mic[device_session.id] == packet.mic): 
                    
                    if device and device.has_joined:
                        # The counter = 0  is valid, then change the has_joined flag
                        device.has_joined = False

                    elif device and device.join_inferred:
                        # The counter = 0  is valid, then change the join_inferred flag
                        device.join_inferred = False
                    device_session.reset_counter += 1
        last_uplink_mic[device_session.id]= packet.mic

    # Check alert LAF-007
    check_duplicated_session(
        packet=packet,
        device_session=device_session,
        device=device,
        gateway=gateway,
        policy=policy
        )
    # CHeck alert LAF-011
    check_session_regeneration(
        packet=packet,
        device_session=device_session,
        device=device,
        gateway=gateway,
        policy=policy
        )
    # Check alert LAF-006
    abp_detector(
        packet=packet,
        device_session=device_session,
        device=device,
        gateway=gateway,
        policy=policy
        )
    # Check alert LAF-103
    check_retransmissions(
        packet=packet,
        device_session=device_session,
        device=device,
        gateway=gateway,
        policy_manager=policy
    )
    # Check alert LAF-101
    check_packets_lost(
        packet=packet,
        device_session=device_session,
        device=device,
        gateway=gateway,
        policy_manager=policy
    )

    chrono.stop()

    chrono.start("update")

    resource_meter(device, packet, policy)
    resource_meter(gateway, packet, policy)
    resource_meter.gc(packet.date)

    if gateway: gateway.update_state(packet)
    if device_session: device_session.update_state(packet)
    if device: device.update_state(packet)

    ## Check alert LAF-100
    if (
        device and device.max_rssi is not None and \
        policy.is_enabled("LAF-100") and \
        device.max_rssi < policy.get_parameters("LAF-100")["minimum_rssi"]
    ):
        emit_alert(
            "LAF-100", packet,
            device = device,
            device_session = device_session,
            gateway = gateway,
            rssi = device.max_rssi
            )

    ## Check alert LAF-102
    if(
        device and \
        device.max_lsnr is not None and \
        policy.is_enabled("LAF-102") and \
        device.max_lsnr < policy.get_parameters("LAF-102")["minimum_lsnr"]
    ):
        emit_alert(
            alert_type="LAF-102", 
            packet=packet,
            device=device,
            device_session=device_session,
            gateway=gateway,
            lsnr=device.max_lsnr
        )

    chrono.stop("update")
    chrono.stop("total")
    chrono.lap()
