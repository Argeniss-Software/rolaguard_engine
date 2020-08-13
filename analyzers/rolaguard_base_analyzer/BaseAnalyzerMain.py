import re, datetime, os, sys, base64, json, logging, math, datetime as dt, logging as log
from db.Models import DevNonce, Gateway, Device, DeviceSession, GatewayToDevice, DataCollectorToDevice, \
    DataCollectorToDeviceSession, DataCollectorToGateway, Packet, DataCollector
from utils import emit_alert
from analyzers.rolaguard_base_analyzer.ResourceMeter import ResourceMeter
from utils import Chronometer


# TODO: delete unused mics to avoid fill up memory.
# Dict containing (device_session_id:last_uplink_mic). Here it will be saved last uplink messages' MIC 
last_uplink_mic = {}
resource_meter = ResourceMeter()

chrono = Chronometer(report_every=1000)

def process_packet(packet, policy):
    chrono.start("total")

    chrono.start("instantiation")
    ## Gateway instantiation
    gateway = Gateway.find_with(gw_hex_id = packet.gateway, data_collector_id = packet.data_collector_id)
    if gateway is None and packet.gateway:
        gateway = Gateway.create_from_packet(packet)
        gateway.save()
        DataCollectorToGateway.associate(packet.data_collector_id, gateway.id)
        emit_alert("LAF-402", packet, gateway = gateway)

    ## Session instantiation
    device_session = DeviceSession.find_with(dev_addr = packet.dev_addr, data_collector_id = packet.data_collector_id)
    if device_session is None and packet.dev_addr:
        device_session = DeviceSession.create_from_packet(packet)
        device_session.save()
        DataCollectorToDeviceSession.associate(packet.data_collector_id, device_session.id)

    ## Device instantiation
    device = Device.find_with(dev_eui = packet.dev_eui, data_collector_id = packet.data_collector_id)
    if device is None and packet.dev_eui:
        device = Device.create_from_packet(packet)
        device.save()
        DataCollectorToDevice.associate(packet.data_collector_id, device.id)
        if policy.is_enabled("LAF-400"):
            emit_alert("LAF-400", packet, device=device, gateway=gateway, device_session=device_session,
                        number_of_devices = DataCollector.number_of_devices(packet.data_collector_id))
    chrono.stop()

    ## Associations
    chrono.start("dev2sess")
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

    ## If the packet does not have a gateway, try to guess from the device
    if gateway is None and device:
        possible_gateways = GatewayToDevice.associated_with(device.id)
        if len(possible_gateways) == 1:
            gateway = Gateway.get(possible_gateways[0])

    ## If the packet does not have a dev_eui, try to guess from the device_session
    if device is None and device_session and device_session.device_id:
        device = Device.get(device_session.device_id)


    chrono.start("checks")
    ## Check alert LAF-400
    if device and not device.connected and policy.is_enabled("LAF-400"):
        emit_alert("LAF-400", packet, device=device, gateway=gateway,
                    number_of_devices = DataCollector.number_of_devices(packet.data_collector_id))

    ## Check alert LAF-402
    if gateway and not gateway.connected and policy.is_enabled("LAF-402"):
            emit_alert("LAF-402", packet, gateway = gateway)

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

    if packet.m_type == "JoinRequest":
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
                    
                    else:
                        if device_session.up_link_counter > 65500:
                            if policy.is_enabled("LAF-011"):
                                emit_alert("LAF-011", packet,
                                            device=device,
                                            device_session=device_session,
                                            gateway=gateway,
                                            counter=device_session.up_link_counter,
                                            new_counter=packet.f_count,
                                            prev_packet_id=device_session.last_packet_id)
                        else:
                            if policy.is_enabled("LAF-006"):
                                emit_alert("LAF-006", packet,
                                            device=device,
                                            device_session=device_session,
                                            gateway=gateway,
                                            counter=device_session.up_link_counter,
                                            new_counter=packet.f_count,
                                            prev_packet_id=device_session.last_packet_id)

                            if device:
                                if not device.is_otaa:
                                    device_session.may_be_abp = True
                                else:
                                    logging.warning("The device is marked as OTAA but reset counter without having joined."\
                                                    "Packet id %d"%(packet.id))

                    device_session.reset_counter += 1
        
        elif ( # Conditions to emit a LAF-007
            # The policy is enabled
            policy.is_enabled("LAF-007") and
            # Have the last uplink mic for this device session
            device_session.id in last_uplink_mic and
            (
                # Received a counter smaller than the expected
                (packet.f_count < device_session.up_link_counter) or
                # Or equal but with a different mic
                ((packet.f_count == device_session.up_link_counter) and (last_uplink_mic[device_session.id] != packet.mic))
            ) and
            # To avoid errors when the counter overflows
            (packet.f_count > 5 or device_session.up_link_counter < 65530)
            ) :
                emit_alert("LAF-007", packet, device=device, device_session=device_session, gateway=gateway,
                            counter=device_session.up_link_counter,
                            new_counter=packet.f_count,
                            prev_packet_id=device_session.last_packet_id)

        last_uplink_mic[device_session.id]= packet.mic

    chrono.stop()

    chrono.start("update")
    if gateway: gateway.update_state(packet)
    if device_session: device_session.update_state(packet)
    if device: device.update_state(packet)

    resource_meter(device, packet)
    resource_meter(gateway, packet)
    resource_meter.gc(packet.date)

    ## Check alert LAF-100
    if (
        device and device.max_rssi is not None and \
        device.max_rssi < policy.get_parameters("LAF-100")["minimum_rssi"]
    ):
        emit_alert(
            "LAF-100", packet,
            device = device,
            device_session = device_session,
            gateway = gateway,
            rssi = packet.rssi
            )

    ## Check alert LAF-101
    if (
        device and \
        device.activity_freq is not None and device.npackets_lost is not None and \
        device.npackets_lost > policy.get_parameters("LAF-101")["max_lost_packets"]
    ):
        emit_alert(
            "LAF-101", packet,
            device=device,
            device_session=device_session,
            gateway=gateway,
            packets_lost=count_diff
            )
    chrono.stop("total")
    chrono.lap()

            
