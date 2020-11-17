import datetime, json, logging 
from db.Models import Alert, Issue, Gateway, Device, \
    DeviceSession, AlertType, DataCollector, Packet, DATE_FORMAT
from mq.AlertEvent import emit_alert_event


alert_blocked_by = {
    "LAF-002" : ["LAF-002"],            # Devices sharing the same DevAddr
    "LAF-006" : ["LAF-006"],            # Possible ABP device
    "LAF-007" : ["LAF-007"],            # Possible duplicated sessions 
    "LAF-009" : ["LAF-009"],            # Easy to guess key
    "LAF-010" : ["LAF-010"],            # Gateway changed location
    "LAF-011" : ["LAF-011"],            # Device not regenerating session
    "LAF-100" : ["LAF-100"],            # Device signal intensity below threshold
    "LAF-103" : ["LAF-103"],            # Too many retransmissions by device
    "LAF-102" : ["LAF-102"],            # Device signal to noise ratio below threshold
    "LAF-101" : ["LAF-101"],            # Device losing many packets
    "LAF-404" : ["LAF-404"],            # Device failed to join
    "LAF-501" : ["LAF-501", "LAF-404"], # Anomaly in Join Requests frequency -> Device failed to join 
}

gateway_alerts = ["LAF-010", "LAF-402", "LAF-403"] # Gateway changed location, New gateway found, Gateway connection lost

def emit_alert(alert_type, packet, device=None, device_session=None, gateway=None, device_auth_id=None, **custom_parameters):
    try:
        if gateway is None:
            gateway = Gateway.find_with(gw_hex_id = packet.gateway, data_collector_id = packet.data_collector_id)
        if device is None:
            device = Device.find_with(dev_eui=packet.dev_eui, data_collector_id=packet.data_collector_id)
        if device_session is None and gateway:
            device_session = DeviceSession.find_with(dev_addr=packet.dev_addr, data_collector_id=packet.data_collector_id)
        if device is None and device_session and device_session.device_id:
            device = Device.get(device_session.device_id)
    except Exception as exc:
        logging.error(f"Error guessing device/gateway/session to emit alert: {exc}")
    try:
        now = datetime.datetime.now().strftime(DATE_FORMAT)
        parameters = {}
        parameters['packet_id'] = packet.id
        parameters['packet_date'] = packet.date.strftime(DATE_FORMAT)
        parameters['packet_data'] = packet.to_json()
        parameters['created_at'] = now
        parameters['dev_eui'] = device.dev_eui if device and device.dev_eui else None
        parameters['dev_name'] = device.name if device and device.name else None
        parameters['dev_vendor'] = device.vendor if device and device.vendor else None
        parameters['dev_addr'] = device_session.dev_addr if device_session and device_session.dev_addr else None
        parameters['gateway'] = gateway.gw_hex_id if gateway and gateway.gw_hex_id else None
        parameters['gw_name'] = gateway.name if gateway and gateway.name else None
        parameters['gw_vendor'] = gateway.vendor if gateway and gateway.vendor else None

        parameters.update(custom_parameters)

        if 'prev_packet_id' in custom_parameters:
            prev_packet = Packet.find_one(custom_parameters['prev_packet_id'])
            if prev_packet:
                parameters['prev_packet_data'] = prev_packet.to_json()

        global alert_blocked_by
        blocked = False

        try:
            for blocking_issue in alert_blocked_by.get(alert_type, []):
                if Issue.has_the_issue(
                    issue_type=blocking_issue,
                    device_id=device.id if device else None,
                    gateway_id=gateway.id
                ):
                    blocked = True
                    break
        except:
            pass # We can't check if the issue exists, then, we let blocked=False
        
        alert = Alert(
            type = alert_type,
            device_id = device.id if device and device.id else None,
            device_session_id = device_session.id if device_session and device_session.id else None,
            gateway_id = gateway.id if gateway and gateway.id else None,
            device_auth_id = device_auth_id,
            data_collector_id = packet.data_collector_id,
            created_at = now,
            packet_id = packet.id,
            parameters= json.dumps(parameters),
            show = not blocked)
        alert.save()
  
        # ReportAlert.print_alert(alert)

        if not blocked:
            params = {
                'data_collector_id': packet.data_collector_id,
                'organization_id': packet.organization_id,
                'alert_id': alert.id,
                'alert_type': alert.type,
            }
            emit_alert_event('NEW', params)

        is_an_issue = any([alert_type in l for l in alert_blocked_by.values()])
        try:
            if is_an_issue: Issue.upsert(packet.date, alert)
        except:
            pass # We can't upsert the issue, then, do nothing

    except Exception as exc:
        logging.error(f"Error trying to emit alert {alert_type}: {exc}")



def print_alert(alert):
    try: 
        alert_type = AlertType.find_one_by_code(alert.type)
        message= alert_type.code + '-' + alert_type.message
        dict_parameters= json.loads(alert.parameters)
        for param_name, param_value in dict_parameters.items():
            message= message.replace('{'+param_name+'}', str(param_value))
        message= message.replace('{'+'packet_id'+'}', str(alert.packet_id))
        message= message.replace('{'+'created_at'+'}', alert.created_at.strftime('%Y-%m-%d %H:%M'))
        collector= DataCollector.get(alert.data_collector_id)
        if collector:
            message= message.replace('{'+'collector.name'+'}', collector.name+' (ID '+str(collector.id)+')')
    except Exception as e:
        logging.error('Error printing alert: {0}'.format(e))
    logging.debug(message)