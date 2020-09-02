import datetime, os, json, logging 
from db.Models import Alert, Quarantine, Gateway, GatewayToDevice, GatewayToDeviceSession, Device, \
    DeviceSession, AlertType, DataCollector, Packet
from mq.AlertEvent import emit_alert_event


alert_blocked_by = {
    "LAF-002" : ["LAF-002"],
    "LAF-006" : ["LAF-006"],
    "LAF-007" : ["LAF-007"], 
    "LAF-009" : ["LAF-009"],
    "LAF-100" : ["LAF-100"],
    "LAF-101" : ["LAF-101"],
    "LAF-404" : ["LAF-404"],
    "LAF-501" : ["LAF-501", "LAF-404"]
}


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
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        parameters = {}
        parameters['packet_id'] = packet.id
        parameters['packet_date'] = packet.date.strftime('%Y-%m-%d %H:%M:%S')
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

        issue = None
        blocked = False
        for blocking_issue in alert_blocked_by[alert_type]:
            issue = Quarantine.find_open_by_type_dev_coll(
                blocking_issue,
                device.id if device else None,
                device_session.id if device_session else None,
                packet.data_collector_id
            )
            if issue:
                blocked = True
                break
                                                        
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
        if is_an_issue:
            Quarantine.put_on_quarantine(alert=alert, quarantine_row=issue)

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
        collector= DataCollector.find_one(alert.data_collector_id)
        if collector:
            message= message.replace('{'+'collector.name'+'}', collector.name+' (ID '+str(collector.id)+')')
    except Exception as e:
        logging.error('Error printing alert: {0}'.format(e))
    logging.debug(message)