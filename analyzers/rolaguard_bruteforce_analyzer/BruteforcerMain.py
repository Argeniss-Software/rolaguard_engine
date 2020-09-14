import json, datetime, logging, os
from analyzers.rolaguard_bruteforce_analyzer.lorawanwrapper import LorawanWrapper 
from utils import emit_alert
from db.Models import Device, DeviceAuthData, PotentialAppKey, Quarantine, AlertType, AppKey


device_auth_obj = None
dontGenerateKeys = None
keys = None
hours_betweeen_bruteforce_trials= None

def add(keyList, key):
    if len(keyList) == 0:
        return key
    elif key in keyList:
        return keyList
    else:
        return keyList + " "+ key

def process_packet(packet, policy):
    result = ""  
    key_tested = False
    global device_auth_obj  
    global dontGenerateKeys
    global keys
    global hours_betweeen_bruteforce_trials
    device_auth_obj = None
    
    if packet.m_type not in ("JoinRequest", "JoinAccept"): return
    if not policy.is_enabled("LAF-009"): return
    if packet.dev_eui is None: return

    if packet.m_type == "JoinRequest":
        
        # device_obj = ObjectInstantiator.get_or_error_device(packet)
        device_obj = Device.find_with(dev_eui=packet.dev_eui, data_collector_id=packet.data_collector_id)
        if not device_obj: return

        # Before cracking with many different keys, try with a PotentialAppKey previously found. In case this key is valid, we are pretty sure that is the correct AppKey
        device_auth_obj = DeviceAuthData.find_one_by_device_id(device_obj.id)
        if device_auth_obj and extractMIC(device_auth_obj.join_request)!= packet.mic:
            pot_app_keys = PotentialAppKey.find_all_by_device_auth_id(device_auth_obj.id)

            if len(pot_app_keys) > 0:
                
                keys_to_test=[bytes(pk.app_key_hex.rstrip().upper(), encoding='utf-8') for pk in pot_app_keys] 
                keys_to_test = list(dict.fromkeys(keys_to_test))

                correct_app_keys = LorawanWrapper.testAppKeysWithJoinRequest(
                    keys_to_test,
                    packet.data,
                    dontGenerateKeys = True).split()
                correct_app_keys = [ak.upper().rstrip() for ak in correct_app_keys]
                key_tested = True

                pk_to_remove = [pk.hex().upper() for pk in keys_to_test if pk.hex().upper() not in correct_app_keys]
                PotentialAppKey.delete_keys(device_auth_data_id=device_auth_obj.id, keys=pk_to_remove)

                if len(correct_app_keys) > 1:
                    logging.warning(f"Found more than one possible keys for the device {packet.dev_eui}." +
                                    f" One of them should be the correct. Check it manually. Keys: {correct_app_keys}")
                elif len(correct_app_keys) == 1:
                    # AppKey found!!
                    device_auth_obj.second_join_request_packet_id = packet.id
                    device_auth_obj.second_join_request = packet.data
                    device_auth_obj.app_key_hex = correct_app_keys[0]

                    emit_alert("LAF-009", packet,
                                device = device_obj,
                                device_auth_id=device_auth_obj.id,
                                app_key = correct_app_keys[0],
                                packet_id_1 = device_auth_obj.join_request_packet_id,
                                packet_type_1 = "JoinRequest",
                                packet_type_2 = "JoinRequest")
                    return
        
        # Check if the DeviceAuthData wasn't already generated
        never_bruteforced = False
        
        if device_auth_obj is None:
            never_bruteforced = True
            try:
                device_auth_obj = DeviceAuthData(
                    device_id = device_obj.id,
                    data_collector_id = packet.data_collector_id,
                    organization_id = packet.organization_id,
                    join_request = packet.data,
                    created_at = datetime.datetime.now(), 
                    join_request_packet_id = packet.id
                    )
                device_auth_obj.save()
            except Exception as exc:
                logging.error("Error trying to save DeviceAuthData at JoinRequest: {0}".format(exc))
        
        # Check when was the last time it was bruteforced and 
        # Try checking with the keys dictionary, the keys generated on the fly
        # and the keys uploaded by the corresponding organization
        today = datetime.datetime.now()
        device_auth_obj.created_at = device_auth_obj.created_at.replace(tzinfo=None)
        
        elapsed = today - device_auth_obj.created_at # Time in seconds
        
        if elapsed.seconds > 3600 * hours_betweeen_bruteforce_trials or never_bruteforced:
            
            result = LorawanWrapper.testAppKeysWithJoinRequest(keys, packet.data, dontGenerateKeys)
            organization_keys = [bytes(app_key.key.upper(), encoding='utf-8') for app_key in AppKey.get_with(organization_id = packet.organization_id)]
            result_org_keys = LorawanWrapper.testAppKeysWithJoinRequest(organization_keys, packet.data, dontGenerateKeys = True)
            if result_org_keys != "":
                result += " " + result_org_keys

            key_tested = True

            # Update the last time it was bruteforced
            device_auth_obj.created_at= datetime.datetime.now()

            # If potential keys found...
            if result != "":

                device_auth_obj.join_request_packet_id= packet.id
                device_auth_obj.join_request= packet.data

                # Split string possibly containing keys separated by spaces
                candidate_keys_array= set(result.split())

                for hex_key in candidate_keys_array:
                    try:
                        # Save the potential app key if it does not exists already in the DB
                        potential_key_obj = PotentialAppKey.get_by_device_auth_data_and_hex_app_key(
                            device_auth_data_id = device_auth_obj.id,
                            app_key_hex = hex_key.upper()
                        )
                        if not potential_key_obj:
                            potential_key_obj = PotentialAppKey(
                                app_key_hex = hex_key.upper(),
                                organization_id = packet.organization_id,
                                last_seen= packet.date,
                                packet_id= packet.id,
                                device_auth_data_id= device_auth_obj.id
                            )
                            potential_key_obj.save()
                    except Exception as exc:
                        logging.error("Error trying to save PotentialAppKey at JoinRequest: {0}".format(exc))           
    
    elif packet.m_type == "JoinAccept" and packet.data is not None:

        last_seconds_date = packet.date - datetime.timedelta(seconds=5)

        try:
            organization_keys= PotentialAppKey.find_all_by_organization_id_after_datetime(packet.organization_id, last_seconds_date)

            # Return if no JR keys were found
            if len(organization_keys) != 0:
                keys_array= list()
                for pk in organization_keys:
                    # Fetch keys in byte format. Needed by ctypes
                    keys_array.append(bytes(pk.app_key_hex.rstrip().upper(), encoding='utf-8')) 

                # Remove possible duplicates in array
                keys_array = list(dict.fromkeys(keys_array))

                result = LorawanWrapper.testAppKeysWithJoinAccept(keys_array, packet.data, True)
                key_tested = True
        except Exception as es:
            logging.error(f"Error trying to bforce JA: {es}")

        if result != "":

            # Clean the key string
            result = result.rstrip().upper()
            
            for potential_key_obj in organization_keys:
                if potential_key_obj.app_key_hex.upper() == result:
                    device_auth_obj = DeviceAuthData.find_one_by_id(potential_key_obj.device_auth_data_id)
                    break
            
            if device_auth_obj:
                #Add missing data
                device_auth_obj.join_accept = packet.data
                device_auth_obj.join_accept_packet_id = packet.id
                device_auth_obj.app_key_hex = result
                
                # Add session keys
                device_auth_obj= deriveSessionKeys(device_auth_obj, result)

                # Get the device to get dev_eui
                device_obj= Device.get(device_auth_obj.device_id)

                # Get DevAddr from JA packet
                dev_addr = LorawanWrapper.getDevAddr(result, packet.data)

                emit_alert("LAF-009", packet, 
                            device=device_obj, 
                            device_auth_id=device_auth_obj.id,
                            app_key = result,
                            dev_addr = dev_addr,
                            packet_id_1 = device_auth_obj.join_request_packet_id,
                            packet_type_1 = "JoinRequest",
                            packet_type_2 = "JoinAccept")
            else:
                logging.error("Cracked a JoinAccept but no device_auth object found")

    if key_tested and len(result)==0 and is_on_quarantine("LAF-009", packet, device=device_obj):
        res_comment = "The AppKey was modified"
        issue_solved = Quarantine.remove_from_quarantine(
            "LAF-009",
            device_id = device_obj.id,
            device_session_id = None,
            data_collector_id = packet.data_collector_id,
            res_reason_id = 3,
            res_comment = res_comment
            )
        if issue_solved:
            emit_alert(
                "LAF-600",
                packet,
                device = device_obj,
                alert_solved = AlertType.find_one_by_code("LAF-009").name,
                resolution_reason = res_comment
            )


def is_on_quarantine(alert_type, packet, device=None, device_session=None):
    """
    Inform if an alert/device or alert/device_session is on quarantine
    """
    if device is None and device_session is None:
        raise Exception("Must provide device or device_session")
    quarantine_row = Quarantine.find_open_by_type_dev_coll(alert_type,
                                                           device.id if device else None,
                                                           device_session.id if device_session else None,
                                                           packet.data_collector_id)
    return quarantine_row is not None 


def deriveSessionKeys(device_auth_obj, appKey):
    json_result = LorawanWrapper.generateSessionKeysFromJoins(device_auth_obj.join_request, device_auth_obj.join_accept, appKey)
    keys= json.loads(json_result)
    device_auth_obj.apps_key = keys["appSKey"]
    device_auth_obj.nwks_key = keys["nwkSKey"]
    return device_auth_obj


def init(keysPath, notGenerateKeys, hours):
    global keys
    keys = list()

    global hours_betweeen_bruteforce_trials
    hours_betweeen_bruteforce_trials = hours
    
    global dontGenerateKeys
    dontGenerateKeys = notGenerateKeys

    with open(keysPath) as f:
        for k in f:
            # Fetch keys in byte format. Needed by ctypes
            keys.append(bytes(k.rstrip().upper(), encoding='utf-8'))    

def extractMIC(b64_packet):
    stringPHY = LorawanWrapper.printPHYPayload(b64_packet)

    jsonPHY = json.loads(stringPHY)

    return jsonPHY['mic']      

# JoinReq: AppEUI - DevEUI - DevNonce
# JoinAccept: AppNonce - NetID - DevAddr

# NwkSKey = aes128_encrypt(AppKey, 0x01 | AppNonce | NetID | DevNonce | pad16)
# AppSKey = aes128_encrypt(AppKey, 0x02 | AppNonce | NetID | DevNonce | pad16)