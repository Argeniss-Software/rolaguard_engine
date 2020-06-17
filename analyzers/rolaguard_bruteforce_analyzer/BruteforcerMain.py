import json, datetime, logging, os
from lorawanwrapper import LorawanWrapper 
from utils import emit_alert
from db.Models import Device, DeviceAuthData, PotentialAppKey, Quarantine


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

        # Before cracking with many different keys, try with a PotentialAppKey previously found. In case this key is valid, we are pretty sure that is the correct AppKey
        device_auth_obj = DeviceAuthData.find_one_by_device_id(device_obj.id)
        if device_auth_obj and extractMIC(device_auth_obj.join_request)!= packet.mic:
            pot_app_keys = PotentialAppKey.find_all_by_device_auth_id(device_auth_obj.id)

            if len(pot_app_keys) > 0:
                
                keys_to_test=list()
                
                for pot_app_key in pot_app_keys:
                    keys_to_test.append(bytes(pot_app_key.app_key_hex.rstrip().upper(), encoding='utf-8')) 

                keys_to_test = list(dict.fromkeys(keys_to_test))
                correct_app_keys = LorawanWrapper.testAppKeysWithJoinRequest(keys_to_test, packet.data, True).split()

                if len(correct_app_keys) > 1:
                    logging.warning("Found more than one possible keys for the device {0}. One of them should be the correct. Check it manually. Keys: {1}".format(packet.dev_eui, correct_app_keys))
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
                else:
                    emit_alert("LAF-600", packet, device=device_obj)
                    Quarantine.remove_from_quarantine("LAF-009",
                                                      device_id = device_obj.id,
                                                      device_session_id = None,
                                                      data_collector_id = packet.data_collector_id,
                                                      res_reason_id = 3,
                                                      res_comment = "Appkey modified")
        
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
        # Try checking with the keys dictionary and the keys generated on the fly
        today = datetime.datetime.now()
        device_auth_obj.created_at = device_auth_obj.created_at.replace(tzinfo=None)
        
        elapsed = today - device_auth_obj.created_at # Time in seconds
        
        if elapsed.seconds > 3600 * hours_betweeen_bruteforce_trials or never_bruteforced:
            
            result = LorawanWrapper.testAppKeysWithJoinRequest(keys, packet.data, dontGenerateKeys)

            # Update the last time it was broteforced
            device_auth_obj.created_at= datetime.datetime.now()

            # If potential keys found...
            if result != "":

                device_auth_obj.join_request_packet_id= packet.id
                device_auth_obj.join_request= packet.data

                # Split string possibly containing keys separated by spaces
                candidate_keys_array= result.split()

                for hex_key in candidate_keys_array:
                    try:
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
        else:
            logging.debug("Skipping JoinRequest for DevEUI {2}. Elapsed {0} hours of {1}".format(elapsed.seconds/3600, hours_betweeen_bruteforce_trials, device_obj.dev_eui ))
    
    elif packet.m_type == "JoinAccept" and packet.data is not None:

        last_seconds_date = packet.date - datetime.timedelta(seconds=5)

        try:
            organization_keys= PotentialAppKey.find_all_by_organization_id_after_datetime(packet.organization_id, last_seconds_date)

            # Return if no JR keys were found
            if len(organization_keys) == 0:
                return 

            keys_array= list()
            for pk in organization_keys:
                # Fetch keys in byte format. Needed by ctypes
                keys_array.append(bytes(pk.app_key_hex.rstrip().upper(), encoding='utf-8')) 

            # Remove possible duplicates in array
            keys_array = list(dict.fromkeys(keys_array))

            result = LorawanWrapper.testAppKeysWithJoinAccept(keys_array, packet.data, True)
        except Exception as es:
            logging.error(f"Error trying to bforce JA: {es}")

        if result != "":

            # Clean the key string
            result = result.rstrip().upper()
            
            for potential_key_obj in organization_keys:
                if potential_key_obj.app_key_hex.upper() == result:
                    device_auth_obj = DeviceAuthData.find_one_by_id(potential_key_obj.device_auth_data_id)
                    break
            
            if device_auth_obj is None:
                logging.error("Cracked a JoinAccept but no device_auth object found")
                return

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