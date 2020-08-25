from collections import defaultdict

import pandas as pd
import numpy as np
from sklearn.preprocessing import OneHotEncoder, LabelEncoder, RobustScaler
from sklearn.svm import SVC

from db.Models import DeviceSession, Device


class DeviceIdentifier():
    # Join requests older than this to amount of seconds will be erased
    jr_expiration_time = 500
    # This number of samples of each device will be saved as maximum.
    max_samples_per_device = 16

    def __init__(self):
        self.jrs = defaultdict(lambda: [])
        self.last_gc = None

    def __call__(self, packet):
        self.gc(today = packet.date)
        if packet.m_type == "JoinRequest":
            try:
                # Tries to unlink the device with the session (if any)
                self.unlink_device_session(
                    dev_eui = packet.dev_eui,
                    dev_addr = packet.dev_addr,
                    data_collector_id = packet.data_collector_id
                )
            except:
                # If not linked, save the JR for future data packets
                self.save_jr(packet)

        elif packet.m_type == "JoinAccept":
            # One of the devices that have sent a JR in the lasts minutes probabily started a session
            jrs = self.jrs[packet.data_collector_id]
            for i, v in enumerate(jrs):
                v["ja_counter"] += 1
                jrs[i] = v

        else:
            if packet.dev_eui is None:
                try: # Try to get the dev_eui from the session
                    packet = self.get_deveui_from_session(packet)
                except: # Use ML to guess the device
                    packet = self.guess_deveui_from_jrs(packet)
            
        return packet


    def get_deveui_from_session(self, packet):
        """
        Looks for the device_session of the packet, from this object gets the
        device_id and from this finally gets the dev_eui. If one step fails raises an exception.
        """
        device_session = DeviceSession.find_with(
            dev_addr=packet.dev_addr,
            data_collector_id=packet.data_collector_id
            )
        device = Device.get(device_session.device_id)
        packet.dev_eui = device.dev_eui
        return packet


    def guess_deveui_from_jrs(self, packet):
        """
        Guess the dev_eui using the rssi, lsnr, gateway and machine learning.
        """
        if packet.f_count is None or packet.f_count > 4:
            # The data packet has a high counter, the JR was missed.
            return packet
        if packet.rssi is None or packet.lsnr is None:
            # Data needed to guess the device is missing.
            return packet
        join_request = [jr for jr in self.jrs[packet.data_collector_id] if jr["ja_counter"]>0]
        if len(join_request) < 1:
            # No JR registered in the last jr_expiration_time seconds.
            return packet

        ds = pd.DataFrame(self.jrs[packet.data_collector_id])

        deveui_encoder = LabelEncoder().fit(ds["dev_eui"])
        if len(deveui_encoder.classes_) < 2:
            # All JRs registered are from the same device, the packet must be from this device
            packet.dev_eui = deveui_encoder.classes_[0]
            return packet

        # Some data preprocessing
        gateway_encoder = OneHotEncoder().fit(np.array(ds["gateway"]).reshape(-1,1))
        numeric_scaler = RobustScaler().fit(ds[["rssi", "lsnr"]])
        label_encoder = LabelEncoder().fit(ds["dev_eui"])
        X = np.concatenate([
                gateway_encoder.transform(np.array(ds["gateway"]).reshape(-1,1)).toarray(),
                numeric_scaler.transform(ds[["rssi", "lsnr"]]),
            ], axis=1
        )
        Y = label_encoder.transform(ds["dev_eui"])
        
        # Trains a Support Vector Classifier with saved JRs.
        # The hiper-parameters were optimized with grid search.
        model = SVC(C=0.5, gamma=1.0, class_weight='balanced').fit(X, Y)
        
        # Makes a prediction over the actual packet.
        X = np.concatenate([
                gateway_encoder.transform(np.array(packet.gateway).reshape(1,1)).toarray(),
                numeric_scaler.transform(np.array([[packet.rssi, packet.lsnr]]))
            ], axis=1
        )
        predicted_dev_eui = label_encoder.inverse_transform(model.predict(X))[0]
        packet.dev_eui = predicted_dev_eui

        # All registered JRs from the predicted device are deleted, since it is probabily linked to a session.
        self.del_jrs_with(data_collector_id=packet.data_collector_id, dev_eui=predicted_dev_eui)
        try: # Tries to link the device and the session (could fail if they were not instantiated)
            self.link_device_session(
                dev_eui = predicted_dev_eui,
                dev_addr = packet.dev_addr,
                data_collector_id = packet.data_collector_id
            )
        except: pass
        return packet
        

    def link_device_session(self, dev_eui, dev_addr, data_collector_id):
        """
        Links the device_session and a device.
        """
        device = Device.find_with(
            dev_eui = dev_eui,
            data_collector_id = data_collector_id
        )
        device_session = DeviceSession.find_with(
            dev_addr = dev_addr,
            data_collector_id = data_collector_id
        )
        device_session.device_id = device.id
        

    def unlink_device_session(self, dev_eui, dev_addr, data_collector_id):
        """
        Unlinks the device and the device_session. If the device or session are 
        not instantiated yet, raises an exception. If no session is linked with
        the device, raises an exception.
        """
        device = Device.find_with(
            dev_eui = dev_eui,
            data_collector_id = data_collector_id
        )
        device_session = DeviceSession.find_with(
            device_id = device.id
        )
        device_session.device_id = None


    def save_jr(self, packet):
        """
        Saves some fields of the join requests for using when the device of a data
        packet must be guessed. If it haves many packets samples of that devies it
        deletes the older one.
        """
        n_dev_samples = len([p for p in self.jrs[packet.data_collector_id] if p["dev_eui"] == packet.dev_eui])
        if n_dev_samples > self.max_samples_per_device:
            for i, jr in enumerate(self.jrs[packet.data_collector_id]):
                if jr["dev_eui"] == packet.dev_eui:
                    break
            del self.jrs[packet.data_collector_id][i]
        self.jrs[packet.data_collector_id].append(
            {
                'dev_eui' : packet.dev_eui,
                'gateway' : packet.gateway,
                'rssi' : packet.rssi,
                'lsnr' : packet.lsnr,
                'date' : packet.date,
                'ja_counter' : 0
            }
        )

    
    def del_jrs_with(self, data_collector_id, dev_eui):
        """
        Deletes all join requests of the device with the dev_eui passed as parameter.
        """
        self.jrs[data_collector_id] = [
            jr for jr in self.jrs[data_collector_id] if jr['dev_eui'] != dev_eui
        ]


    def gc(self, today):
        """
        Deletes join requests older than jr_expiration_time seconds.
        """
        if self.last_gc is not None and (today - self.last_gc).seconds < self.jr_expiration_time: return
        todel = []
        for data_collector_id, jrs in self.jrs.items():
            self.jrs[data_collector_id] = [
                jr for jr in jrs if (today - jr["date"]).seconds < self.jr_expiration_time
                ]
            if len(self.jrs) == 0: todel.append(data_colelctor_id)
        for k in todel: del self.jrs[k]
        self.last_gc = today
        