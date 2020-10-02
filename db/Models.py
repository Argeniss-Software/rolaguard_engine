import math
import json
import logging as log
from sqlalchemy import Column, DateTime, String, Integer, BigInteger, SmallInteger, Float, Boolean, Interval,\
                       ForeignKey, func, asc, desc, func, LargeBinary, or_, Enum as SQLEnum
from db import session, Base, engine
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import relationship
from enum import Enum
from datetime import datetime

BigIntegerType = BigInteger()
BigIntegerType = BigIntegerType.with_variant(postgresql.BIGINT(), 'postgresql')
BigIntegerType = BigIntegerType.with_variant(sqlite.INTEGER(), 'sqlite')
DATE_FORMAT = "%Y-%m-%d %H:%M:%S%z"

class AlertType(Base):
    __tablename__ = 'alert_type'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    code = Column(String(20), nullable=False, unique=True)
    name = Column(String(120), nullable=False)
    message = Column(String(4096), nullable=True) 
    risk = Column(String(20), nullable=False)
    description= Column(String(3000), nullable= False)
    parameters = Column(String(4096), nullable=True)
    technical_description= Column(String(3000), nullable= True)
    recommended_action= Column(String(3000), nullable= True)
    quarantine_timeout = Column(Integer, nullable=True, default=0)


    @classmethod
    def count(cls):
        return session.query(func.count(cls.id)).scalar()

    def save(self):
        session.add(self)
        session.flush()

    @classmethod
    def find_one_by_code(cls, code):
        return session.query(cls).filter(cls.code == code).first()


class Alert(Base):
    __tablename__ = 'alert'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    type = Column(String(20), ForeignKey("alert_type.code"), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=False)
    # device relationship. It may be null if we didn't get the dev_eui
    device_id = Column(BigInteger, ForeignKey("device.id"), nullable=True)
    # devicesession relationship. It may be null for some alerts, where we don't have a session yet (ex: join request)
    device_session_id = Column(BigInteger, ForeignKey("device_session.id"), nullable=True)
    gateway_id = Column(BigIntegerType, ForeignKey("gateway.id"), nullable=True)
    device_auth_id = Column(BigIntegerType, ForeignKey("device_auth_data.id"), nullable=True)
    data_collector_id = Column(BigIntegerType, ForeignKey("data_collector.id"), nullable=False)
    parameters = Column(String(4096), nullable=False)
    show = Column(Boolean, nullable=False, default=True)

    alert_type = relationship("AlertType", lazy="joined")

    @classmethod
    def find_organization_id(cls, alert_id):
        """
        returns the organization_id from the data collector associated to the alert
        :param alert_id: alert id
        :return: organization_id (big integer)
        """
        result = session.query(cls,DataCollector.organization_id).join(DataCollector).filter(alert_id==cls.id).first().organization_id
        return result

    @classmethod
    def find_by_organization_id_and_created_at(cls, organization_id, since, until):
        return session.query(cls).filter(cls.packet_id == Packet.id).filter(
            DataCollector.id == Packet.data_collector_id).filter(
            DataCollector.organization_id == organization_id).filter(cls.created_at > since,
                                                                     cls.created_at < until).all()

    def save(self):
        session.add(self)
        session.flush()
        session.commit()

    @classmethod
    def find_one(cls, id):
        return session.query(cls).filter(cls.id == id).first()


class Gateway(Base):
    __tablename__ = 'gateway'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    gw_hex_id = Column(String(16), nullable=False)
    name = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    location_latitude = Column(Float, nullable=True)
    location_longitude = Column(Float, nullable=True)
    data_collector_id = Column(BigIntegerType, ForeignKey("data_collector.id"), nullable=False)
    organization_id = Column(BigIntegerType, ForeignKey("organization.id"), nullable=False)

    connected = Column(Boolean, nullable=False, default=True)
    first_activity = Column(DateTime(timezone=True), nullable=True)
    last_activity = Column(DateTime(timezone=True), nullable=False)
    activity_freq = Column(Float, nullable=True)
    npackets_up = Column(Integer, nullable=False, default=0)
    npackets_down = Column(Integer, nullable=False, default=0)

    last_packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=True)

    @classmethod
    def create_from_packet(cls, packet):
        vendor = None
        if len(packet.gateway) == 16:
            vendor = DeviceVendorPrefix.get_vendor_from_dev_eui(packet.gateway)
        return Gateway(
            gw_hex_id = packet.gateway,
            name = packet.gw_name,
            vendor = vendor,
            data_collector_id = packet.data_collector_id,
            organization_id = packet.organization_id,
            connected = True,
            last_activity = packet.date,
            first_activity = packet.date
        )

    @classmethod
    def find_with(cls, gw_hex_id, data_collector_id):
        if gw_hex_id and data_collector_id:
            return session.query(Gateway).\
                filter(Gateway.gw_hex_id == gw_hex_id).\
                filter(Gateway.data_collector_id == data_collector_id).\
                first()
        else:
            return None

    @classmethod
    def get(cls, id):
        return session(cls).query(cls.id == id)

    def save(self):
        try:
            session.add(self)
            session.commit()
        except Exception as exc:
            log.error(f"Error creating gateway: {exc}")
        

    def update_state(self, packet):
        try:
            if packet.latitude and packet.longitude:
                self.location_latitude = packet.latitude
                self.location_longitude = packet.longitude
            self.last_packet_id = packet.id
        except Exception as exc:
            log.error(f"Error updating gateway {self.id}: {exc}")

    # The haversine formula determines the great-circle distance between two points on a sphere given their longitudes and latitudes.
    def distance_to(self, latitude, longitude):
        if latitude is None or longitude is None or (latitude==0 and longitude==0):
            return -1
        if self.location_latitude is None or self.location_longitude is None:
            return -1
        R = 6378.137 #Radius of earth in KM
        dLat = self.location_latitude * math.pi / 180 - latitude * math.pi / 180
        dLon = self.location_longitude * math.pi / 180 - longitude * math.pi / 180
        a = math.sin(dLat/2) * math.sin(dLat/2) + \
            math.cos(self.location_latitude * math.pi / 180) * math.cos(latitude * math.pi / 180) * math.sin(dLon/2) * math.sin(dLon/2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        d = R * c
        return d * 1000 #meters


class DataCollectorStatus(Enum):
    CONNECTED = 'CONNECTED'
    DISCONNECTED = 'DISCONNECTED'
    DISABLED = 'DISABLED'


class DataCollector(Base):
    __tablename__ = "data_collector"
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    data_collector_type_id = Column(BigIntegerType, ForeignKey("data_collector_type.id"), nullable=False)
    type = relationship("DataCollectorType", lazy="joined")
    policy = relationship("Policy", lazy="joined")
    name = Column(String(120), nullable=False)
    organization_id = Column(BigIntegerType, ForeignKey("organization.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    ip = Column(String(120), nullable=False)
    port = Column(String(120), nullable=False)
    user = Column(String(120), nullable=True)
    password = Column(String(120), nullable=False)
    ssl = Column(Boolean, nullable=False)
    organization_id = Column(BigInteger, ForeignKey("organization.id"), nullable=False)
    policy_id = Column(BigInteger, ForeignKey("policy.id"), nullable=False)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(SQLEnum(DataCollectorStatus))

    @classmethod
    def find_one_by_ip_port_and_dctype_id(cls, dctype_id, ip, port):
        return session.query(cls).filter(cls.ip == ip).filter(cls.data_collector_type_id == dctype_id).filter(
            cls.port == port).first()

    @classmethod
    def find_one_by_name_and_dctype_id(cls, dctype_id, name):
        return session.query(cls).filter(cls.data_collector_type_id == dctype_id, cls.name == name).first()

    @classmethod
    def get(cls, id):
        return session.query(cls).get(id)

    @classmethod
    def count(cls):
        return session.query(func.count(cls.id)).scalar()

    @classmethod
    def number_of_devices(cls, data_collector_id):
        ndev = session.query(Device.dev_eui).\
                filter(Device.connected).\
                filter(Device.data_collector_id == data_collector_id).\
                distinct().count()
        return ndev

    def is_ttn(self):
        return self.type.type == 'ttn_collector'

    def save(self):
        session.add(self)
        session.flush()
        commit()


class DataCollectorType(Base):
    __tablename__ = "data_collector_type"
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    type = Column(String(30), nullable=False, unique=True)
    name = Column(String(50), nullable=False)
    
    @classmethod
    def find_one_by_type(cls, type):
        return session.query(cls).filter(cls.type == type).first()

    @classmethod
    def find_type_by_id(cls, id):
        return session.query(cls).filter(cls.id == id).first().type

    def save(self):
        session.add(self)
        session.flush()


class Device(Base):
    __tablename__ = 'device'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    dev_eui = Column(String(16), nullable=False)
    name = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    app_name = Column(String, nullable=True)
    join_eui = Column(String(16), nullable=True)
    organization_id = Column(BigIntegerType, ForeignKey("organization.id"), nullable=False)
    data_collector_id = Column(BigInteger, ForeignKey("data_collector.id"), nullable=False)
    
    repeated_dev_nonce = Column(Boolean, nullable=True)
    join_request_counter = Column(Integer, nullable=False, default=0)
    join_accept_counter = Column(Integer, nullable=False, default=0)
    has_joined = Column(Boolean, nullable=True, default=False)
    join_inferred = Column(Boolean, nullable=True, default=False)
    is_otaa = Column(Boolean, nullable=True)
    last_packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=True)

    pending_first_connection = Column(Boolean, nullable=False, default=True)
    connected = Column(Boolean, nullable=False, default=True)
    first_activity = Column(DateTime(timezone=True), nullable=True)
    last_activity = Column(DateTime(timezone=True), nullable=True)
    activity_freq = Column(Float, nullable=True)
    activity_freq_variance = Column(Float, nullable=False, default=0)
    npackets_up = Column(Integer, nullable=False, default=0)
    npackets_down = Column(Integer, nullable=False, default=0)
    npackets_lost = Column(Float, nullable=False, default=0)
    max_rssi = Column(Float, nullable=True)
    max_lsnr = Column(Float, nullable=True)
    ngateways_connected_to = Column(Integer, nullable=False, default=0)
    payload_size = Column(Integer, nullable=True)

    last_packets_list = Column(String(4096), nullable=True, default='[]')

    MAX_PACKETS_LIST_SIZE = 200

    @classmethod
    def get(cls, id):
        return session.query(cls).filter(cls.id == id).first()

    @classmethod
    def create_from_packet(cls, packet):
        vendor = DeviceVendorPrefix.get_vendor_from_dev_eui(packet.dev_eui)
        uplink = packet.m_type in ["UnconfirmedDataUp", "ConfirmedDataUp", "JoinRequest"]
        return Device(
            dev_eui = packet.dev_eui,
            name = packet.dev_name,
            vendor = vendor,
            join_eui = packet.join_eui,
            organization_id = packet.organization_id,
            last_packet_id = packet.id,
            connected = "Up" in packet.m_type,
            app_name = packet.app_name,
            last_activity = packet.date,
            first_activity = packet.date if uplink else None,
            data_collector_id = packet.data_collector_id,
            pending_first_connection = True,
            last_packets_list = '[]'
            )

    @classmethod
    def find_with(cls, dev_eui, data_collector_id):
        if dev_eui and data_collector_id:
            return session.query(cls).\
                filter(Device.dev_eui == dev_eui).\
                filter(Device.data_collector_id == data_collector_id).first()
        else:
            return None

    def save(self):
        try:
            session.add(self)
            session.commit()
        except Exception as exc:
            log.error(f"Error creating device: {exc}")

    def db_update(cls):
        session.commit()
        
    def update_state(self, packet):
        try:
            if packet.join_eui:
                self.join_eui = packet.join_eui
            if packet.m_type == "JoinAccept":
                self.has_joined = True
                self.join_accept_counter += 1
            if packet.m_type == "JoinRequest":
                self.join_request_counter += 1
                self.is_otaa = True
            self.last_packet_id = packet.id
            if packet.m_type in ["UnconfirmedDataUp", "ConfirmedDataUp", "JoinRequest"]:
                packets_list = json.loads(self.last_packets_list)
                packets_list.append(packet.id)
                while len(packets_list) > self.MAX_PACKETS_LIST_SIZE:
                    packets_list.pop(0)
                self.last_packets_list = json.dumps(packets_list)
                if self.first_activity is None:
                    self.first_activity = packet.date
            DeviceCounters.upsert_counters(device = self, packet = packet)
        except Exception as exc:
            log.error(f"Error while updating device {self.dev_eui}: {exc}")


class CounterType(Enum):
    PACKETS_UP = 'PACKETS_UP'
    PACKETS_DOWN = 'PACKETS_DOWN'
    PACKETS_LOST = 'PACKETS_LOST'
    JOIN_REQUESTS = 'JOIN_REQUESTS'
    FAILED_JOIN_REQUESTS = 'FAILED_JOIN_REQUESTS'
    RETRANSMISSIONS = 'RETRANSMISSIONS'


class DeviceCounters(Base):
    __tablename__ = 'device_counters'
    device_id = Column(BigInteger, ForeignKey("device.id"), nullable=False, primary_key=True)
    counter_type = Column(SQLEnum(CounterType), nullable=False, primary_key=True)
    hour_of_day = Column(Integer, nullable=False, primary_key=True)
    value = Column(BigInteger, nullable=False, default=0)
    last_update = Column(DateTime(timezone=True), nullable=False)

    @classmethod
    def upsert_counters(cls, device, packet):
        if not packet.date or packet.is_repeated or packet.m_type == "JoinAccept":
            return

        if packet.m_type == "JoinRequest":
            cls.upsert_counter(device_id=device.id, packet_date=packet.date, counter_type=CounterType.JOIN_REQUESTS)
            if packet.failed_jr_found:
                cls.upsert_counter(device_id=device.id, packet_date=packet.date, counter_type=CounterType.FAILED_JOIN_REQUESTS)
            return
        
        if packet.uplink:
            cls.upsert_counter(device_id=device.id, packet_date=packet.date, counter_type=CounterType.PACKETS_UP)
            if packet.is_retransmission:
                cls.upsert_counter(device_id=device.id, packet_date=packet.date, counter_type=CounterType.RETRANSMISSIONS)
            if packet.npackets_lost_found > 0:
                cls.upsert_counter(device_id=device.id, packet_date=packet.date, counter_type=CounterType.PACKETS_LOST, delta=packet.npackets_lost_found)
        else:
            cls.upsert_counter(device_id=device.id, packet_date=packet.date, counter_type=CounterType.PACKETS_DOWN)
        return
    
    @classmethod
    def upsert_counter(cls, device_id, packet_date, counter_type, delta=1, commit=False):
        counters = session.query(cls).filter(
            cls.device_id == device_id,
            cls.counter_type == counter_type,
            cls.hour_of_day ==  packet_date.hour
        ).all()

        if len(counters) > 1:
            log.error(f"More than one counter found for device_id={device_id}, packet_date={packet_date}, counter_type={counter_type}")
            return

        curCounter = None
        if len(counters) == 1:
            curCounter = counters[0]

        # Insert if doesn't exist or update the counter
        if curCounter is None:
            session.add(DeviceCounters(
                device_id = device_id,
                counter_type = counter_type,
                hour_of_day = packet_date.hour,
                value = delta,
                last_update = packet_date
            ))
        else:
            if( # If the counter is outdated, then reset it
                packet_date.year != curCounter.last_update.year or \
                packet_date.month != curCounter.last_update.month or \
                packet_date.day != curCounter.last_update.day
            ):
                curCounter.value = 0

            curCounter.value += delta
            curCounter.last_update = packet_date

        if commit:
            session.commit()
        
        return


class GatewayCounters(Base):
    __tablename__ = 'gateway_counters'
    device_id = Column(BigInteger, ForeignKey("gateway.id"), nullable=False)
    counter_type = Column(SQLEnum(CounterType), nullable=False)
    hour_of_day = Column(Integer, nullable=False)
    value = Column(BigInteger, nullable=False, default=0)
    last_update = Column(DateTime(timezone=True), nullable=False)

    
class DeviceVendorPrefix(Base):
    __tablename__ = 'device_vendor_prefix'
    id = Column(BigIntegerType, primary_key=True)
    prefix = Column(String, nullable=False)
    vendor = Column(String, nullable=False)

    @classmethod
    def get_vendor_from_dev_eui(cls, dev_eui):
        row = session.query(cls).filter(cls.prefix == dev_eui[0:9].upper()).first()
        if not row:
            row = session.query(cls).filter(cls.prefix == dev_eui[0:7].upper()).first()
        if not row:
            row = session.query(cls).filter(cls.prefix == dev_eui[0:6].upper()).first()
        return row.vendor if row else None


class DevNonce(Base):
    __tablename__ = 'dev_nonce'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    dev_nonce = Column(Integer, nullable=True)
    device_id = Column(BigIntegerType, ForeignKey("device.id"), nullable=False)
    packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=False)

    def save(self):
        session.add(self)
        session.flush()

    @classmethod
    def saveIfNotExists(cls, dev_nonce, device_id, packet_id):
        existing_dev_nonces = session.query(DevNonce).\
            filter(DevNonce.device_id == device_id).\
            filter(DevNonce.dev_nonce == dev_nonce).first()
        if existing_dev_nonces:
            prev_packet_id = existing_dev_nonces.packet_id
            existing_dev_nonces.packet_id = packet_id
            return prev_packet_id
        else:
            DevNonce(
                dev_nonce=dev_nonce,
                device_id=device_id,
                packet_id=packet_id
            ).save()
            return None

    
class GatewayToDevice(Base):
    __tablename__ = 'gateway_to_device'
    gateway_id = Column(BigIntegerType, ForeignKey("gateway.id"), nullable=False, primary_key=True)
    device_id = Column(BigIntegerType, ForeignKey("device.id"), nullable=False, primary_key=True)

    @classmethod
    def associated_with(cls, device_id):
        gateway_ids = session.query(cls.gateway_id).filter(cls.device_id == device_id).all()
        return [id[0] for id in gateway_ids]

    @classmethod
    def associate(cls, gateway_id, device_id):
        try:
            row = session.query(GatewayToDevice).\
                filter(cls.gateway_id == gateway_id).\
                filter(cls.device_id == device_id).first()
            if row is None:
                row = GatewayToDevice(
                    gateway_id = gateway_id,
                    device_id = device_id
                )
                session.add(row)
                session.commit()
        except Exception as exc:
            session.rollback()
            log.error(f"Error trying to add GatewayToDevice: {exc}")

    @classmethod
    def delete(cls, gateway_id, device_id):
        try:
            row = session.query(GatewayToDevice).\
                filter(cls.gateway_id == gateway_id).\
                filter(cls.device_id == device_id).first()
            if row is None:
                raise Exception("Trying to erase a non existing row in GatewayToDevice")
            session.delete(row)
            session.commit()
        except Exception as exc:
            session.rollback()
            log.error(f"Couldn't delete row: {exc}")


class GatewayToDeviceSession(Base):
    __tablename__ = 'gateway_to_device_session'
    gateway_id = Column(BigIntegerType, ForeignKey("gateway.id"), nullable=False, primary_key=True)
    device_session_id = Column(BigIntegerType, ForeignKey("device_session.id"), nullable=False, primary_key=True)

    @classmethod
    def associated_with(cls, device_session_id):
        gateway_ids = session.query(cls.gateway_id).filter(cls.device_session_id == device_session_id).all()
        return [id[0] for id in gateway_ids]

    @classmethod
    def associate(cls, gateway_id, device_session_id):
        try:
            row = session.query(GatewayToDeviceSession).\
                filter(cls.gateway_id == gateway_id).\
                filter(cls.device_session_id == device_session_id).first()
            if row is None:
                row = GatewayToDeviceSession(
                    gateway_id = gateway_id,
                    device_session_id = device_session_id
                )
                session.add(row)
                session.commit()
        except Exception as exc:
            session.rollback()
            log.error(f"Error trying to add GatewayToDeviceSession: {exc}")



class DeviceSession(Base):
    __tablename__ = 'device_session'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    may_be_abp = Column(Boolean, nullable=True)
    reset_counter = Column(Integer, nullable=False, default=0)
    is_confirmed = Column(Boolean, nullable=True)
    dev_addr = Column(String(8), nullable=False)

    up_link_counter = Column(Integer, nullable=False, default=-1)

    device_id = Column(BigIntegerType, ForeignKey("device.id"), nullable=True)
    organization_id = Column(BigIntegerType, ForeignKey("organization.id"), nullable=False)
    data_collector_id = Column(BigInteger, ForeignKey("data_collector.id"), nullable=False)
    device_auth_data_id = Column(BigIntegerType, ForeignKey("device_auth_data.id"), nullable=True)
    # This is the last uplink packet ID
    last_packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=True)

    connected = Column(Boolean, nullable=False, default=True)
    last_activity = Column(DateTime(timezone=True), nullable=True)

    @classmethod
    def get(cls, device_session_id):
        return session.query(cls).filter(cls.id == device_session_id).first()

    @classmethod
    def create_from_packet(cls, packet):
        return DeviceSession(
            dev_addr = packet.dev_addr,
            up_link_counter = 0,
            organization_id = packet.organization_id,
            connected = True,
            last_activity = packet.date,
            data_collector_id = packet.data_collector_id
        )

    @classmethod
    def find_with(cls, dev_addr=None, data_collector_id=None, device_id=None):
        if dev_addr and data_collector_id:
            return session.query(cls).\
                filter(cls.dev_addr == dev_addr).\
                filter(cls.data_collector_id == data_collector_id).first()
        elif device_id:
            return session.query(cls).\
                filter(cls.device_id == device_id).first()
        else:
            return None

    def save(self):
        try:
            session.add(self)
            session.commit()
        except Exception as exc:
            log.error(f"Error creating device session: {exc}")

    def update_state(self, packet):
        if packet.m_type in ["UnconfirmedDataUp", "ConfirmedDataUp"]:
            if packet.f_count is not None:
                self.up_link_counter = packet.f_count
            self.last_packet_id = packet.id
        self.last_activity = packet.date



class Packet(Base):
    __tablename__ = 'packet'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    date = Column(DateTime(timezone=True), nullable=False)
    topic = Column(String(256), nullable=True)
    data_collector_id = Column(BigIntegerType, ForeignKey("data_collector.id"), nullable=False)
    organization_id = Column(BigIntegerType, ForeignKey("organization.id"), nullable=False)
    gateway = Column(String(16), nullable=True)
    tmst = Column(BigIntegerType, nullable=True)
    chan = Column(SmallInteger, nullable=True)
    rfch = Column(Integer, nullable=True)
    seqn = Column(Integer, nullable=True)
    opts = Column(String(20), nullable=True)
    port = Column(Integer, nullable=True)
    freq = Column(Float, nullable=True)
    stat = Column(SmallInteger, nullable=True)
    modu = Column(String(4), nullable=True)
    datr = Column(String(50), nullable=True)
    codr = Column(String(10), nullable=True)
    lsnr = Column(Float, nullable=True)
    rssi = Column(Integer, nullable=True)
    size = Column(Integer, nullable=True)
    data = Column(String(300), nullable=True)
    m_type = Column(String(20), nullable=True)
    major = Column(String(10), nullable=True)
    mic = Column(String(8), nullable=True)
    join_eui = Column(String(16), nullable=True)
    dev_eui = Column(String(16), nullable=True)
    dev_nonce = Column(Integer, nullable=True)
    dev_addr = Column(String(8), nullable=True)
    adr = Column(Boolean, nullable=True)
    ack = Column(Boolean, nullable=True)
    adr_ack_req = Column(Boolean, nullable=True)
    f_pending = Column(Boolean, nullable=True)
    class_b = Column(Boolean, nullable=True)
    f_count = Column(Integer, nullable=True)
    f_opts = Column(String(500), nullable=True)
    f_port = Column(Integer, nullable=True)
    error = Column(String(300), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    altitude = Column(Float, nullable=True)
    app_name = Column(String(100), nullable=True)
    dev_name = Column(String(100), nullable=True)
    gw_name= Column(String(120), nullable=True)

    is_repeated = False
    is_retransmission = False
    failed_jr_found = False
    uplink = False
    npackets_lost_found = 0

    def to_json(self):
        return {
            'id': self.id,
            'date': self.date.strftime(DATE_FORMAT),
            'topic': self.topic,
            'data_collector_id': self.data_collector_id,
            'organization_id': self.organization_id,
            'gateway': self.gateway,
            'tmst': self.tmst,
            'chan': self.chan,
            'rfch': self.rfch,
            'seqn': self.seqn,
            'opts': self.opts,
            'port': self.port,
            'freq': self.freq,
            'stat': self.stat,
            'modu': self.modu,
            'datr': self.datr,
            'codr': self.codr,
            'lsnr': self.lsnr,
            'rssi': self.rssi,
            'size': self.size,
            'data': self.data,
            'm_type': self.m_type,
            'major': self.major,
            'mic': self.mic,
            'join_eui': self.join_eui,
            'dev_eui': self.dev_eui,
            'dev_nonce': self.dev_nonce,
            'dev_addr': self.dev_addr,
            'adr': self.adr,
            'ack': self.ack,
            'adr_ack_req': self.adr_ack_req,
            'f_pending': self.f_pending,
            'class_b': self.class_b,
            'f_count': self.f_count,
            'f_opts': self.f_opts,
            'f_port': self.f_port,
            'error': self.error,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'altitude': self.altitude,
            'app_name': self.app_name,
            'dev_name': self.dev_name,
            'gw_name': self.gw_name
        }

    @classmethod
    def find_one(cls, packet_id):
        return session.query(cls).filter(cls.id == packet_id).first()

    @classmethod
    def find_by_organization_id_and_date(cls, organization_id, since, until):
        return session.query(cls).filter(cls.organization_id == organization_id).filter(cls.date > since,
                                                                                        cls.date < until).all()

    @classmethod
    def find_by_organization_id_and_mtype_and_date(cls, organization_id, mtype, since, until):
        return session.query(cls).filter(cls.organization_id == organization_id).filter(cls.date > since,
                                                                                        cls.date < until,
                                                                                        cls.m_type == mtype).all()

    @classmethod
    def find_all_from(cls, id, size=1000):
        return session.query(Packet).filter(Packet.id >= id).order_by(asc(Packet.id)).limit(size).all()

    @classmethod
    def find_previous_by_data_collector_and_dev_eui(cls, date, data_collector_id, dev_eui=None):
        previous_date = session.query(func.max(Packet.date)).filter(Packet.date < date).filter(
            Packet.data_collector_id == data_collector_id).filter(Packet.dev_eui == dev_eui).scalar()
        return session.query(Packet).filter(Packet.date == previous_date).filter(
            Packet.data_collector_id == data_collector_id).filter(Packet.dev_eui == dev_eui).first()

    @classmethod
    def rows_quantity(cls):
        return session.query(func.max(cls.id)).scalar()

    def save_to_db(self):
        session.add(self)


class DeviceAuthData(Base):
    __tablename__ = 'device_auth_data'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    join_request = Column(String(200), nullable=True)
    join_accept = Column(String(200), nullable=True)
    apps_key = Column(String(32), nullable=True)
    nwks_key = Column(String(32), nullable=True)
    data_collector_id = Column(BigIntegerType, ForeignKey("data_collector.id"), nullable=False)
    organization_id = Column(BigIntegerType, ForeignKey("organization.id"), nullable=False)
    device_id = Column(BigIntegerType, ForeignKey("device.id"), nullable=True)
    device_session_id = Column(BigIntegerType, ForeignKey("device_session.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    join_accept_packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=True)
    join_request_packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=True)
    app_key_hex = Column(String(32), nullable=True)
    # These vars are in case we cracked the key using another JoinRequest
    second_join_request_packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=True)
    second_join_request = Column(String(200), nullable=True)

    def save(self):
        session.add(self)
        session.flush()

    def is_complete(self):
        return self.join_request is not None and self.join_accept is not None
    
    @classmethod
    def find_one_by_device_id(cls, device_id):
        return session.query(cls).filter(cls.device_id == device_id).first()

    @classmethod
    def find_one_by_id(cls, id):
        return session.query(cls).filter(cls.id == id).first()


class PotentialAppKey(Base):
    __tablename__ = 'potential_app_key'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    device_auth_data_id = Column(BigIntegerType, ForeignKey("device_auth_data.id"), nullable=False)
    app_key_hex = Column(String(32), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=True)
    organization_id = Column(BigIntegerType, ForeignKey("organization.id"), nullable=True)

    def save(self):
        session.add(self)
        session.flush()

    @classmethod
    def find_all_by_organization_id_after_datetime(cls, organization_id, since):
        return session.query(cls).filter(cls.organization_id == organization_id, cls.last_seen > since).order_by(
            desc(cls.last_seen)).all()

    @classmethod
    def find_all_by_device_auth_id(cls, dev_auth_data_id):
        return session.query(cls).filter(cls.device_auth_data_id == dev_auth_data_id).all()

    @classmethod
    def delete_keys(cls, device_auth_data_id, keys):
        delete_query = cls.__table__.delete().\
            where(cls.device_auth_data_id == device_auth_data_id).\
            where(cls.app_key_hex.in_(keys))
        session.execute(delete_query)

    @classmethod
    def get_by_device_auth_data_and_hex_app_key(cls, device_auth_data_id, app_key_hex):
        return session.query(cls).filter(cls.device_auth_data_id == device_auth_data_id).\
                                  filter(cls.app_key_hex == app_key_hex).first()

class AppKey(Base):
    __tablename__ = 'app_key'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    key = Column(String(32), nullable=False)
    organization_id = Column(BigInteger, ForeignKey("organization.id"), nullable=True)

    @classmethod
    def get_with(cls, organization_id):
        return session.query(cls).filter(cls.organization_id == organization_id)

class RowProcessed(Base):
    __tablename__ = 'row_processed'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    last_row = Column(Integer, nullable=False, default=0)
    analyzer = Column(String(20), nullable=False)

    def save(self):
        session.add(self)
    
    @classmethod
    def find_one(cls, id):
        return session.query(cls).filter(cls.id == id).first()

    @classmethod
    def find_one_by_analyzer(cls, analyzer_id):
        return session.query(cls).filter(cls.analyzer == analyzer_id).first()

    @classmethod
    def count(cls):
        return session.query(func.count(cls.id)).scalar()

    def save_and_flush(self):
        session.add(self)
        session.flush()


class Organization(Base):
    __tablename__ = "organization"
    id = Column(BigIntegerType, primary_key=True)
    name = Column(String(120), unique=True)

    @classmethod
    def find_one(cls, id=None):
        query = session.query(cls)
        if id:
            query = query.filter(cls.id == id)
        return query.first()

    @classmethod
    def count(cls):
        return session.query(func.count(cls.id)).scalar()

    def save(self):
        session.add(self)
        session.flush()
        commit()


class PolicyItem(Base):
    __tablename__ = 'policy_item'
    id = Column(Integer, primary_key=True, autoincrement=True)
    parameters = Column(String(4096), nullable=False)
    enabled = Column(Boolean, nullable=False)
    policy_id = Column(BigInteger, ForeignKey("policy.id", ondelete="CASCADE"), nullable=False)
    alert_type_code = Column(String(20), ForeignKey("alert_type.code"), nullable=False)
    alert_type = relationship("AlertType", lazy="joined")

    def db_update(self):
        session.commit()

    @classmethod
    def find_one(cls, id):
        return session.query(cls).get(id)


class Policy(Base):
    __tablename__ = 'policy'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    items = relationship("PolicyItem", lazy="joined", cascade="all, delete-orphan")
    organization_id = Column(BigInteger, ForeignKey("organization.id"), nullable=True)
    is_default = Column(Boolean, nullable=False)
    data_collectors = relationship("DataCollector", lazy="joined")

    def add_missing_item(self, alert_type_code):
        """
        Add new policy item, with default parameters, 
        for this policy and this alert type.
        Returns the corresponding default parameters.
        """
        alert_type = AlertType.find_one_by_code(alert_type_code)
        parameters = json.loads(alert_type.parameters)
        parameters = {par : val['default'] for par, val in parameters.items()}

        session.add(PolicyItem(
            policy_id=self.id,
            alert_type_code=alert_type.code,
            enabled=True,
            parameters=json.dumps(parameters)))
        session.commit()
        return parameters

    @classmethod
    def find(cls, organization_id=None):
        query = session.query(cls)
        if organization_id:
            query = query.filter(or_(cls.organization_id == organization_id, cls.organization_id == None))
        return query.all()

    @classmethod
    def find_one(cls, id):
        return session.query(cls).get(id)


def commit():
    session.commit()


def begin():
    session.begin()


def rollback():
    session.rollback()


class QuarantineRisk(Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'


class QuarantineResolutionReasonType(Enum):
    MANUAL = 'MANUAL'
    AUTOMATIC = 'AUTOMATIC'


class QuarantineResolutionReason(Base):
    __tablename__ = "quarantine_resolution_reason"
    #region fields
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    type = Column(SQLEnum(QuarantineResolutionReasonType))
    name = Column(String(80), nullable=False)
    description = Column(String(200), nullable=True)
    #endregion

    @classmethod
    def find_by_id(cls, id):
        return session.query(cls).filter(cls.id == id).first()

    @classmethod
    def find_by_type(cls, type):
        return session.query(cls).filter(cls.type == type).first()

class Quarantine(Base):
    __tablename__ = "quarantine"
    #region fields
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    device_id = Column(BigInteger, ForeignKey("device.id"), nullable=True)
    device_session_id = Column(BigInteger, ForeignKey("device_session.id"), nullable=True)
    # organization relationship
    organization_id = Column(BigInteger, ForeignKey("organization.id"), nullable=False)
    # alert relationship
    alert_id = Column(BigInteger, ForeignKey("alert.id"), nullable=False)
    # since when is this device/alert in quarantine
    since = Column(DateTime(timezone=True), nullable=False)
    # last time the condition for quarantine was checked
    last_checked = Column(DateTime(timezone=True), nullable=True)
    # when was resolved, if applicable
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    # who resolved the quarantine, if applicable.
    # This is a foreign key to User, but here in Engine it is not used so
    # I removed the FK declaration to avoid bringing in the User class
    resolved_by_id = Column(BigInteger, nullable=True)
    # resolution reason relationship, if resolved. Null if not
    resolution_reason_id = Column(BigInteger, ForeignKey("quarantine_resolution_reason.id"), nullable=True)
    # resolution comment (optional)
    resolution_comment = Column(String(1024), nullable=True)
    # quarantine parameters (optional)
    parameters = Column(String(4096), nullable=True)
    alert = relationship("Alert", lazy="joined")
    #endregion

    def save(self):
        session.add(self)
        session.commit()

    def resolve(self, reason_id, comment, resolved_by_id=None, commit=True):
        self.resolved_at = datetime.now()
        self.resolved_by_id = resolved_by_id
        self.resolution_reason_id = reason_id
        self.resolution_comment = comment
        if commit:
            session.commit()

    @classmethod
    def find_by_id(cls, id):
        return session.query(cls).filter(cls.id == id).first()

    @classmethod
    def get_dev_id(cls, dev_eui, data_collector_id):
        dev_ids = Device.find(dev_eui, data_collector_id)
        if len(dev_ids) == 1:
            return dev_ids[0].id
        elif len(dev_ids) == 0:
            raise RuntimeError(f"No device with dev_eui {dev_eui} and data_collector_id {data_collector_id} found in database")
        else:
            raise RuntimeError(f"More than one device with eui {dev_eui} and data_collector_id {data_collector_id}")

    @classmethod
    def find_open_by_alert(cls, alert):
        return cls.find_open_by_type_dev_coll(alert.type, alert.device_id, alert.device_session_id, alert.data_collector_id)

    @classmethod
    def find_open_by_type_dev_coll(cls, alert_type, device_id=None, device_session_id=None, data_collector_id=None, returnAll=False, gateway_id=None):
        q = session.query(cls).join(Alert).filter(Alert.type == alert_type, cls.resolved_at == None)
        if device_id:
            q = q.filter(Alert.device_id == device_id)
        if gateway_id:
            q = q.filter(Alert.gateway_id == gateway_id)
        if device_session_id:
            q = q.filter(Alert.device_session_id == device_session_id)
        if data_collector_id:
            q = q.filter(Alert.data_collector_id == data_collector_id)
        if returnAll:
            return q.all()
        return q.first()

    @classmethod
    def put_on_quarantine(cls, alert=None, quarantine_row=None):
        row_added = False
        if quarantine_row is None:
            quarantine_row = cls.find_open_by_alert(alert=alert)

        if quarantine_row:
            quarantine_row.last_checked = datetime.now()
            session.commit()
        else:
            quarantine_row = cls(device_id = alert.device_id,
                                device_session_id = alert.device_session_id,
                                organization_id = alert.find_organization_id(alert.id),
                                alert_id = alert.id,
                                since = datetime.now(),
                                last_checked = datetime.now())
            quarantine_row.save()
            row_added = True
        return quarantine_row, row_added

    @classmethod
    def remove_from_quarantine_by_alert(cls, alert, res_reason_id, res_comment):
        cls.remove_from_quarantine(alert.type, alert.device_id, alert.device_session_id,
                                   alert.data_collector_id, res_reason_id, res_comment)

    @classmethod
    def remove_from_quarantine_manually(cls, id, user_id, res_comment):
        qRec = cls.find_by_id(id)
        if not qRec:
            raise RuntimeError(f'Quarantine record with id {id} not found')
        if qRec.resolved_at is not None:
            raise RuntimeError(f'Quarantine is already resolved')
        reason = QuarantineResolutionReason.find_by_type(QuarantineResolutionReasonType.MANUAL)
        if not reason:
            raise RuntimeError(f'Manual quarantine resolution type not found')
        qRec.resolve(
            resolved_by_id=user_id,
            reason_id=reason.id,
            comment=res_comment,
            commit=True
        )

    @classmethod
    def remove_from_quarantine(cls, alert_type, device_id, device_session_id, data_collector_id, res_reason_id, res_comment):
        qrec = cls.find_open_by_type_dev_coll(alert_type, device_id, device_session_id, data_collector_id)
        if qrec:
            qrec.resolve(
                reason_id=res_reason_id,
                comment=res_comment,
                commit=True
            )
            return True
        return False


Base.metadata.create_all(engine)
