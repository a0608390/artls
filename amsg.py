from helper import *
import hmac
from hashlib import sha1
from tabulate import tabulate
import struct
import pysnooper

secret = '123456'

# HMAC-SHA1 signature
def signature(key,pkt):
     sig = hmac.new(key.encode(), pkt, sha1).digest()
     return pkt + sig



class MSG:
    """
     aruba rtls packet structure
          -------------------------------------------------------
          | ip | udp | rtls_hdr | rtls_payload | rtls_signature |
          -------------------------------------------------------
     MSG class is a rtls_hdr + rtls_payload + rtls_signature
     rtls_hdr is 16 bytes
     rtls_signature is 20 bytes, HMAC-SHA1(rtls_hdr+rtls_payload)

    """
    def __init__(self, pkt):
        self.message_type = pkt[:2]
        self.message_id = pkt[2:4]
        self.major_version = pkt[4:5]
        self.minor_version = pkt[5:6]
        self.data_lenght = pkt[6:8]
        self.ap_mac = pkt[8:14]
        self.padding = pkt[14:16]
        self.tags = None

        if self.message_type == b'\x00\x10':
            print('AR_NACK')
            self.payload = pull_10(pkt[16:-20])
        elif self.message_type == b'\x00\x11':
            print('AR_NACK')
            self.payload = pull_11(pkt[16:-20])
        elif self.message_type == b'\x00\x12':
            print('AR_TAG_REPORT')
            self.payload = pull_12(pkt[16:-20])
        elif self.message_type == b'\x00\x13':
            print('AR_STATION_REPORT')
            self.payload = pull_13(pkt[16:-20])
        elif self.message_type == b'\x00\x14':
            print('AR_COMPOUND_MESSAGE_REPORT')
            self.payload = pull_14(pkt[16:-20])
            self.tags = self.payload['Tags']
            self.payload['Tags'] = b''
        elif self.message_type == b'\x00\x15':
            print('AR_AP_NOTIFICATION')
            self.payload = pull_15(pkt[16:-20])
        elif self.message_type == b'\x00\x17':
            print('AR_STATION_EX_REPORT')
            self.payload = pull_17([pkt[16:-20]])
        elif self.message_type == b'\x00\x18':
            print('AR_AP_EX_REPORT')
            self.payload = pull_18(pkt[16:-20])

        self.signature = pkt[-20:]

    # view rtls server received packet.
    def view(self):
        tb_header = ['Message Type','Message Id','Major version','Minor Version','Data Length','AP MAC','Padding']
        for key in self.payload.keys():
            tb_header.append(key)
        tb_data = [self.message_type,self.message_id,self.major_version,self.minor_version,self.data_lenght,self.ap_mac,self.padding]
        for key in self.payload.keys():
            tb_data.append(self.payload.get(key))
        tb_data = [data.hex() for data in tb_data]

        print(tabulate([tb_data], headers=tb_header, tablefmt='psql'))

        if self.tags != None:
            tb_station_ex_header = ['Message Type','Message Id','Major version','Minor Version','Data Length','AP MAC','Padding']
            tb_ap_ex_header = ['Message Type','Message Id','Major version','Minor Version','Data Length','AP MAC','Padding']
            tb_station_header = ['Message Type', 'Message Id', 'Major version', 'Minor Version', 'Data Length', 'AP MAC', 'Padding']

            tb_station_ex_data = []
            tb_ap_ex_data = []
            tb_station_data = []

            while self.tags:
                msg_length, = struct.unpack('!H', self.tags[6:8])
                msg_length +=16
                if self.tags[:2] == b'\x00\x17':
                    station_ex_data = [self.tags[:2],self.tags[2:4],self.tags[4:5],self.tags[5:6],self.tags[6:8],self.tags[8:14],self.tags[14:16]]
                    station_ex = pull_17(self.tags[16:msg_length])
                    station_ex_data.extend(station_ex.values())
                    station_ex_data = [data.hex() for data in station_ex_data]
                    tb_station_ex_data.append(station_ex_data)
                    self.tags = self.tags[msg_length:]

                elif self.tags[:2] == b'\x00\x18':
                    ap_ex_data = [self.tags[:2],self.tags[2:4],self.tags[4:5],self.tags[5:6],self.tags[6:8],self.tags[8:14],self.tags[14:16]]
                    ap_ex = pull_18(self.tags[16:msg_length])
                    ap_ex_data.extend(ap_ex.values())
                    ap_ex_data = [data.hex() for data in ap_ex]
                    tb_ap_ex_data.append(ap_ex_data)
                    self.tags = self.tags[msg_length:]

                elif self.tags[:2] == b'\x00\x13':
                    station_data = [self.tags[:2],self.tags[2:4],self.tags[4:5],self.tags[5:6],self.tags[6:8],self.tags[8:14],self.tags[14:16]]
                    station = pull_13(self.tags[16:msg_length])
                    station_data.extend(station.values())
                    station_data = [data.hex() for data in station_data]
                    tb_station_data.append(station_data)
                    self.tags = self.tags[msg_length:]

                else:
                    pass
            print('\033[1;35mstation_ex tags report....\033[0m')
            try:
                tb_station_ex_header.extend(station_ex.keys())
                print(tabulate(tb_station_ex_data,headers=tb_station_ex_header,tablefmt='psql'))
            except:
                print('station tags is null')
            print('\033[1;35map_ex tags report...\033[0m')
            try:
                tb_ap_ex_header.extend(ap_ex.keys())
                print(tabulate(tb_ap_ex_data,headers=tb_ap_ex_header,tablefmt='psql'))
            except:
                print('ap_ex tags is null')
            print('\033[1;35mstation tags report....\033[0m')
            try:
                tb_station_header.extend(station.keys())
                print(tabulate(tb_station_data,headers=tb_station_header,tablefmt='psql'))
            except:
                print('station tags is null')





    # AR_AS_CONFIG_SET
    def push_00(self):
        pass

    # AR_STATION_REQUEST
    def push_01(self, mac):
        pass

    def push_10(self):
        content = b'\x00\x10' + self.message_id + self.major_version + self.minor_version + b'\x00\x00' + self.ap_mac + self.padding
        pkt = signature(secret,content)
        return pkt
