"""
define hepler function,get massage payload
"""


# AR_ACK
def pull_10(pkt):
    payload = {}
    return payload


# AR_NACK
def pull_11(pkt):
    payload = {
        'flags': pkt[:2],
        'reserved': pkt[2:]
    }
    return payload


# AR_TAG_REPORT
def pull_12(pkt):
    payload = {
        'Bssid': pkt[:6],
        'RSSI': pkt[6:7],
        'Noise_floor': pkt[7:8],
        'Timestamp': pkt[8:12],
        'Tag_mac': pkt[12:18],
        'Frame_control': pkt[18:20],
        'Sequence': pkt[20:22],
        'Data_rate': pkt[22:23],
        'Tx_power': pkt[23:24],
        'Channel': pkt[24:25],
        'Battery': pkt[25:26],
        'Reserved': pkt[26:28],
        'Payload': pkt[28:29]
    }

    return payload


# AR_STATION_REPORT
def pull_13(pkt):
    payload = {
        'MAC': pkt[:6],
        'Noise_floor': pkt[6:7],
        'Data_rate': pkt[7:8],
        'Channel': pkt[8:9],
        'RSSI': pkt[9:10],
        'Type': pkt[10:11],
        'Associated': pkt[11:12],
        'Radio_BSSID': pkt[12:18],
        'Mon_BSSID': pkt[18:24],
        'Age': pkt[24:28]
    }

    return payload


# AR_COMPOUND_MESSAGE_REPORT
def pull_14(pkt):
    payload = {
        'Messages_number':pkt[:2],
        'Reserved':pkt[2:3],
        'Payload':pkt[3:4],
        'Tags':pkt[4:]
    }

    return payload


# AR_AP_NOTIFICATION
def pull_15(pkt):
    payload = {}

    return payload


# AR_MMS_CONFIG_SET
def push_16(pkt):
    pass


# AR_STATION_EX_REPORT
def pull_17(pkt):
    payload = {
        'MAC':pkt[:6],
        'BSSID':pkt[6:12],
        'ESSID':pkt[12:45],
        'Channel':pkt[45:46],
        'Phy_type':pkt[46:47],
        'RSSI':pkt[47:48],
        'Duration':pkt[48:50],
        'Num_packets':pkt[50:52],
        'Noise_floor':pkt[52:53],
        'Classification':pkt[53:54],
        'Reserved':pkt[54:56]
    }

    return payload


# AR_AP_EX_REPORT
def pull_18(pkt):
    payload = {
        'BSSID':pkt[:6],
        'ESSID':pkt[6:39],
        'Channel':pkt[39:40],
        'Phy_type':pkt[40:41],
        'RSSI':pkt[41:42],
        'Duration':pkt[42:44],
        'Num_packets':pkt[44:46],
        'Noise_floor':pkt[46:47],
        'Classification':pkt[47:48],
        'Match_type':pkt[48:49],
        'Match_method':pkt[49:50],
        'Reserved':pkt[50:52]
    }

    return payload
