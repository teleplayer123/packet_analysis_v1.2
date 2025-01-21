import os
import struct 
import sys
import usb.core
import usb.util
from time import sleep

from utils.hex_dump import xdump

if len(sys.argv) > 0:
    CHANNEL = int(sys.argv[1])
else:
    CHANNEL = 37

#cc2540 Requests
GET_IDENTITY = 0xc0
SET_POWER = 0xc5
GET_POWER = 0xc6
SET_START = 0xd0
SET_END = 0xd1
SET_CHANNEL = 0xd2

class LL_Header:

    def __init__(self, raw_data):
        phy_hdr = struct.unpack(">BIH", raw_data[0:7])
        self.preamble = phy_hdr[0]
        self.access_addr = hex(phy_hdr[1])
        self.pdu = self.get_pdu_hdr(phy_hdr[2])
        self.data = raw_data[7:]

    def get_pdu_hdr(self, data):
        """
        pdu type: 4 bits
        rfu: 1 bit
        ChSel: 1 bit
        TxAdd: 1 bit
        RxAdd: 1 bit
        length: 8 bits
        """
        pdu_type = data >> 12
        rfu = data >> 11 & 0b00001
        chsel = data >> 10 & 0b000001
        txadd = data >> 9 & 0b0000001
        rxadd = data >> 8 & 0b00000001
        length = data & 0b11111111
        return {
            "pdu_type": (self.get_pdu_type(pdu_type)),
            "rfu": rfu,
            "chsel": chsel,
            "txadd": txadd,
            "rxadd": rxadd,
            "length": length
        }

    def get_pdu_type(self, bits):
        name = None
        val = None
        pdu_types = {
            "ADV_IND": 0b0000,
            "ADV_DIRECT_IND": 0b0001,
            "ADV_NONCONN_IND": 0b0010,
            "SCAN_REQ": 0b0011,
            "SCAN_RSP": 0b0100,
            "CONNECT_IND": 0b0101,
            "ADV_SCAN_IND": 0b0110
        }
        for k, v in pdu_types.items():
            if bits & v:
                name = k
                val = v
                break
        return name, val

    def __str__(self):
        return f"""
        Preamble: {self.preamble}
        Access Address: {self.access_addr}
        PDU: {self.pdu}
        Data Dump:
        {xdump(self.data)}
        """


class CC2540_Packet:
    
    def __init__(self, raw_data):
        pdata = struct.unpack("<BIQB", raw_data[0:14])
        self.p_info = pdata[0]
        self.p_num = pdata[1]
        self.p_time = self.calc_time(pdata[2])
        self.p_len = pdata[3]
        

    def calc_time(self, tm):
        tm_hi = tm & 0xffff
        tm_lo = tm >> 16
        tms = (tm_hi*5000 + tm_lo) / 32
        return float(tms)
    
    def __str__(self):
        return f"""
        Info: {self.p_info}
        Packet Number: {hex(self.p_num)}
        Timestamp: {self.p_time}
        Length: {self.p_len}
        """
        

#you can get id's from lsusb
cc2540_vendor = 0x0451
cc2540_product = 0x16b3
cc2540_ep = 0x83
#cc2531_vendor = 0x0451
#cc2531_product = 0x16ae
#cc2531_ep = 0x83


dev = usb.core.find(idVendor=cc2540_vendor, idProduct=cc2540_product)
"""
dev.set_configuration()
config = dev.get_active_configuration()
iface = config[(0,0)]
"""
"""
##bConfigurationValue is needed to set_configuration to work with device
bconfig = iface.bConfigurationValue
config = usb.util.find_descriptor(dev)
config.set()
print(config)
"""

#write(endpoint_addr, msg, timeout)
#read(endpoint_addr, read_size, timeout)
#ctrl_transfer(bmRequestType, bmRequest, wValue, wIndex, payload/length)
# -bmRequestType controls data transfer direction (OUT and IN) OUT=0x40, IN=0xC0
# -bmRequest is the action command:  
ret = dev.ctrl_transfer(0xc0, GET_IDENTITY, 0, 0, 256)
print(f"ID: {ret}")
dev.ctrl_transfer(0x40, SET_POWER, wIndex=4)
while True:
    power = dev.ctrl_transfer(0xc0, GET_POWER, 0, 0, 1)
    print(power)
    if power[0] == 4:
        break
    else:
        sleep(1)
dev.ctrl_transfer(0x40, SET_CHANNEL, 0, 0, [CHANNEL])
dev.ctrl_transfer(0x40, SET_CHANNEL, 0, 1, [0x00])

dev.ctrl_transfer(0x40, SET_START)
while True:
    try:
        data = dev.read(cc2540_ep, 4096, 1500)
        try:
            pkt = LL_Header(data)
            print(str(pkt))
            print(f"\nRAW DATA: {data}")
        except struct.error:
            continue
    except usb.core.USBError as err:
        print(f"Error: {err}")
        continue
    except KeyboardInterrupt:
        dev.ctrl_transfer(0x40, SET_POWER, wIndex=0)
        power = dev.ctrl_transfer(0xc0, GET_POWER, 0, 0, 1)
        print(f"Shutting down power: {power}")
        dev.ctrl_transfer(0x40, SET_END)
        break
