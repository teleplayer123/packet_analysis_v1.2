from collections import defaultdict
import json
import socket
import struct

from packet import ethr_hdr, ip_hdr, ipv6_hdr, tcp_hdr
from utils.hex_dump import xdump
from utils.checksum import verify_checksum

class Ethernet:

    def __init__(self, frame):
        eth_struct = struct.Struct("!6B6BH")
        data = eth_struct.unpack(frame[:14])
        self.size = struct.calcsize("!6B6BH")
        self.dst_addr = self.fmt_mac(data[0:6])
        self.src_addr = self.fmt_mac(data[6:12])
        self.etype = self.get_type(data[12])

    def fmt_mac(self, data):
        bs = ["%02x" % data[i] for i in range(len(data))]
        return ":".join(bs)

    def get_type(self, data):
        etype = "Unknown"
        set_of_pairs = {
        "IPv4": 0x0800,
        "ARP": 0x0806,
        "RARP": 0x8035,
        "SNMP": 0x814c,
        "IPv6": 0x86dd
        }
        for k, v in set_of_pairs.items():
            if data == v:
                etype = k
                break
        return etype, data

    def obj_hdr(self):
        hdr = ethr_hdr(self.dst_addr, self.src_addr, self.etype[0])
        return hdr

    def json_dump(self):
        return json.dumps(self.obj_hdr())

    def dump(self):
        print("Ethernet Header")
        print("------------------------")
        print(f"Destination: {self.dst_addr}")
        print(f"Source: {self.src_addr}")
        print(f"Ether Type: {self.etype[0]} ({hex(self.etype[1])})")

    def __str__(self):
        return f"""
        Ethernet Header
        ---------------
        Destination Address: {self.dst_addr}
        Source Address: {self.src_addr}
        Ether Type: {self.etype[0]} ({hex(self.etype[1])})
        """


class IPv4Header:
    def __init__(self, frame):
        hstr = frame[14:34]
        iph = struct.unpack("!BBHHHBBH4s4s", hstr)
        self.size = struct.calcsize("!BBHHHBBH4s4s")
        self.version = iph[0] >> 4
        self.internet_header_len = (iph[0] & 0b1111) * 4
        self.dscp = self.get_dscp(iph[1] >> 2)
        self.explicit_congestion = self.get_ecn(iph[1] & 0b11)
        self.total_len = iph[2]
        self.id = iph[3]
        self.flags = self.get_flag((iph[4] >> 13))
        self.fragment_offset = iph[4] & 0b1111111111111
        self.time_to_live = iph[5]
        self.protocol = self.get_proto(iph[6])
        self.checksum = iph[7]
        self.src_addr = socket.inet_ntoa(iph[8])
        self.dst_addr = socket.inet_ntoa(iph[9])

        self.packet_data = struct.unpack("!10H", hstr)


    def obj_hdr(self):
        hdr = ip_hdr(self.version, self.internet_header_len, self.dscp[0], self.explicit_congestion[0],
                    self.total_len, self.id, self.flags, self.fragment_offset, self.time_to_live,
                    self.protocol[0], self.checksum, self.src_addr, self.dst_addr)
        return hdr

    def json_dump(self):
        return json.dumps(self.obj_hdr())

    def get_dscp(self, bits):
        """
        CS: Class Selector
        AFxy: Assured Forwarding(x=class, y=drop presedence)
        EF: Expedited Forwarding
        """
        flag = ""
        desc = ""
        dscp_dict = {
            #class selector
            "CS0": 0, 
            "CS1": 8,
            "CS2": 16,
            "CS3": 24,
            "CS4": 32,
            "CS5": 40,
            "CS6": 48,
            "CS7": 56,
            #assured forwarding
            "AF11": 10,
            "AF12": 12,
            "AF13": 14,
            "AF21": 18,
            "AF22": 20,
            "AF23": 22,
            "AF31": 26,
            "AF32": 28,
            "AF33": 30,
            "AF41": 34,
            "AF42": 36,
            "AF43": 38,
            #expedited forwarding
            "EF": 46,
            "VOICE-ADMIT": 44
        }

        presedence = {
            "Best Effort": {0},
            "Priority": {8, 10, 12, 14},
            "Immediate": {16, 18, 20, 22},
            "Flash": {24, 26, 28, 30},
            "Flash Override": {32, 34, 36, 38},
            "Critical": {40, 46},
            "Internetwork Control": {48},
            "Network Control": {56}
        }

        for k, v in dscp_dict.items():
            if bits == v:
                flag = k
                break
        for k, v in presedence.items(): 
            if dscp_dict[flag] in v:
                desc = k
                break
        return flag, dscp_dict[flag], desc

    def get_opt_type(self, bits):
        flag = ""
        opts = {
            "EOOL": 0x00,
            "NOP": 0x01,
            "SEC(defunct)": 0x02,
            "RR": 0x07A,
            "ZSU": 0x0A,
            "MTUP": 0x0B,
            "MTUR": 0x0C,
            "ENCODE": 0x0F,
            "QS": 0x19,
            "EXP": 0x1E,
            "SEC(RIPSO)": 0x82,
            "LSR": 0x83,
            "E-SEC": 0x85,
            "CIPSO": 0x86,
            "SID": 0x88,
            "SSR": 0x89,
            "VISA": 0x8E,
            "IMITD": 0x90,
            "EIP": 0x91,
            "ADDEXT": 0x93,
            "RTRALT": 0x94,
            "SDB": 0x95,
            "DPS": 0x97,
            "UMP": 0x98,
            "EXP0": 0x9E,
            "FINN": 0xCD,
            "EXP1": 0xDE
        }
        for k, v in opts.items():
            if bits == v:
                flag = k
                break
        return flag, opts[flag]

    def get_ecn(self, bits):
        flag = ""
        flag_dic = {
            "Non-ECT": 0b00, #non ecn-capable transport
            "ECT0": 0b10,
            "ECT1": 0b01,
            "CE": 0b11 #congestion encountered
        }
        for k, v in flag_dic.items():
            if bits == v:
                flag = k
                break
        return flag, flag_dic[flag]

    def get_flag(self, fbits):
        flags = []
        if (fbits >> 1) & 0b1:
            flags.append("DF")
        if (fbits & 0b1) & 0b1:
            flags.append("MF")
        if flags != []:
            return ",".join(flags)
        else:
            return "--"

    def get_proto(self, bits):
        proto = ""
        proto_dic = {
            "HOPOPT": 0,
            "ICMP": 1,
            "IGMP": 2,
            "GGP": 3,
            "IP-in-IP": 4,
            "ST": 5,
            "TCP": 6,
            "CBT": 7,
            "EGP": 8,
            "IGP": 9,
            "BBN-RCC-MON": 10,
            "NVP-II": 11,
            "PUP": 12,
            "ARGUS": 13,
            "EMCON": 14,
            "XNET": 15,
            "CHAOS": 16,
            "UDP": 17,
            "MUX": 18,
            "DCN-MEAS": 19,
            "HMP": 20,
            "PRM": 21,
            "XNS-IDP": 22,
            "TRUNK-1": 23,
            "TRUNK-2": 24,
            "LEAF-1": 25,
            "LEAF-2": 26,
            "RDP": 27,
            "IRTP": 28,
            "ISO-TP4": 29,
            "NETBLT": 30,
            "MFE-NSP": 31,
            "MERIT-INP": 32,
            "DCCP": 33,
            "3PC": 34,
            "IDPR": 35,
            "XTP": 36,
            "DDP": 37,
            "IDPR-CMTP": 38,
            "TP++": 39,
            "IL": 40,
            "IPv6": 41,
            "SDRP": 42,
            "IPv6-Route": 43,
            "IPv6-Frag": 44,
            "IDRP": 45,
            "RSVP": 46,
            "GREs": 47,
            "DSR": 48,
            "BNA": 49,
            "ESP": 50,
            "AH": 51,
            "I-NLSP": 52,
            "SwIPe": 53,
            "NARP": 54,
            "MOBILE": 55,
            "TLSP": 56,
            "SKIP": 57,
            "IPv6-ICMP": 58,
            "IPv6-NoNxt": 59,
            "IPv6-Opts": 60,
            "Any host internal protocol": 61,
            "CFTP": 62,
            "Any local network": 63,
            "SAT-EXPAK": 64,
            "KRYPTOLAN": 65,
            "RVD": 66,
            "IPPC": 67,
            "Any distributed file system": 68,
            "SAT-MON": 69,
            "VISA": 70,
            "IPCU": 71,
            "CPNX": 72,
            "CPHB": 73,
            "WSN": 74,
            "PVP": 75,
            "BR-SAT-MON": 76,
            "SUN-ND": 77,
            "WB-MON": 78,
            "WB-EXPAK": 79,
            "ISO-IP": 80,
            "VMTP": 81,
            "SECURE-VMTP": 82,
            "VINES": 83,
            "TTP": 84,
            "NSFNET-IGP": 85,
            "DGP": 86,
            "TCF": 87,
            "EIGRP": 88,
            "OSPF": 89,
            "Sprite-RPC": 90,
            "LARP": 91,
            "MTP": 92,
            "AX.25": 93,
            "OS": 94,
            "MICP": 95,
            "SCC-SP": 96,
            "ETHERIP": 97,
            "ENCAP": 98,
            "Any private encryption scheme": 99,
            "GMTP": 100,
            "IFMP": 101,
            "PNNI": 102,
            "PIM": 103,
            "ARIS": 104,
            "SCPS": 105,
            "QNX": 106,
            "A/N": 107,
            "IPComp": 108,
            "SNP": 109,
            "Compaq-Peer": 110,
            "IPX-in-IP": 111,
            "VRRP": 112,
            "PGM": 113,
            "0-hop protocol": 114,
            "L2TP": 115,
            "DDX": 116,
            "IATP": 117,
            "STP": 118,
            "SRP": 119,
            "UTI": 120,
            "SMP": 121,
            "SM": 122,
            "PTP": 123,
            "IS-IS": 124,
            "FIRE": 125,
            "CRTP": 126,
            "CRUDP": 127,
            "SSCOPMCE": 128,
            "IPLT": 129,
            "SPS": 130,
            "PIPE": 131,
            "SCTP": 132,
            "FC": 133,
            "RSVP-E2E-IGNORE": 134,
            "Mobility": 135,
            "UDPLite": 136,
            "MPLS-in-IP": 137,
            "manet": 138,
            "HIP": 139,
            "Shim6": 140,
            "WESP": 141,
            "ROHC": 142,
            "Ethernet": 143,
            #"Unassigned": range(144, 253),
            #"Experimental": range(253, 255),
            "Reserved": 255
        }
        if bits in range(144, 253):
            return "Unassigned", bits
        if bits in range(253, 255):
            return "Experimental", bits
        for k, v in proto_dic.items():
            if bits == v:
                proto = k
                break
        return proto, proto_dic[proto]

    def dump(self):
        print("IP Header")
        print("------------------")
        print(f"Version: {self.version}")
        print(f"Header Length: {self.internet_header_len}")
        print(f"Differentiated Services Code Point: {self.dscp[0]} ({hex(self.dscp[1])}): {self.dscp[2]}")
        print(f"Explicit Congestion Notification: {self.explicit_congestion[0]} ({hex(self.explicit_congestion[1])})")
        print(f"Total Length: {self.total_len}")
        print(f"Identification: {self.id}")
        print(f"Flags: {self.flags}")
        print(f"Fragment Offset: {self.fragment_offset}")
        print(f"Time to Live: {self.time_to_live}")
        print(f"Protocol: {self.protocol[0]}")
        print(f"Checksum: {self.checksum}")
        print(f"Source Address: {self.src_addr}")
        print(f"Destination Address: {self.dst_addr}")

    def __str__(self):
        return f"""
        IPv4 Header
        ------------------
        Version: {self.version}
        Header Length: {self.internet_header_len}
        Differentiated Services Code Point: {self.dscp[0]} ({hex(self.dscp[1])}): {self.dscp[2]}
        Explicit Congestion Notification: {self.explicit_congestion[0]} ({hex(self.explicit_congestion[1])})
        Total Length: {self.total_len}
        Identification: {self.id}
        Flags: {self.flags}
        Fragment Offset: {self.fragment_offset}
        Time to Live: {self.time_to_live}
        Protocol: {self.protocol[0]} ({hex(self.protocol[1])})
        Checksum: {self.checksum}
        Source Address: {self.src_addr}
        Destination Address: {self.dst_addr}

        Data Integrity Check (should be zero): {verify_checksum(self.packet_data)}
        """


class IPv6Header:

    def __init__(self, frame):
        ipv6_struct = struct.Struct("!4sHBB8H8H")
        data = ipv6_struct.unpack(frame[14:54])
        data0 = int.from_bytes(data[0], byteorder="big")
        self.version = data0 >> 28
        self.dscp = self.get_dscp(data0 >> 22 & 0b111111)
        self.ecn = self.get_ecn(data0 >> 20 & 0b11)
        self.flow_label = data0 & 0b11111111111111111111
        self.payload_len = data[1]
        self.next_header = self.get_proto(data[2])
        self.hop_limit = data[3]
        self.src_addr = self.format_ipv6(data[4:12])
        self.dst_addr = self.format_ipv6(data[12:20])
    
    def obj_hdr(self):
        hdr = ipv6_hdr(self.version, self.dscp[0], self.ecn[0], self.flow_label,
                       self.payload_len, self.next_header[0], self.hop_limit,
                       self.src_addr, self.dst_addr)
        return hdr

    def json_obj(self):
        d = {}
        d["ipv6"] = self.obj_hdr()
        return d

    def format_ipv6(self, bits):
        ipv6 = ":".join(["%04x" %bits[i] for i in range(len(bits))])
        return str(ipv6)

    def get_dscp(self, bits):
        flag = ""
        dscp_dict = {
            "CS0": 0,
            "CS1": 8,
            "CS2": 16,
            "CS3": 24,
            "CS4": 32,
            "CS5": 40,
            "CS6": 48,
            "CS7": 56,
            "AF11": 10,
            "AF12": 12,
            "AF13": 14,
            "AF21": 18,
            "AF22": 20,
            "AF23": 22,
            "AF31": 26,
            "AF32": 28,
            "AF33": 30,
            "AF41": 34,
            "AF42": 36,
            "AF43": 38,
            "EF": 46,
            "VOICE-ADMIT": 44
        }
        for k, v in dscp_dict.items():
            if bits == v:
                flag = k
                break
        return flag, dscp_dict[flag]

    def get_ecn(self, bits):
        flag = ""
        flag_dic = {
            "Non-ECT": 0b00, #non ecn-capable transport
            "ECT0": 0b10,
            "ECT1": 0b01,
            "CE": 0b11 #congestion encountered
        }
        for k, v in flag_dic.items():
            if bits == v:
                flag = k
                break
        return flag, flag_dic[flag]

    def get_proto(self, bits):
        proto = ""
        proto_dic = {
            "HOPOPT": 0,
            "ICMP": 1,
            "IGMP": 2,
            "GGP": 3,
            "IP-in-IP": 4,
            "ST": 5,
            "TCP": 6,
            "CBT": 7,
            "EGP": 8,
            "IGP": 9,
            "BBN-RCC-MON": 10,
            "NVP-II": 11,
            "PUP": 12,
            "ARGUS": 13,
            "EMCON": 14,
            "XNET": 15,
            "CHAOS": 16,
            "UDP": 17,
            "MUX": 18,
            "DCN-MEAS": 19,
            "HMP": 20,
            "PRM": 21,
            "XNS-IDP": 22,
            "TRUNK-1": 23,
            "TRUNK-2": 24,
            "LEAF-1": 25,
            "LEAF-2": 26,
            "RDP": 27,
            "IRTP": 28,
            "ISO-TP4": 29,
            "NETBLT": 30,
            "MFE-NSP": 31,
            "MERIT-INP": 32,
            "DCCP": 33,
            "3PC": 34,
            "IDPR": 35,
            "XTP": 36,
            "DDP": 37,
            "IDPR-CMTP": 38,
            "TP++": 39,
            "IL": 40,
            "IPv6": 41,
            "SDRP": 42,
            "IPv6-Route": 43,
            "IPv6-Frag": 44,
            "IDRP": 45,
            "RSVP": 46,
            "GREs": 47,
            "DSR": 48,
            "BNA": 49,
            "ESP": 50,
            "AH": 51,
            "I-NLSP": 52,
            "SwIPe": 53,
            "NARP": 54,
            "MOBILE": 55,
            "TLSP": 56,
            "SKIP": 57,
            "IPv6-ICMP": 58,
            "IPv6-NoNxt": 59,
            "IPv6-Opts": 60,
            "Any host internal protocol": 61,
            "CFTP": 62,
            "Any local network": 63,
            "SAT-EXPAK": 64,
            "KRYPTOLAN": 65,
            "RVD": 66,
            "IPPC": 67,
            "Any distributed file system": 68,
            "SAT-MON": 69,
            "VISA": 70,
            "IPCU": 71,
            "CPNX": 72,
            "CPHB": 73,
            "WSN": 74,
            "PVP": 75,
            "BR-SAT-MON": 76,
            "SUN-ND": 77,
            "WB-MON": 78,
            "WB-EXPAK": 79,
            "ISO-IP": 80,
            "VMTP": 81,
            "SECURE-VMTP": 82,
            "VINES": 83,
            "TTP": 84,
            "NSFNET-IGP": 85,
            "DGP": 86,
            "TCF": 87,
            "EIGRP": 88,
            "OSPF": 89,
            "Sprite-RPC": 90,
            "LARP": 91,
            "MTP": 92,
            "AX.25": 93,
            "OS": 94,
            "MICP": 95,
            "SCC-SP": 96,
            "ETHERIP": 97,
            "ENCAP": 98,
            "Any private encryption scheme": 99,
            "GMTP": 100,
            "IFMP": 101,
            "PNNI": 102,
            "PIM": 103,
            "ARIS": 104,
            "SCPS": 105,
            "QNX": 106,
            "A/N": 107,
            "IPComp": 108,
            "SNP": 109,
            "Compaq-Peer": 110,
            "IPX-in-IP": 111,
            "VRRP": 112,
            "PGM": 113,
            "0-hop protocol": 114,
            "L2TP": 115,
            "DDX": 116,
            "IATP": 117,
            "STP": 118,
            "SRP": 119,
            "UTI": 120,
            "SMP": 121,
            "SM": 122,
            "PTP": 123,
            "IS-IS": 124,
            "FIRE": 125,
            "CRTP": 126,
            "CRUDP": 127,
            "SSCOPMCE": 128,
            "IPLT": 129,
            "SPS": 130,
            "PIPE": 131,
            "SCTP": 132,
            "FC": 133,
            "RSVP-E2E-IGNORE": 134,
            "Mobility": 135,
            "UDPLite": 136,
            "MPLS-in-IP": 137,
            "manet": 138,
            "HIP": 139,
            "Shim6": 140,
            "WESP": 141,
            "ROHC": 142,
            "Ethernet": 143,
            #"Unassigned": range(144, 253),
            #"Experimental": range(253, 255),
            "Reserved": 255
        }
        for k, v in proto_dic.items():
            if bits == v:
                proto = k
                break
        return proto, proto_dic[proto]

    def __str__(self):
        return f"""
        IPv6 Header
        -------------------------
        Version: {self.version}
        Differentiated Services: {self.dscp[0]} ({hex(self.dscp[1])})
        Explicit Congestion Notification: {self.ecn[0]} ({hex(self.ecn[1])})
        Flow Label: {self.flow_label}
        Payload Length: {self.payload_len}
        Next Header: {self.next_header[0]} ({hex(self.next_header[1])})
        Hop Limit: {self.hop_limit}
        Source Address: {self.src_addr}
        Destination Address: {self.dst_addr}
        """


class TCPHeader:
    def __init__(self, frame, ipheader):
        header_size = 14 + ipheader.internet_header_len
        tcphead = frame[header_size: header_size + 20]
        tcpbits = struct.unpack("!HHLLHHHH", tcphead)
        self.size = struct.calcsize("!HHLLHHHH")
        self.src_port = tcpbits[0]
        self.dst_port = tcpbits[1]
        self.seq_num = tcpbits[2]
        self.ack_num = tcpbits[3]
        self.offset = (tcpbits[4] >> 12) * 4
        self.flags = self.get_flags(tcpbits[4] & 0b111111111)
        self.window_size = tcpbits[5]
        self.checksum = tcpbits[6]
        self.urg_pointer = tcpbits[7]

    def get_flags(self, flagbits):
        flag_dict = {
            "NS": 0b100000000 & flagbits,
            "CWR": 0b010000000 & flagbits,
            "ECE": 0b001000000 & flagbits,
            "URG": 0b000100000 & flagbits,
            "ACK": 0b000010000 & flagbits,
            "PSH": 0b000001000 & flagbits,
            "RST": 0b000000100 & flagbits,
            "SYN": 0b000000010 & flagbits,
            "FIN": 0b000000001 & flagbits,
            }
        flags = []
        for flag, bits in flag_dict.items():
            if bits:
                flags.append(flag)
        if flags != []:
            return ",".join(flags)
        else:
            return "--"

    def dump(self):
        print("TCP Header")
        print("-------------------")
        print(f"Source Port: {self.src_port}")
        print(f"Destination Port: {self.dst_port}")
        print(f"Sequence Number: {self.seq_num}")
        print(f"Aknowledgment Number: {self.ack_num}")
        print(f"Data Offset: {self.offset}")
        print(f"Flags: {self.flags}")
        print(f"Window Size: {self.window_size}")
        print(f"Checksum: {self.checksum}")
        print(f"Urgent Pointer: {self.urg_pointer}")

    def obj_hdr(self):
        hdr = tcp_hdr(self.src_port, self.dst_port, self.seq_num, self.ack_num,
                      self.offset, self.flags, self.window_size, self.checksum,
                      self.urg_pointer)
        return hdr

    def json_dump(self):
        return json.dumps(self.obj_hdr())

    def __str__(self):
        return f"""
        TCP Header
        -------------------
        Source Port: {self.src_port}
        Destination Port: {self.dst_port}
        Sequence Number: {self.seq_num}
        Aknowledgment Number: {self.ack_num}
        Data Offset: {self.offset}
        Flags: {self.flags}
        Window Size: {self.window_size}
        Checksum: {self.checksum}
        Urgent Pointer: {self.urg_pointer}
        """


class TCP_Packet:
    def __init__(self, frame):
        self.eth = Ethernet(frame)
        self.ip = IPv4Header(frame)
        self.tcp = TCPHeader(frame, self.ip)
        self.bytes = frame.__sizeof__() - self.tcp.offset
        self.total_header_size = self.eth.size + self.ip.internet_header_len + self.tcp.offset
        self.data_size = self.ip.total_len - self.tcp.size
        self.data = struct.unpack("!{}s".format(self.data_size), frame[-self.data_size:])[0]

    def dump(self):
        print(f"\nTCP Packet\nbytes {self.bytes}")
        print("----------------------------------------\n")
        self.eth.dump()
        print("\n")
        self.ip.dump()
        print("\n")
        self.tcp.dump()
        print("\n")

    def json_obj(self):
        hdrs = {}
        eth = self.eth.obj_hdr()
        ipv4 = self.ip.obj_hdr()
        tcp = self.tcp.obj_hdr()
        hdrs["eth"] = eth
        hdrs["ipv4"] = ipv4
        hdrs["tcp"] = tcp
        return hdrs

    def __str__(self):
        return f"""
        {str(self.eth)}
        {str(self.ip)}
        {str(self.tcp)}
        {xdump(self.data) if self.data != b"" else ""}
        """