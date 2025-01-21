from collections import defaultdict
import json
import socket
import struct

from utils.packet_json import ethr_hdr, ip_hdr, ipv6_hdr, tcp_hdr
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


class ARP_Packet:
    
    def __init__(self, frame):
        data = struct.unpack("!2H2BH6s4s6s4s", frame[14:42])
        self.hw_type =  self.hardware_type(data[0])
        self.proto = self.proto_type(data[1])
        self.hw_len = data[2]
        self.proto_len = data[3]
        self.opcode = self.opcode_type(data[4])
        self.sender_hw_addr = self.fmt_mac(data[5])
        self.sender_ip_addr = socket.inet_ntoa(data[6])
        self.target_hw_addr = self.fmt_mac(data[7])
        self.target_ip_addr = socket.inet_ntoa(data[8])

    def fmt_mac(self, data):
        bs = ["%02x" % data[i] for i in range(len(data))]
        return ":".join(bs)

    def hardware_type(self, bits):
        hw = ""
        hw_types = {
            "Ethernet": 1,
            "Experimental Ethernet": 2,
            "Radio": 3,
            "Proteon ProNet Token Ring": 4,
            "Chaos": 5,
            "IEEE 802 Networks": 6,
            "ARCNET": 7,
            "Hyperchannel": 8,
            "Lanstar": 9,
            "Autonet Short Address": 10,
            "LocalTalk": 11,
            "LocalNet": 12,
            "Ultra Link": 13,
            "SMDS": 14,
            "Frame Relay": 15,
            "Asyncronous Transmission Mode (ATM)": 16,
            "HDLC": 17,
            "Fibre Channel": 18,
            "ATM": 19,
            "Serial Line": 20,
            "ATM (Asynchronous Transmission Mode)": 21,
            "MIL-STD-188-220": 22,
            "Metricom": 23,
            "IEEE 1394.1995": 24,
            "MAPOS": 25,
            "Twinaxial": 26,
            "EUI-64": 27,
            "HIPARP": 28,
            "IP and ARP over ISO 7816-3": 29,
            "ARPSec": 30,
            "IPsec Tunnel": 31,
            "InfiniBand": 32,
            "TIA-102 Project 25 Common Air Interface (CAI)": 33,
            "Wiegand Interface": 34,
            "Pure IP": 35,
            "HW_EXP1": 36,
            "HFI": 37,
            "HW_EXT2": 256,
            "AEthernet": 257,
        }
        for k, v in hw_types.items():
            if int(bits) == v:
                hw = k
                break
        if hw in hw_types.keys():
            return hw, hw_types[hw]
        else:
            return "Unassigned/Reserved", bits

    def opcode_type(self, bits):
        op_type = ""
        ops = {
            "Request": 1,
            "Reply": 2
        }
        for k, v in ops.items():
            if bits == v:
                op_type = k
                break
        if op_type in ops.keys():
            return op_type, ops[op_type]
        else:
            return op_type, int(bits)

    def proto_type(self, bits):
        proto = ""
        proto_types = {
            "IPv4 (Internet Protocol version 4)": 0x0800,
            "ARP (Address Resolution Protocol)": 0x0806,
            "WoL (Wake-On-LAN)": 0x0842,
            "AVTP (Audio Video Transport Protocol)": 0x22f0,
            "IETF (Internet Engineering Task Force) TRILL (Transparent Interconnection of Lots of Links) Protocol": 0x22f3,
            "SRP (Stream Reservation_Protocol)": 0x22ea,
            "DEC (Digital Equipment Corporation) MOP (Maintenance Operation Protocol) RC": 0x6002,
            "DECnet Phase IV, DNA Routing": 0x6003,
            "DEC ((Digital Equipment Corporation) LAT (Local Area Transport)": 0x6004,
            "RARP (Reverse Address Resolution Protocol)": 0x8035,
            "AppleTalk(Ethertalk)": 0x809b,
            "AARP (AppleTalk Address Resolution Protocol)": 0x80f3, 
            "VLAN-tagged frame and SPB (Shortest Path Bridging) with NNI (Network-to-Network Interface) compatibility": 0x8100,
            "SLPP (Simple Loop Prevention Protocol)": 0x8102,
            "VLACP (Virtual Link Aggregation Control Protocol)": 0x8103,
            "IPX (Internetwork Packet Exchange)": 0x8137,
            "QNX Qnet": 0x8204,
            "IPv6 (Internet Protocol version 6)": 0x86DD,
            "Ethernet Flow Control": 0x8808,
            "LACP (Link Aggregation Control Protocol)": 0x8809,
            "CobraNet": 0x8819,
            "MPLS (Multiprotocol Label Switching) unicast": 0x8847,
            "MPLS (Multiprotocol Label Switching) multicast": 0x8848,
            "PPPoE (Point-to-Point Protocol over Ethernet) Discovery Stage": 0x8863,
            "PPPoE (Point-to-Point Protocol over Ethernet) Session Stage": 0x8864,
            "HomePlug 1.0 MME": 0x887b,
            "EAPOL (Extensible Authentication Protocol over LAN)": 0x888e,
            "PROFINET Protocol": 0x8892,
            "HyperSCSI": 0x889a,
            "AoE (Advanced Technology Attachment over Ethernet)": 0x88a2,
            "EtherCAT Protocol": 0x88a4,
            "Service VLAN tag identifier on Q-in-Q tunnel": 0x88a8,
            "Ethernet Powerlink": 0x88ab,
            "GOOSE (Generic Object Oriented Substation Event)": 0x88b8,
            "GSE (Generic Substation Events) Managment Services": 0x88b9,
            "SV (Sampled Value Transmission)": 0x88ba,
            "LLDP (Link Layer Discovery Protocol)": 0x88cc,
            "SERCOS III": 0x88cd,
            "MRP (Media Redundancy Protocol)": 0x88e3,
            "MACsecd (MAC security)": 0x88e5,
            "PBB (Provider Backbone Bridges)": 0x88e7,
            "PTP (Precision Time Protocol) over Ethernet": 0x88f7,
            "NC-SI (Network Controller Sideband Interface)": 0x88f8,
            "PRP (Parallel Redundancy Protocol)": 0x88fb,
            "CFM (Connectivity Fault Management) Protocol": 0x8902,
            "FCoE (Fiber Channel over Ethernet)": 0x8906,
            "FCoE Initialization Protoco": 0x8914,
            "RoCE (RDMA (Remote Direct Memory Access) over Converged Ethernet)": 0x8915,
            "TTE (Time-Triggered Ethernet) Protocol Control Frame": 0x891d,
            "1905.1 IEEE Protocol": 0x893a,
            "HSR (High-availability Seamless Redundancy)": 0x892f,
            "Ethernet Configuration Testing Protocol": 0x9000,
            "VLAN-tagged frame with double tagging": 0x9100,
            "Redundancy Tag": 0xf1c1
        }
        for k, v in proto_types.items():
            if bits == v:
                proto = k
                break
        return proto, proto_types[proto]

    def __str__(self):
        return f"""
        ARP Header
        ------------------
        Hardware Type: {self.hw_type[0]} ({hex(self.hw_type[1])})
        Protocol Type: {self.proto[0]} ({self.proto[1]})
        Hardware Address Length: {int(self.hw_len)}
        Protocol Type Length: {int(self.proto_len)}
        Operation Code: {self.opcode[0]} ({hex(self.opcode[1])})
        Sender HW Address: {self.sender_hw_addr}
        Sender IP Address: {self.sender_ip_addr}
        Target HW Address: {self.target_hw_addr}
        Target IP Address: {self.target_ip_addr} 
        """


class IPv4Header:

    def __init__(self, frame):
        hstr = frame[14:34]
        iph = struct.unpack("!BBHHHBBH4s4s", hstr)
        self.size = struct.calcsize("!BBHHHBBH4s4s")
        self.version = iph[0] >> 4
        self.internet_header_len = (iph[0] & 0b1111) * 4 #internet header length measure in 32bit words (i.e. 32bits = 1)
        self.dscp = self.get_dscp(iph[1] >> 2)
        self.explicit_congestion = self.get_ecn(iph[1] & 0b11)
        self.total_len = iph[2]  #total length of header including data in octets
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


class TCPIP_Packet:

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

