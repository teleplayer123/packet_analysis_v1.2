import struct

from utils.hex_dump import xdump
from utils.checksum import verify_checksum

"""
Notes:
    Neighbor Discovery:
        * neighbor discovery in ipv6 is what ARP is to ipv4.
        * ipv6 has no broadcasts, it uses multicasts frequently.
        * neighbor advertisement and solicitation use multicast to discover other systems.
        * router advertisement and solicitation use multicast to discover other routers.
    Addresses:
        * localhost - ::1/128
        * Unique Local Addresses(ULA) - fc00::/7  (equivelant ipv4 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        * Link-Local Adressess - fe80::/10  (equivelant ipv4 169.254.0.0/16)
        * Global Addresss(Teredo) - 2001::1000::/32
        * Global Addresses(6to4) - 2002::/16
"""


class ICMPv6_Packet:

    ERROR_NUMS = {1, 2, 3, 4, 100, 101, 127}

    def __init__(self, frame):
        icmp6_struct = struct.Struct("!BBH4s")
        data = icmp6_struct.unpack(frame[54:62])
        self.type = self.get_type(data[0])
        
        if self.type[1] in self.ERROR_NUMS:
            self.next_header = ICMPv6_Error(frame)
        elif self.type[1] in {128, 129}:
            self.next_header = ICMPV6_EchoRequestReply(frame)
        elif self.type[1] == {130, 131, 132}:
            self.next_header = ICMPv6_MulticastListenerDiscovery(frame)
        elif self.type[1] == 133:
            self.next_header = ICMPv6_RouterSolicitation(frame)
        elif self.type[1] == 134:
            self.next_header = ICMPv6_RouterAdvertisment(frame)
        elif self.type[1] == 135:
            self.next_header = ICMPv6_NeighborSolicitation(frame)
        elif self.type[1] == 136:
            self.next_header = ICMPv6_NeighborAdvertisment(frame)
        elif self.type[1] == 137:
            self.next_header = ICMPv6_RedirectMessage(frame)
        else:
            self.next_header = self.type[0]

    def get_type(self, bits):
        flag = ""
        type_dict = {
            "ERROR: Destination Unreachable": 1,
            "ERROR: Packet Too Big": 2,
            "ERROR: Time Exceeded": 3,
            "ERROR: Parameter Problem": 4,
            "ERROR: Private Experimentation0": 100,
            "ERROR: Private Experimentation1": 101,
            "INFO: Reserved for expansion of error nessages": 127,
            "INFO: Echo Request": 128,
            "INFO: Echo Reply": 129,
            "INFO: Multicast Listener Query": 130,
            "INFO: Multicast Listener Report": 131,
            "INFO: Multicast Listener Done": 132,
            "INFO: Router Solicitation": 133,
            "INFO: Router Advertisment": 134,
            "INFO: Neighbor Solicitation": 135,
            "INFO: Neighbor Advertisment": 136,
            "INFO: Redirect Message": 137,
            "INFO: Router Renumbering": 138,
            "INFO: ICMP Node Information Query": 139,
            "INFO: ICMP Node Information Response": 140,
            "INFO: Private Experimentation0": 200,
            "INFO: Private Experimentation1": 201
        }
        for k, v in type_dict.items():
            if bits == v:
                flag = k
                break
        if flag == "":
            return "Unknown", bits
        return flag, type_dict[flag]

    def format_ipv6(self, bits):
        ipv6 = ":".join(["%04x" %bits[i] for i in range(len(bits))])
        return str(ipv6)

    def fmt_mac(self, data):
        bs = ["%02x" % data[i] for i in range(len(data))]
        return ":".join(bs)

    def data_dump(self, data):
        return xdump(data)

    def __str__(self):
        return str(self.next_header)


class ICMPv6_Error:

    def __init__(self, frame):
        icmp6_struct = struct.Struct("!BBH4s")
        data = icmp6_struct.unpack(frame[54:62])
        self.type = self.get_type(data[0])
        self.checksum = data[2]
        if self.type[1] == 1:
            self.code = self.get_type1_code(data[1])
            self.msg = ("Unused", data[3])
        elif self.type[1] == 2:
            self.code = ("Zero", data[1])
            self.msg = ("MTU of next-hop link", data[3])
        elif self.type[1] == 3:
            self.code = self.get_type3_code(data[1])
            self.msg = ("Unused", data[3])
        elif self.type[1] == 4:
            self.code = self.get_type4_code(data[1])
            self.msg = ("Pointer", data[3])

    def get_type(self, bits):
        flag = ""
        type_dict = {
            "Destination Unreachable": 1,
            "Packet Too Big": 2,
            "Time Exceeded": 3,
            "Parameter Problem": 4,
            "Private Experimentation0": 100,
            "Private Experimentation1": 101,
            "Reserved for expansion of error nessages": 127
        }
        for k, v in type_dict.items():
            if bits == v:
                flag = k
                break
        if flag == "":
            return "Unknown", bits
        return flag, type_dict[flag]

    def format_ipv6(self, bits):
        ipv6 = ":".join(["%04x" %bits[i] for i in range(len(bits))])
        return str(ipv6)

    def get_type1_code(self, bits):
        flag = ""
        code_dict = {
            "No route to destination": 0,
            "Communication with destination administratively prohibited": 1,
            "Beyond scope of source address": 2,
            "Address unreachable": 3,
            "Port unreachable": 4,
            "Source address failed ingress/egress policy": 5,
            "Reject route to destination": 6
        }
        for k, v in code_dict.items():
            if bits == v:
                flag = k
                break
        return flag, code_dict[flag]
    
    def get_type3_code(self, bits):
        flag = ""
        code_dict = {
            "Hop limit exceeded in transit": 0,
            "Fragment reassembly time exceeded": 1
        }
        for k, v in code_dict.items():
            if bits == v:
                flag = k
                break
        return flag, code_dict[flag]

    def get_type4_code(self, bits):
        flag = ""
        code_dict = {
            "Erroneous header field encountered": 0,
            "Unrecognized Next header type encountered": 1,
            "Unrecognized IPv6 option encountered": 2
        }
        for k, v in code_dict.items():
            if bits == v:
                flag = k
                break
        return flag, code_dict[flag]

    def __str__(self):
        return f"""
        ICMPv6
        ---------------------------------
        Type: {self.type[0]} ({hex(self.type[1])})
        Code: {self.code[0]} ({self.code[1]})
        Checksum: {self.checksum}
        Message Body: {self.msg[0]} ({hex(self.msg[1])})
        """


class ICMPV6_EchoRequestReply:
    def __init__(self, frame):
        data = struct.unpack("!BBHHH", frame[54:62])
        if data[0] == 128:
            self.type = ("Echo Request Message", data[0])
        if data[0] == 129:
            self.type = ("Echo Reply Message", data[0]) 
        self.code = data[1] 
        self.checksum = data[2]
        self.identifier = data[3]
        self.seq_num = data[4]
        self.arbitrary_data = ""

        try:
            self.arbitrary_data_len = len(frame[62:])
            self.arbitrary_data = struct.unpack("!{}s".format(self.arbitrary_data_len), frame[62:])[0]
        except (struct.error, TypeError, EnvironmentError) as err:
            print("ERROR: icmpv6 echo reply request: " + str(err))

    def __str__(self):
        return f"""
        ICMPv6 
        ---------------------
        Type: {self.type[0]} ({self.type[1]})
        Code: {self.code}
        Checksum: {self.checksum}
        Identifier: {self.identifier}
        Sequence Number: {self.seq_num}
        Arbitrary Data: 
        {xdump(self.arbitrary_data) if self.arbitrary_data != "" else ""}
       """ 


class ICMPv6_MulticastListenerDiscovery:

    def __init__(self, frame):
        data = struct.unpack("!BB11H", frame[54:78])
        if data[0] == 130:
            self.type = ("Multicast Listener Query", data[0])
        if data[0] == 131:
            self.type = ("Multicast Listener Report", data[0])
        if data[0] == 132:
            self.type = ("Multicast Listener Done", data[0])
        self.code = data[1]
        self.checksum = data[2]
        self.max_delay_resp = data[3]
        self.reserved = data[4]
        self.multicast_addr = self.format_ipv6(data[5:12])
    
    def format_ipv6(self, bits):
        ipv6 = ":".join(["%04x" %bits[i] for i in range(len(bits))])
        return str(ipv6)

    def __str__(self):
        return f"""
        ICMPv6
        ------------------------------------
        Type: {self.type[0]} ({self.type[1]})
        Code: {self.code}
        Checksum: {self.checksum}
        Maximum Response Delay: {self.max_delay_resp}
        Reserved: {self.reserved}
        Multicast Address: {self.multicast_addr}
        """


class ICMPv6_RouterSolicitation:

    def __init__(self, frame):
        data = struct.unpack("!BBH4s", frame[54:62])
        self.type = ("Router Solicitation", data[0])
        self.code = data[1]
        self.checksum = data[2]
        self.reserved = data[3]

        self.data_short_words = struct.unpack("!4H", frame[54:62])
        self.opt_type_len = ""

        try:
            self.opt_type_len = struct.unpack("!BB", frame[62:64])
        except (struct.error, TypeError, EnvironmentError):
            pass

        

    def format_ipv6(self, bits):
        ipv6 = ":".join(["%04x" %bits[i] for i in range(len(bits))])
        return str(ipv6)

    def __str__(self):
        return f"""
        ICMPv6
        -----------------------
        Type: {self.type[0]} ({self.type[1]})
        Code: {self.code}
        Checksum: {self.checksum}
        Reserved: {self.reserved}
        """


class ICMPv6_RouterAdvertisment:

    def __init__(self, frame):
        data = struct.unpack("!BBHBBH4s4s", frame[54:70])
        self.type = ("Router Advertisment", data[0])
        self.code = data[1]
        self.checksum = data[2]
        self.cur_hop_limit = data[3]
        self.M = data[4] >> 0x07 & 0b1
        self.O = data[4] >> 0x06 & 0b1
        self.reserved = data[4] & 0x3f
        self.router_lifetime = data[5]
        self.reachable_time = int.from_bytes(data[6], byteorder="big")
        self.retrans_time = int.from_bytes(data[7], byteorder="big")

        self.data_short_words = struct.unpack("!8H", frame[54:70])
        self.opt_type_len = ""

        try:
            self.opt_type_len = struct.unpack("!BB", frame[70:72])
        except (struct.error, TypeError, EnvironmentError):
            pass

    def __str__(self):
        return f"""
        ICMPv6
        -------------------------------------
        Type(134): {self.type[0]} ({self.type[1]})
        Code(0): {self.code}
        Checksum: {self.checksum}
        Cur Hop Limit: {self.cur_hop_limit}
        Managed Address Configuration: {self.M}
        Other Configuration: {self.O}
        Reserved(0): {self.reserved}
        Router Lifetime: {self.router_lifetime}
        Reachable Time: {self.reachable_time}
        Retrans Time: {self.retrans_time}
        """


class ICMPv6_NeighborSolicitation:

    def __init__(self, frame):
        data = struct.unpack("!BBH4s8H", frame[54:78])
        self.type = ("Neighbor Solicitation", data[0])
        self.code = data[1]
        self.checksum = data[2]
        self.reserved = data[3]
        self.target_addr = self.format_ipv6(data[4:11])

        self.data_short_words = struct.unpack("!12H", frame[54:78])
        self.opt_type_len = ""

        try:
            self.opt_type_len = struct.unpack("!BB", frame[78:80])
        except (struct.error, TypeError, EnvironmentError):
            pass

        if self.opt_type_len is not None:
            self.opt_hdr = ND_OptHdrs(self.opt_type_len[0], self.opt_type_len[1], frame, 80)

    def format_ipv6(self, bits):
        ipv6 = ":".join(["%04x" %bits[i] for i in range(len(bits))])
        return str(ipv6)

    def __str__(self):
        return f"""
        ICMPv6
        -----------------------------
        Type(135): {self.type[0]} ({self.type[1]})
        Code(0): {self.code}
        Checksum: {self.checksum}
        Reserved(0): {self.reserved}
        Target Address: {self.target_addr}

        {self.opt_hdr.opt_hdr if self.opt_type_len != "" else ""}
        """


class ICMPv6_NeighborAdvertisment:

    def __init__(self, frame):
        data = struct.unpack("!BBH4s8H", frame[54:78])
        self.type = ("Neighbor Advertisment", data[0])
        self.code = data[1]
        self.checksum = data[2]
        resv = int.from_bytes(data[3], byteorder="big")
        self.router_flag = (resv >> 31) & 0b1
        self.solicited_flag = (resv >> 30) & 0b1
        self.override_flag = (resv >> 29) & 0b1
        self.reserved = resv & 0x1fffffff   
        self.target_addr = self.format_ipv6(data[4:11])

        self.data_short_words = struct.unpack("!12H", frame[54:78])
        self.opt_type_len = ""

        try:
            self.opt_type_len = struct.unpack("!BB", frame[78:80])
        except (struct.error, TypeError, EnvironmentError):
            pass

    def format_ipv6(self, bits):
        ipv6 = ":".join(["%04x" %bits[i] for i in range(len(bits))])
        return str(ipv6)

    def __str__(self):
        return f"""
        ICMPv6
        ---------------------------
        Type(136): {self.type[0]} ({self.type[1]})
        Code(0): {self.code}
        Checksum: {self.checksum}
        Router Flag({"set" if self.router_flag == 1 else "not set"}): {self.router_flag}
        Solicited Flag({"set" if self.solicited_flag == 1 else "not set"}): {self.solicited_flag}
        Override Flag({"set" if self.override_flag == 1 else "not set"}): {self.override_flag}
        Reserved(0): {self.reserved}
        Target Address: {self.target_addr}
        """


class ICMPv6_RedirectMessage:

    def __init__(self, frame):
        data = struct.unpack("!BBHL8H8H", frame[54:94])
        self.type = ("Redirect Message", data[0])
        self.code = data[1]
        self.checksum = data[2]
        self.reserved = data[3]
        self.target_addr = self.format_ipv6(data[4])
        self.dst_addr = self.format_ipv6(data[5])

        self.data_short_words = struct.unpack("!20H", frame[54:94])
        self.opt_type_len = ""

        try:
            self.opt_type_len = struct.unpack("!BB", frame[94:96])
        except struct.error:
            pass

    def format_ipv6(self, bits):
        ipv6 = ":".join(["%04x" %bits[i] for i in range(len(bits))])
        return str(ipv6)

    def __str__(self):
        return f"""
        ICMPv6
        ----------------------
        Type(137): {self.type[0]} ({self.type[1]})
        Code(0): {self.code}
        Checksum: {self.checksum}
        Reserved(0): {self.reserved}
        Target Address: {self.target_addr}
        Destination Address: {self.dst_addr}
        """


class ND_OptHdrs:

    ND_OPTS = {
        1: "SRC_LINK_ADDR",
        2: "TRGT_LINK_ADDR",
        3: "PREFIX_INFO",
        4: "REDIRECT_HDR",
        5: "MTU"
    }

    def __init__(self, htype, length, buff, buff_start):
        call_dict = {
            "SRC_LINK_ADDR":  lambda self, *args: self.get_link_layer_addr(*args),
            "TRGT_LINK_ADDR": lambda self, *args: self.get_link_layer_addr(*args),
            "PREFIX_INFO": lambda self, *args: self.get_prefix_info(*args),
            "REDIRECT_HDR": lambda self, *args: self.get_redirect_hdr(*args),
            "MTU": lambda self, *args: self.get_mtu(*args)
        } 
        self.opt_hdr = None

        for k, v in self.ND_OPTS.items():
            if htype == k:
                self.opt_hdr = call_dict[v](self, htype, length, buff, buff_start)
                break
        if self.opt_hdr is None:
            self.opt_hdr = "No known option headers."

    def format_ipv6(self, bits):
        ipv6 = ":".join(["%04x" %bits[i] for i in range(len(bits))])
        return str(ipv6)

    def fmt_mac(self, data):
        bs = ["%02x" % data[i] for i in range(len(data))]
        return ":".join(bs)

    def get_link_layer_addr(self, htype, length, buff, buff_start):
        if htype == 1:
            htype = ("Source Link-Layer Address", htype)
        elif htype == 2:
            htype = ("Target Link-Layer Address", htype)
        else:
            htype = ("Unknown type", htype)
        addr_len = (length * 8) - 2 
        addr = struct.unpack("!{}s".format(addr_len), buff[buff_start:buff_start + addr_len])[0]
        addr = self.fmt_mac(addr)
        return f"""
        ICMPv6 Options
        ---------------------
        Type: {htype[0]} ({hex(htype[1])})
        Length: {length}
        Link-Layer Address: {addr}
        """

    def get_prefix_info(self):
        pass

    def get_redirect_hdr(self):
        pass

    def get_mtu(self):
        pass