import struct

from utils.hex_dump import xdump

MAX_ERR_MSG_SIZE = 4608
ETH_HDR_LEN = 14

class ICMP_Packet:

    def __init__(self, frame, ihl):
        self.type = struct.unpack("!B", frame[ihl+ETH_HDR_LEN:ihl+ETH_HDR_LEN+1])[0]
        if self.type == 3:
            self.icmp_hdr = ICMP_DestinationUnreachable(frame, ihl)
        elif self.type == 8 or self.type == 0:
            self.icmp_hdr = ICMP_EchoReply(frame, ihl)

    def __str__(self):
        return str(self.icmp_hdr)



class ICMP_DestinationUnreachable:

    def __init__(self, frame, ihl):
        data = struct.unpack("!BBHL", frame[ihl+ETH_HDR_LEN:ihl+ETH_HDR_LEN+8])
        self.type = ("Destination Unreachable", data[0])
        self.code = self.get_code(data[1])
        self.checksum = data[2]
        self.unused = data[3]
        self.msg_data = struct.unpack("!{}s".format(len(frame[ihl+ETH_HDR_LEN+8:])), frame[ihl+ETH_HDR_LEN+8:])

    def get_code(self, code):
        msg = ""
        code_dict = {
            "Net Unreachable": 0,
            "Host Unreachable": 1,
            "Protocol Unreachable": 2, 
            "Port Unreachable": 3,
            "Fragmentation needed and DF set": 4,
            "Source Route Failed": 5
        }
        for k, v in code_dict.items():
            if code == v:
                msg = k
                break
        return msg, code

    def __str__(self):
        return f"""
        Type: {self.type[0]} ({self.type[1]})
        Code: {self.code[0]} ({self.code[1]})
        Checksum: {self.checksum}
        Unused: {self.unused}
        message:
        {xdump(self.msg_data)}
        """


class ICMP_EchoReply:

    def __init__(self, frame, ihl):
            data = struct.unpack("!BBHHH", frame[ihl+ETH_HDR_LEN:ihl+ETH_HDR_LEN+8])
            self.type = self.get_type(data[0])
            self.code = data[1]
            self.checksum = data[2]
            self.identifier = data[3]
            self.seq_number = data[4]
            mdata = frame[ihl+ETH_HDR_LEN+8:]
            self.msg_data = struct.unpack("!{}s".format(len(mdata)), mdata)[0]

    def get_type(self, t):
        if t == 8:
            return "Echo Message", t
        elif t == 0:
            return "Echo Reply Message", t
        else:
            return "Error", t

    def __str__(self):
        return f"""
        ICMPv4
        ----------------------------------
        Type: {self.type[0]} ({self.type[1]})
        Code: {self.code}
        Checksum: {self.checksum}
        Identifier: {self.identifier}
        Sequence Number: {self.seq_number}
        Message Data:
        {xdump(self.msg_data)}
        """    