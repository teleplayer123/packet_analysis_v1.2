import struct
import socket

ETH_STRUCT = struct.Struct("!6B6BH")
ETHIP_STUCT = struct.Struct("!4s4sBBH")
IPv4_STRUCT = struct.Struct("!BBHHHBBH4s4s")
TCP_STRUCT = struct.Struct("!HHLLHHHH")
ICMP_STRUCT = struct.Struct("!BBHHH")