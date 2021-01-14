#!/usr/bin/python3.9

from collections import defaultdict
from datetime import date
import json
import logging
import os
import re
import socket
import sys
from time import time, asctime, localtime

from protocols import Ethernet, IPv4Header, IPv6Header, TCP_Packet
from icmpv6 import ICMPv6_Packet
try:
    from config import USER, MODE
except ImportError as err:
    print("Run setup.py first.")
    sys.exit(0)

logger = logging.Logger(__name__)
logger.setLevel(logging.DEBUG)
handle = logging.FileHandler("log/pcap_exception.log")
logger.addHandler(handle)

save_flag = False
json_flag = False
print_flag = False
filter_port = False
filter_addr = False
filter_proto = False

usage = """
    options {
        -f[args]:   filters and saves packets in text file based on given args
        -j:         saves packet capture in json file
        -p:         prints packets to console
        -s:         saves packet capture in text file
    }

    args {
        -f:         port=[port number]
                    addr=[ip address]
                    proto=[protocol]

            protocols: eth, ipv4, ipv6, icmpv6, tcp
    }
"""
if len(sys.argv) > 1:
    args = sys.argv[1:]
    for i in range(len(args)):
        if args[i] == "-s":
            save_flag = True
        elif args[i] == "-p":
            print_flag = True
        elif args[i] == "-j":
            json_flag = True
        elif args[i] == "-f":
            fargs = args[i+1:]
            for arg in fargs:
                if re.match(r"[\s]*addr=[\d.\d.\d.\d]*?[\s]*", arg):
                    faddr = arg.split("=")[1]
                    filter_addr = True
                elif re.match(r"port=\d", arg):
                    fport = arg.split("=")[1]
                    filter_port = True
                elif re.match(r"proto=\w", arg):
                    fproto = arg.split("=")[1]
                    filter_proto = True
else:
    print(usage)

current_date = date.fromtimestamp(time())
cap_dir = "/home/{}/captures".format(USER)
dumpdir = "/home/{}/captures/{}".format(USER, current_date)
dumptimedir = dumpdir + "/{}".format(asctime(localtime()))

if not os.path.exists(cap_dir):
    os.mkdir(cap_dir)
    os.chmod(cap_dir, MODE)

if not os.path.exists(dumpdir):
    os.mkdir(dumpdir)
    os.chmod(dumpdir, MODE)

if not os.path.exists(dumptimedir):
    os.mkdir(dumptimedir)
    os.chmod(dumptimedir, MODE)

filter_packets = defaultdict(list)
tcp_packet_by_src_dst = defaultdict(list)
ipv4_packet_by_src_dst = defaultdict(list)
ipv6_packet_by_src_dst = defaultdict(list)
ipv6_json_pkt_dump = defaultdict(list)
tcp_json_pkt_dump = defaultdict(list)

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("wlp2s0", 3))

try: 
    while True:
        try:
            data = s.recv(65565)
            e = Ethernet(data)
            if filter_proto == True and str(fproto).lower() == "eth":
                filter_packets["eth"].append(str(e))
            if e.etype[0] == "IPv4":
                ipv4 = IPv4Header(data)
                tcp = TCP_Packet(data)
                if save_flag == True:
                    ipv4_packet_by_src_dst[(ipv4.src_addr, ipv4.dst_addr)].append(str(ipv4))
                    tcp_packet_by_src_dst[(tcp.ip.src_addr, tcp.ip.dst_addr)].append(str(tcp))
                if filter_addr == True:
                    if filter_port == True:
                        if tcp.ip.dst_addr == faddr and tcp.tcp.dst_port == int(fport):
                            filter_packets[(faddr, fport)].append(str(tcp))
                    else:
                        if tcp.ip.dst_addr == faddr:
                            filter_packets[faddr].append(str(tcp))
                if filter_port == True:
                    if tcp.tcp.dst_port == fport:
                        filter_packets[str(fport)].append(str(tcp))
                if filter_proto == True:
                    if str(fproto).lower() == "ipv4":
                        filter_packets["ipv4"].append(str(ipv4))
                    elif str(fproto).lower() == "tcp":
                        filter_packets["tcp"].append(str(tcp.tcp))
                if print_flag == True:
                    print(str(tcp))
                if json_flag == True:
                    tcp_json_pkt_dump[(str(tcp.ip.src_addr) + "," + str(tcp.ip.dst_addr))].append(tcp.json_obj())
            if e.etype[0] == "IPv6":
                ipv6 = IPv6Header(data)
                if save_flag == True:
                    ipv6_packet_by_src_dst[(ipv6.src_addr, ipv6.dst_addr)].append(str(ipv6))
                if json_flag == True:
                    ipv6_json_pkt_dump[(str(ipv6.src_addr) + "," + str(ipv6.dst_addr))].append(ipv6.json_obj())
                if print_flag == True:
                    print(str(ipv6))
                if filter_proto == True and str(fproto).lower() == "ipv6":
                    filter_packets["ipv6"].append(str(ipv6))
                if ipv6.next_header[1] == 58:
                    icmpv6 = ICMPv6_Packet(data)
                    if filter_proto == True and str(fproto).lower() == "icmpv6":
                        filter_packets["icmpv6"].append(str(icmpv6))
                    if save_flag == True:
                        ipv6_packet_by_src_dst[(ipv6.src_addr, ipv6.dst_addr)].append(str(icmpv6))
                    if print_flag == True:
                        print(str(icmpv6))
        except Exception as err:
            print(err)
            logger.debug(err)
        except KeyboardInterrupt:
            break
except KeyboardInterrupt:
    if s:
        s.close()
except Exception as err:
    print(err)
finally:
    if save_flag == True:
        text_dumpdir = dumptimedir + "/text"
        if not os.path.exists(text_dumpdir):
            os.mkdir(text_dumpdir)
            os.chmod(text_dumpdir, MODE)
        if len(tcp_packet_by_src_dst) > 0:
            for i, ps in tcp_packet_by_src_dst.items():
                fn = text_dumpdir + "/{}".format(i)
                with open(fn, "w") as fh:
                    for p in ps:
                        fh.write(p)
                        fh.write("\n")
        if len(ipv6_packet_by_src_dst) > 0:
            for i, ps in ipv6_packet_by_src_dst.items():
                fn = text_dumpdir + "/{}".format(i)
                with open(fn, "w") as fh:
                    for p in ps:
                        fh.write(p)
                        fh.write("\n") 
    if json_flag == True:
        json_dumpdir = dumptimedir + "/json"
        if not os.path.exists(json_dumpdir):
            os.mkdir(json_dumpdir)
            os.chmod(json_dumpdir, MODE)
        if len(tcp_json_pkt_dump) > 0:
            for addrs, ps in tcp_json_pkt_dump.items():
                fn = json_dumpdir + "/{}.json".format(addrs)
                with open(fn, "w") as fp:
                    json.dump(tcp_json_pkt_dump[addrs], fp)
        if len(ipv6_json_pkt_dump) > 0:
            for addrs, ps in ipv6_json_pkt_dump.items():
                fn = json_dumpdir + "/{}.json".format(addrs)
                with open(fn, "w") as fp:
                    json.dump(ipv6_json_pkt_dump[addrs], fp)
    if len(filter_packets) > 0:
        filter_dir = dumptimedir + "/filtered"
        if not os.path.exists(filter_dir):
            os.mkdir(filter_dir)
            os.chmod(filter_dir, MODE)
        for addr, ps in filter_packets.items():
            fn = filter_dir + "/{}".format(addr)
            with open(fn, "w") as fh:
                for p in ps:
                    fh.write(p)
                    fh.write("\n")
                
    sys.exit()