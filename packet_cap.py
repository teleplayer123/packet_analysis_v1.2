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

from protocols import Ethernet, IPv4Header, IPv6Header, TCPIP_Packet, ARP_Packet
from icmp import ICMP_Packet
from icmpv6 import ICMPv6_Packet
try:
    from config import USER, MODE, INTERFACE, TYPE
except ImportError as err:
    print("Run setup.py first.")
    sys.exit(0)

logger = logging.Logger(__name__)
logger.setLevel(logging.DEBUG)

if not os.path.exists("log"):
    os.mkdir("log")
handle = logging.FileHandler("log/pktcap_exception.log")
fmt = logging.Formatter(fmt="%(asctime)s - %(levelname)s - %(module)s - %(message)s")
handle.setFormatter(fmt)
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

            protocols: eth, ipv4, icmpv4, ipv6, icmpv6, tcp
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
                    fproto_dic = {
                        "eth": False,
                        "ipv4": False,
                        "icmpv4": False,
                        "ipv6": False,
                        "icmpv6": False,
                        "tcp": False,
                        "arp": False
                    }
                    fproto = arg.split("=")[1]
                    fproto = fproto.split(",")  
                    if len(fproto) > 1:
                        for p in fproto:
                            fproto_dic[p.lower()] = True
                    elif len(fproto) == 1:
                        fproto_dic[fproto[0]] = True
                    else:
                        print(usage)
            filter_proto = True
else:
    print(usage)
    sys.exit(1)

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
arp_packet_by_src_dst = defaultdict(list)
tcp_packet_by_src_dst = defaultdict(list)
ipv4_packet_by_src_dst = defaultdict(list)
ipv6_packet_by_src_dst = defaultdict(list)
ipv6_json_pkt_dump = defaultdict(list)
tcp_json_pkt_dump = defaultdict(list)

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind((INTERFACE, TYPE))


try: 
    while True:
        try:
            data = s.recv(65565)
            e = Ethernet(data)
            if filter_proto == True and str(fproto).lower() == "eth":
                filter_packets["eth"].append(str(e))
            if print_flag == True and filter_proto == True:
                if fproto == "eth":
                    print(str(e))
            if e.etype[0] == "IPv4":
                ipv4 = IPv4Header(data)
                if ipv4.protocol[1] == 1:
                    icmpv4 = ICMP_Packet(data, ipv4.internet_header_len)
                    if print_flag == True:
                        if filter_proto == True:
                            if fproto_dic["eth"] == True:
                                print(str(e))
                            if fproto_dic["ipv4"] == True:
                                print(str(ipv4))
                            if fproto_dic["icmpv4"] == True:
                                print(str(icmpv4))
                        else:
                            print(str(e))
                            print(str(ipv4))
                            print(str(icmpv4))
                    if save_flag == True:
                        ipv4_packet_by_src_dst[ipv4.src_addr].append(str(e))
                        ipv4_packet_by_src_dst[ipv4.src_addr].append(str(ipv4))
                        ipv4_packet_by_src_dst[ipv4.src_addr].append(str(icmpv4))
                elif ipv4.protocol[1] == 6:
                    tcp = TCPIP_Packet(data)
                    if print_flag == True:
                        if filter_proto == True:
                            if fproto_dic["eth"] == True:
                                print(str(e))
                            if fproto_dic["ipv4"] == True:
                                print(str(ipv4))
                            if fproto_dic["tcp"] == True:
                                print(str(tcp.tcp))
                        else:
                            print(str(tcp))
                    if save_flag == True:
                        ipv4_packet_by_src_dst[(tcp.ip.src_addr, tcp.ip.dst_addr)].append(str(tcp))
                if json_flag == True:
                    tcp_json_pkt_dump[(str(tcp.ip.src_addr) + "," + str(tcp.ip.dst_addr))].append(tcp.json_obj())
            elif e.etype[0] == "IPv6":
                ipv6 = IPv6Header(data)
                if save_flag == True:
                    ipv6_packet_by_src_dst[(ipv6.src_addr, ipv6.dst_addr)].append(str(ipv6))
                if json_flag == True:
                    ipv6_json_pkt_dump[(str(ipv6.src_addr) + "," + str(ipv6.dst_addr))].append(ipv6.json_obj())
                if print_flag == True:
                    if filter_proto == True:
                        if fproto_dic["ipv6"] == True:
                            print(str(ipv6))
                    else:
                        print(str(ipv6))
                if ipv6.next_header[1] == 58:
                    icmpv6 = ICMPv6_Packet(data)
                    if print_flag == True:
                        if filter_proto == True:
                            if fproto_dic["icmpv6"] == True:
                                print(str(icmpv6))
                        else:
                            print(str(icmpv6))
                    if save_flag == True:
                        ipv6_packet_by_src_dst[(ipv6.src_addr, ipv6.dst_addr)].append(str(icmpv6))
            elif e.etype[0] == "ARP":
                arp = ARP_Packet(data)
                if filter_proto == True:
                    if fproto_dic["arp"] == True:
                        #filter_packets["eth"].append(str(e))
                        filter_packets["arp"].append(str(arp))
                        if print_flag == True:
                            print(str(e))
                            print(str(arp))
                elif print_flag == True:
                    print(str(arp))
                if save_flag == True:
                    arp_packet_by_src_dst[(arp.sender_ip_addr, arp.target_ip_addr)].append(str(e))
                    arp_packet_by_src_dst[(arp.sender_ip_addr, arp.target_ip_addr)].append(str(arp))
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
        save_dir = dumptimedir + "/text"
        ipv4_dumpdir = save_dir + "/ipv4"
        ipv6_dumpdir = save_dir + "/ipv6"
        arp_dumpdir = save_dir + "/arp"
        if not os.path.exists(save_dir):
            os.mkdir(save_dir)
            os.chmod(save_dir, MODE)
        if len(ipv4_packet_by_src_dst) > 0:
            if not os.path.exists(ipv4_dumpdir):
                os.mkdir(ipv4_dumpdir)
                os.chmod(ipv4_dumpdir, MODE)
            for i, ps in ipv4_packet_by_src_dst.items():
                fn = ipv4_dumpdir + "/{}".format(i)
                with open(fn, "w") as fh:
                    for p in ps:
                        fh.write(p)
                        fh.write("\n")
        if len(arp_packet_by_src_dst) > 0:
            if not os.path.exists(arp_dumpdir):
                os.mkdir(arp_dumpdir)
                os.chmod(arp_dumpdir, MODE)
            for i, ps in arp_packet_by_src_dst.items():
                fn = arp_dumpdir + "/{}".format(i)
                with open(fn, "w") as fh:
                    for p in ps:
                        fh.write(p)
                        fh.write("\n")
        if len(ipv6_packet_by_src_dst) > 0:
            if not os.path.exists(ipv6_dumpdir):
                os.mkdir(ipv6_dumpdir)
                os.chmod(ipv6_dumpdir, MODE)
            for i, ps in ipv6_packet_by_src_dst.items():
                fn = ipv6_dumpdir + "/{}".format(i)
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