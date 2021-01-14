from collections import defaultdict
import os
import json
import threading
import sys

from config import USER
from packet import ip_hdr, ipv6_hdr, tcp_hdr, ethr_hdr

#todo

"""def load_file_data(path):
    data = None
    with open(path, "r") as fp:
        data = json.load(fp)
    return data

def parse_into_pkt_obj(path):
    ipv4_pkts = defaultdict(list)
    ipv6_pkts = defaultdict(list)

    pkt_data = load_file_data(path)
    

def parse_json_dir(json_dir):
    pkts_by_src_dst = defaultdict(list)
    json_pkts_by_type = defaultdict(list)
    d = None
    for k, v in json_dir.items():
        d = load_file_data(v)
        for i in d:
            pkts_by_src_dst[k].append(i)
    print(pkts_by_src_dst["10.0.0.6,13.224.8.62"])

cap_dir = "/home/{}/captures".format(USER)
json_files_by_dirname = defaultdict(dict)
dirnames = []

for dirname in os.listdir(cap_dir):
    dirnames.append(dirname)

for dirname in dirnames:
    path = os.path.join(cap_dir, dirname, "json")
    for filename in os.listdir(path):
        json_files_by_dirname[dirname][filename.strip(".json")] = os.path.join(path, filename)

files = json_files_by_dirname["2021-01-02"]#["10.0.0.174,13.224.8.101"]
parse_json_dir(files)"""