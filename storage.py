from datetime import date
import json
import os
from time import time, asctime, localtime

from config import USER, MODE
from protocols import IPv4Header, IPv6Header, TCPIP_Packet, TCPHeader
from icmpv6 import ICMPv6_Packet

class Storage:

    def __init__(self):
        current_date = date.fromtimestamp(time())
        cap_dir = "/home/{}/captures".format(USER)
        dumpdatedir = "/home/{}/captures/{}".format(USER, current_date)
        self.dumpdir = dumpdatedir + "/{}".format(asctime(localtime()))

        if not os.path.exists(cap_dir):
            os.mkdir(cap_dir)
            os.chmod(cap_dir, MODE)

        if not os.path.exists(dumpdatedir):
            os.mkdir(dumpdatedir)
            os.chmod(dumpdatedir, MODE)

        if not os.path.exists(self.dumpdir):
            os.mkdir(self.dumpdir)
            os.chmod(self.dumpdir, MODE)

    def save_text(self, hdr_dict):
        text_dumpdir = self.dumpdir + "/text"
        if not os.path.exists(text_dumpdir):
            os.mkdir(text_dumpdir)
            os.chmod(text_dumpdir, MODE)
        if len(hdr_dict) > 0:
            for i, ps in hdr_dict.items():
                fn = text_dumpdir + "/{}".format(i)
                with open(fn, "w") as fh:
                    for p in ps:
                        fh.write(p)
                        fh.write("\n")

    def save_json(self, hdr_dict):
        json_dumpdir = self.dumpdir + "/json"
        if not os.path.exists(json_dumpdir):
            os.mkdir(json_dumpdir)
            os.chmod(json_dumpdir, MODE)
        if len(hdr_dict) > 0:
            for addrs, ps in hdr_dict.items():
                fn = json_dumpdir + "/{}.json".format(addrs)
                with open(fn, "w") as fp:
                    json.dump(ps, fp)