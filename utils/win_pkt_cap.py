import re
import subprocess
from time import sleep


def win_pkt_cap(ip, proto="TCP", cap_time=120):
    subprocess.check_output(f"pktmon filter add -i {ip} -t {proto}", encoding="utf-8")
    subprocess.check_output("pktmon start --etw")
    sleep(cap_time)
    file_info = subprocess.check_output("pktmon stop", encoding="utf-8")
    #isolate log file info in output
    file_info = file_info.split("\n")[-2]
    #cut out log file path
    cap_file = file_info.split(" ")[2]
    res = subprocess.check_output(f"pktmon etl2txt {cap_file}", encoding="utf-8")
    print(res)
    

