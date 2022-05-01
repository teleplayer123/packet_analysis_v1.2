import json
import getpass
import os
import sys
from yaml import full_load

uid = os.getuid()
mode = 0o777 #poor permission security for ease of debugging, should be hardened
user = getpass.getuser()
data = {}
if user == "root":
    raise EnvironmentError("Do not run setup as root.")

if not os.path.exists("config.yaml"):
    yaml_template = \
"""
network:
  interface: "lo"
  type: 3
"""
    with open("config.yaml", "w") as fh:
        fh.write(yaml_template)

filename = "config.yaml"
umask = os.umask(0)
try:
    fd = os.open(filename, os.O_RDONLY, 0o400)
finally:
    os.umask(umask)

with os.fdopen(fd, "r") as ymlfile:
    netconf = full_load(ymlfile)


data["uid"] = uid
data["user"] = user
data["mode"] = mode 
data["interface"] = str(netconf["network"]["interface"])
data["type"] = int(netconf["network"]["type"])

cwd = os.getcwd()
config_dir = os.path.join(cwd, "config")
if not os.path.exists(config_dir):
    os.mkdir(config_dir)


with open("config/config.json", "w") as fp:
    json.dump(data, fp)

init_template = \
"""import json
with open("config/config.json", "r") as fp:
    data = json.load(fp)
USER = data["user"]
MODE = data["mode"]
UID = data["uid"]
INTERFACE = data["interface"]
TYPE = data["type"]"""

with open("config/__init__.py", "w") as fh:
    fh.write(init_template)