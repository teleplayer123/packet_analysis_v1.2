import json
import getpass
import os


uid = os.getuid()
mode = 0o777 #poor permission security for ease of debugging, should be hardened
user = getpass.getuser()
data = {}
if user == "root":
    raise EnvironmentError("Do not run setup as root.")


data["uid"] = uid
data["user"] = user
data["mode"] = mode 

cwd = os.getcwd()
config_dir = os.path.join(cwd, "config")
if not os.path.exists(config_dir):
    os.mkdir(config_dir)


with open("config/config.json", "w") as fp:
    json.dump(data, fp)