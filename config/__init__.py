import json

with open("config/config.json", "r") as fp:
    data = json.load(fp)

USER = data["user"]
MODE = data["mode"]
UID = data["uid"]