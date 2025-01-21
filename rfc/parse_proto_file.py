p = []
with open("protocols.txt", "r") as fh:
    for line in fh:
        line = line.split(" ")
        p.append(line[2].strip("\t"))
p = p[1:]

d = {}
for i in range(len(p)):
    d[p[i]] = i

with open("p.txt", "w") as fh:
    for k, v in d.items():
        fh.write("\"{}\": {},\n".format(str(k), int(v)))
