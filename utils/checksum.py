def checksum(data):
    s = 0
    if type(data) == bytes:
        for i in range(0, len(data), 2):
            if len(data) > int(i+1):
                a = data[i]
                b = data[i+1]
                s += (ord(chr(a)) + (ord(chr(b)) << 8))
            elif len(data) == int(i+1):
                s += ord(data[i])
        s += s >> 16
        s = ~s & 0xffff
        return s
    else:
        for i in range(0, len(data), 2):
            if len(data) > int(i+1):
                a = data[i]
                b = data[i+1]
                s += (ord(a) + (ord(b) << 8))
            elif len(data) == int(i+1):
                s += ord(data[i])
        s += s >> 16
        s = ~s & 0xffff
        return s


def verify_checksum(h_struct):
    """
    Usage:
        h_struct = (17664, 147, 0, 16384, 14865, 40894, 19275, 19275, 2560, 6)
        verify_checksum(h_struct)
    """
    words = []
    for b in h_struct:
        words.append("%04x" %b)
    words = "".join(words)
    s = ""
    for i in range(0, len(words), 2):
        s += " " + str(words[i] + words[i+1])
    d = [chr(int(i, 16)) for i in s.split()]
    return checksum(d)
