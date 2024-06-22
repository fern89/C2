import socket, time
import zlib, re
import base64, shlex

stacks = {}
outs = {}
living = {}
allout = ""
def call(x):
    return [pack(x)]
def pack(x):
    return (x).to_bytes(4, byteorder='little')
def wrap(data):
    return pack(len(data)+4) + pack(zlib.crc32(data)) + data
def string(data):
    return pack(len(data)+0x80000000)+data.encode("charmap")
def construct(stack):
    instructs = b""
    data = b""
    for x in stack:
        if "list" in str(type(x)):
            instructs += x[0]
        else:
            data += x
    return wrap(instructs) + wrap(data)
def toCmdTable(opcodes):
    data = {}
    i = 0
    for x in opcodes.split("\n"):
        if x.strip() == "":
            continue
        raw = x.split("//")[0].strip().strip(", ")
        data[raw.upper()] = [i, "r" in x.split("//")[1], x.split("//")[1].strip("r")]
        if len(x.split("//"))>2:
            data[raw.upper()].append(x.split("//")[2].strip())
        i+=1
    return data
def toTable(opcodes):
    data = {}
    i = 0
    for x in opcodes.split("\n"):
        if x.strip() == "":
            continue
        raw = x.strip().strip(", ")
        data[raw.upper()] = i
        i+=1
    return data

def xor(ss):
    return bytes(a ^ 0x68 for a in ss)
def scriptparse(script, data, subs):
    stack = []
    line = 0
    errors = ""
    for x in script.split("\n"):
        line += 1
        if x.strip() == "":
            continue
        if x[0] == "#":
            continue
        sh = shlex.split(x)
        if not sh[0].upper() in data:
            errors+="unrecognized command! line="+str(line)+"\n"
            continue
        if not data[sh[0].upper()][2] == "?":
            if not((len(sh)-1 == int(data[sh[0].upper()][2])) or ((len(sh)-3 == int(data[sh[0].upper()][2])) and ("->" in sh))):
                errors+="invalid arg num! line="+str(line)+"\n"
                continue
        stack.append(call(data[sh[0].upper()][0]))
        
        for i in range(1, len(sh)):
            if sh[i] == "->":
                stack.append(call(data[sh[i+1].upper()][0]))
                break
            elif sh[i] == "TRUE":
                stack.append(pack(1))
            elif sh[i] == "FALSE":
                stack.append(pack(0))
            elif sh[i].upper() in subs:
                stack.append(pack(subs[sh[i].upper()]))
            elif re.match(r"hex\([0-9a-fA-F]+\)", sh[i]):
                stack.append(string(bytes.fromhex(sh[i].split("(")[1][:-1]).decode("charmap")))
            elif re.match(r"file\(.+\)", sh[i]):
                f = open(sh[i].split("(")[1][:-1], "rb")
                r = f.read()
                f.close()
                stack.append(string(r.decode("charmap")))
            elif sh[i].isnumeric():
                stack.append(pack(int(sh[i])))
            else:
                stack.append(string(sh[i]))
        if data[sh[0].upper()][1]:
            if not "->" in sh:
                stack.append(call(data["POPSTR"][0]))
    return [stack, errors]