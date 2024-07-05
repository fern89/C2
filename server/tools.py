import socket, time
import zlib, re
import base64, shlex

stacks = {}
outs = {}
living = {}
allout = ""

def pack(x):
    return (x).to_bytes(4, byteorder='little')
def wrap(data):
    return pack(len(data)+4) + pack(zlib.crc32(data)) + data
def string(data):
    return pack(len(data)+0x80000000)+data.encode("charmap")
def construct(stack):
    return wrap(stack)
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
    servstack = []
    line = 0
    errors = ""
    for x in script.split("\n"):
        line += 1
        if x.strip() == "":
            continue
        if x[0] == "#":
            continue
        sh = shlex.split(x) #splt(x)
        if sh[0].upper() == "SERVER":
            sh.pop(0)
            servstack.append(sh)
        else:
            if not sh[0].upper() in data:
                errors+="unrecognized command! line="+str(line)+"\n"
                continue
            loci = len(stack)
            stack.append(pack(data[sh[0].upper()][0]))
            print(sh)
            for i in range(1, len(sh)):
                if sh[i] == "->":
                    stack.append(pack(data[sh[i+1].upper()][0]))
                    break
                elif sh[i].upper() == "TRUE":
                    stack.insert(loci, pack(data["PUSHINT"][0])+pack(1))
                elif sh[i].upper() == "FALSE":
                    stack.insert(loci, pack(data["PUSHINT"][0])+pack(0))
                elif sh[i].upper() in subs:
                    stack.insert(loci, pack(data["PUSHINT"][0])+pack(subs[sh[i].upper()]))
                elif re.match(r"hex\([0-9a-fA-F]+\)", sh[i]):
                    stack.insert(loci, pack(data["PUSHSTR"][0])+string(bytes.fromhex(sh[i].split("(")[1][:-1]).decode("charmap")))
                elif re.match(r"file\(.+\)", sh[i]):
                    f = open(sh[i].split("(")[1][:-1], "rb")
                    r = f.read()
                    f.close()
                    stack.insert(loci, pack(data["PUSHSTR"][0])+string(r.decode("charmap")))
                elif sh[i].isnumeric():
                    stack.insert(loci, pack(data["PUSHINT"][0])+pack(int(sh[i])))
                else:
                    stack.insert(loci, pack(data["PUSHSTR"][0])+string(sh[i]))
            if data[sh[0].upper()][1]:
                if not "->" in sh:
                    stack.append(pack(data["PRINT"][0]))
    return [b''.join(stack), errors, servstack]