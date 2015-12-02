#!/usr/bin/env python
#
# picam2socketio.py
#
# Author:   Hiromasa Ihara (miettal)
# URL:      http://miettal.com
# License:  MIT License
# Created:  2014-05-15
#
import threading
from flask import Flask, render_template, request, Response
from flask.ext.socketio import SocketIO, emit

import sys
import os
from scapy.all import *
import json
import time
import datetime
import subprocess
import geoip2.database

import random

randIP = ["8.8.8.8", "2.60.8.8", "1.0.1.1", "203.178.135.4", "93.158.236.1"]

geoip = geoip2.database.Reader('./GeoLite2-City.mmdb')

retjson = ""

def pcap2json(f):
    """pcap -> json, print"""

    _IPV4 = 0x0800
    _IPV6 = 0x86dd
    _DOT1Q = 0x8100
    _ICMP = 1
    _IGMP = 2
    _TCP = 6
    _UDP = 17
    _ESP = 50
    _AH = 51
    _MOBILE = 55
    _ICMP6 = 58
    _L2TP = 115

    pkts = rdpcap(f)
    newj = {}
    newp = []
    for pkt in pkts:
        TS = pkt.time
        
        ### get l3proto ###$
        try:
            l3proto = pkt.type
            if pkt.type == _DOT1Q:
                l3proto = pkt[Dot1Q].type
        except:
            continue
        
        ### get srcip, dstip, proto ###
        if l3proto == _IPV4:
            SA, DA, PR  = pkt[IP].src, pkt[IP].dst, pkt[IP].proto
        elif l3proto == _IPV6:
            SA, DA, PR  = pkt[IPv6].src, pkt[IPv6].dst, pkt[IPv6].nh
        else:
            continue

        ### get srcport, dstport ###
        if PR == _ICMP:
            SP, DP = pkt[ICMP].type, pkt[ICMP].code
        elif PR == _TCP:
            SP, DP = pkt[TCP].sport, pkt[TCP].dport
        elif PR == _UDP:
            SP, DP = pkt[UDP].sport, pkt[UDP].dport
        else:
            continue

	try:
		sres = geoip.city(SA)
	except Exception as e:
		sres = geoip.city(randIP[random.randint(0, len(randIP)-1)])
	try:
		dres = geoip.city(DA)
	except Exception as e:
		dres = geoip.city("8.8.8.8")

	srccount = sres.country.name
	srclat = sres.location.latitude
	srclog = sres.location.longitude
	dstcount = dres.country.name
	dstlat = dres.location.latitude
	dstlog = dres.location.longitude

        ### print ###
	newp.append(json.dumps({"time"  :   TS,
                          "sip"   :   SA,
                          "dip"   :   DA,
                          "proto" :   PR,
                          "sport" :   SP,
                          "dport" :   DP,
			  "srccount" : srccount, 
			  "srclat" : srclat,
			  "srclog" : srclog,
			  "dstcount" : dstcount,
			  "dstlat" : dstlat,
                	  "dstlog" : dstlog
			},
			separators=(',',':')))
    newj["data"] = newp
    retjson = newj

    print retjson
    print "emit"
    socketio.emit('pktdata', {'data': retjson})
    print "emit fin"

def tcpdump():
    command = 'tcpdump -i eth0 -G 1 -Uw ./traffic/%S.pcap'.split(' ')
    try:
        subprocess.Popen(command)
    except:
        print "error: cannnot execute tcpdump"
        exit(1)


def main():
    ### init ###
    command = ['rm','-rf','./traffic']
    subprocess.Popen(command).wait()
    command = ['mkdir','traffic']
    subprocess.Popen(command).wait()

    ### check new file ###
    sec = datetime.datetime.now().second
    oldfile = './traffic/' + ("0" if sec < 10 else '') + str(sec) + '.pcap'

    ### start dumping ###
    tcpdump()
    time.sleep(1)
    if not os.path.exists(oldfile):
        oldfile = './traffic/' + ('0' if sec < 10 else '') + str(sec+1) + '.pcap'

    ### main loop ###
    while(True):
        ### check new file ###
        while(True):
            sec = datetime.datetime.now().second
            newfile = './traffic/' + ('0' if sec < 10 else '') + str(sec) + '.pcap'
            if (oldfile != newfile and os.path.exists(newfile)):
                break

        ### pcap -> json ###
        pcap2json(oldfile)
        command = ['rm','-rf',oldfile]
        subprocess.Popen(command).wait()
        oldfile = newfile

app = Flask(__name__)
app.debug = True
socketio = SocketIO(app)

def camera_thread() :
  main()

@app.route('/')
def index() :
  print "return index"
  return render_template("pandalous.html")




if __name__ == "__main__" :
  t=threading.Thread(target=camera_thread)
  t.setDaemon(True)
  t.start()
  socketio.run(app, host="0.0.0.0", port=5002)
