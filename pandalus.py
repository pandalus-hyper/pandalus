#!/usr/bin/env python
#
# picam2socketio.py
#
# Author:   Hiromasa Ihara (miettal)
# URL:      http://miettal.com
# License:  MIT License
# Created:  2014-05-15
#
import sys
import os
import time
import json
import datetime
import random
import threading
import subprocess

from flask import Flask, render_template, request, Response
from flask.ext.socketio import SocketIO, emit

from scapy.all import *
import geoip2.database

randIP = ["8.8.8.8", "2.60.8.8", "1.0.1.1", "203.178.135.4",
          "93.158.236.1", "1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"]

PROTOCOL_NUMBER_IPV4 = 0x0800
PROTOCOL_NUMBER_IPV6 = 0x86dd
PROTOCOL_NUMBER_DOT1Q = 0x8100

PROTOCOL_ICMP = 1
PROTOCOL_IGMP = 2
PROTOCOL_ICMP6 = 58
PROTOCOL_TCP = 6
PROTOCOL_UDP = 17

geoip = geoip2.database.Reader('./GeoLite2-City.mmdb')

retjson = ""

def pcap2json(f):
    """pcap -> json, print"""


    pkts = rdpcap(f)
    newj = {}
    newp = []
    for pkt in pkts:
        field_time = pkt.time

        # get l3proto ###$
        try:
            l3proto = pkt.type
            if pkt.type == PROTOCOL_NUMBER_DOT1Q:
                l3proto = pkt[Dot1Q].type
        except:
            continue

        ### get srcip, dstip, proto ###
        if l3proto == PROTOCOL_NUMBER_IPV4:
            field_srcip, field_dstip, field_protocol = pkt[IP].src, pkt[IP].dst, pkt[IP].proto
        elif l3proto == PROTOCOL_NUMBER_IPV6:
            field_srcip, field_dstip, field_protocol = pkt[IPv6].src, pkt[IPv6].dst, pkt[IPv6].nh
        else:
            continue

        ### get srcport, dstport ###
        if field_protocol == PROTOCOL_ICMP:
            field_srcport, field_dstport = pkt[ICMP].type, pkt[ICMP].code
        elif field_protocol == PROTOCOL_ICMP6:
            field_srcport, field_dstport = pkt[ICMP6].type, pkt[ICMP6].code
        elif field_protocol == PROTOCOL_TCP:
            field_srcport, field_dstport = pkt[TCP].sport, pkt[TCP].dport
        elif field_protocol == PROTOCOL_UDP:
            field_srcport, field_dstport = pkt[UDP].sport, pkt[UDP].dport
        else:
            continue

        try:
            sres = geoip.city(field_srcip)
        except Exception as e:
            continue
        try:
            dres = geoip.city(field_dip)
        except Exception as e:
            continue

        field_srccc = sres.country.iso_code
        field_srccount = sres.country.name
	print field_srccount
        field_srclat = sres.location.latitude
        field_srclog = sres.location.longitude
        field_dstcc = dres.country.iso_code
        field_dstcount = dres.country.name
        field_dstlat = dres.location.latitude
        field_dstlog = dres.location.longitude

        ### print ###
        newp.append({"time": field_time,
                                "sip": field_srcip,
                                "dip": field_dstip,
                                "proto": field_protocol,
                                "sport": field_srcport,
                                "dport": field_dstport,
                                "srccc": field_srccc,
                                "srccount": field_srccount,
                                "srclat": field_srclat,
                                "srclog": field_srclog,
                                "dstcc": field_dstcc,
                                "dstcount": field_dstcount,
                                "dstlat": field_dstlat,
                                "dstlog": field_dstlog
                                })
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
    command = ['rm', '-rf', './traffic']
    subprocess.Popen(command).wait()
    command = ['mkdir', 'traffic']
    subprocess.Popen(command).wait()

    ### check new file ###
    sec = datetime.datetime.now().second
    oldfile = './traffic/' + ("0" if sec < 10 else '') + str(sec) + '.pcap'

    ### start dumping ###
    tcpdump()
    time.sleep(1)
    if not os.path.exists(oldfile):
        oldfile = './traffic/' + \
            ('0' if sec < 10 else '') + str(sec + 1) + '.pcap'

    ### main loop ###
    while(True):
        ### check new file ###
        while(True):
            sec = datetime.datetime.now().second
            newfile = './traffic/' + \
                ('0' if sec < 10 else '') + str(sec) + '.pcap'
            if (oldfile != newfile and os.path.exists(newfile)):
                break
            time.sleep(0.01)

        ### pcap -> json ###
        try :
            pcap2json(oldfile)
        except MemoryError :
            pass
        command = ['rm', '-rf', oldfile]
        subprocess.Popen(command).wait()
        oldfile = newfile

app = Flask(__name__)
app.debug = True
socketio = SocketIO(app)


def capture_thread():
    main()


@app.route('/')
def index():
    print "return index"
    return render_template("pandalous.html")


if __name__ == "__main__":
    port = int(os.environ.get('PORT'))

    t = threading.Thread(target=capture_thread)
    t.setDaemon(True)
    t.start()

    socketio.run(app, host="0.0.0.0", port=port)
