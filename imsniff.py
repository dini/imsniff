#!/usr/bin/env python
# encoding: utf-8
#
# Copyright (C) 2010 Denis Klester. All rights reserved.
#

__author__ = "Denis Klester"
__copyright__ = "Copyright (C) 2010 Denis Klester"
__revision__ = "$Id$"
__version__ = "0.1"

import sys, os, nfqueue, socket, struct, MySQLdb
from socket import AF_INET, AF_INET6, inet_ntoa
from dpkt import ip, tcp

# Protocol family id
OSCAR = 1
MRIM = 2
UNKNOW = 255
UNKNOW_TXT = "Unknow"

# outgoing or incoming
INCOMING = 1
OUTGOING = 2

# Protocols magic numbers
FLAP_ID = 42
MRIM_ID = 3735928559

# MySQL
db_host = "localhost"
db_name = "security"
db_user = "root"
db_pass = ""

def proto(data):
    if struct.unpack("!B", data[:1])[0] == FLAP_ID: return OSCAR
    elif struct.unpack("!I", data[:4])[0] == MRIM_ID: return MRIM
    return UNKNOW

def oscar(data):
    flap_id, flap_ch, flap_seq, flap_size = struct.unpack("!BBHH", data[:6]) # parse flap struct
    if (flap_id == FLAP_ID and flap_ch == 2):
	print "FLAP ID: %d, channel: %d, seq: %d, size: %d" % (flap_id, flap_ch, flap_seq, flap_size)
	snac_id, snac_type, snac_flags, snac_seq = struct.unpack("!HHHL", data[6:16]) # parse snac struct
	if (snac_id == 4 and (snac_type == 6 or snac_type == 7)):
	    print "  SNAC ID: %d, type: %d, flags: %d, seq: %d" % (snac_id, snac_type, snac_flags, snac_seq)
	    msg_id, msg_ch, uinlen = struct.unpack("!QHB", data[16:27]) # parse snac data
	    uin = str(data[27:27+uinlen]) # get uin
	    print "    Message ID: %d, channel: %d, UIN: %d, len: %d" % (msg_id, msg_ch, int(uin), uinlen)
	    data = data[27+uinlen:flap_size]
	    if snac_type == 7:
		warn_lvl, tlvs = struct.unpack("!HH", data[:4])
		data = data[4:]
	    # find tlv type 5
	    tlvlen = 0
	    tlvtype = 0
	    while tlvtype != 5:
		data = data[tlvlen:]
		tlvtype, tlvlen = struct.unpack("!HH", data[:4])
		print "      TLV type: %d, len: %d" % (tlvtype, tlvlen)
		if (tlvtype == 5 and tlvlen < 5): tlvtype = 0
		tlvlen += 4
	    msg_type, msg_cookie = struct.unpack("!HQ", data[4:14])
	    guid = struct.unpack("!IHHBBBBBBBB", data[14:30])
	    print "        Msg type: %d, cooking: %d" % (msg_type, msg_cookie), ", GUID: ", list(guid)
	    data = data[30:tlvlen]
	    # find tlv type 0x2711
	    tlvlen = 0
	    while tlvtype != 10001:
		data = data[tlvlen:]
		tlvtype, tlvlen = struct.unpack("!HH", data[:4])
		print "          TLV type: %d, len: %d" % (tlvtype, tlvlen)
		tlvlen += 4
	    data = data[4:tlvlen]
	    # parse capability struct
	    datalen, protov = struct.unpack("<HH", data[:4])
	    plug_guid = struct.unpack("!IHHBBBBBBBB", data[4:20])
	    unknow, client_flags, unknow, downcount = struct.unpack("<HIBH", data[20:29])
	    data = data[datalen+2:]
	    # unknow struct
	    datalen, downcount = struct.unpack("<HH", data[:4])
	    data = data[datalen+2:]
	    # parse message struct
	    msgtype, msgflag, status, priority, msglen = struct.unpack("<BBHHH", data[:8])
	    print "            Message type: %d, flag: %d, status: %d, priority: %d, len: %d" % (msgtype, msgflag, status, priority, msglen)
	    if msgtype == 1:
		msg = data[8:8+msglen]
		print "              Message: ", msg
		if snac_type == 7: return INCOMING, uin, msg
		else: return OUTGOING, uin, msg
    return UNKNOW, UNKNOW_TXT, UNKNOW_TXT

def callback(payload):
    data = payload.get_data()
    pkt = ip.IP(data)
    ip_src = inet_ntoa(pkt.src)
    ip_dst = inet_ntoa(pkt.dst)
    buf = pkt.tcp.data
    route = UNKNOW
    temp = proto(buf)
    if temp == OSCAR: route, handle, msg = oscar(buf)
    if route == INCOMING:
	print "Message from %s: %s" % (handle, msg)
	print """INSERT INTO sniff (proto, ip, from_handle, msg) VALUES ("%d", "%s", "%s", "%s")""" % (temp, ip_dst, handle, msg)
	dbh.execute("""INSERT INTO sniff (proto, ip, from_handle, msg) VALUES ("%d", "%s", "%s", "%s")""" % (temp, ip_dst, handle, msg))
    elif route == OUTGOING:
	print "Message to %s: %s" % (handle, msg)
	print """INSERT INTO sniff (proto, ip, to_handle, msg) VALUES ("%d", "%s", "%s", "%s")""" % (temp, ip_src, handle, msg)
	dbh.execute("""INSERT INTO sniff (proto, ip, to_handle, msg) VALUES ("%d", "%s", "%s", "%s")""" % (temp, ip_src, handle, msg))


    payload.set_verdict(nfqueue.NF_ACCEPT)

def bind():
    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(callback)
    q.create_queue(0)
    try:
        q.try_run()
    except KeyboardInterrupt:
        print "Exiting..."
        q.unbind(socket.AF_INET)
        q.close()
	dbh.close()
        sys.exit(1)

db = MySQLdb.connect(host=db_host, user=db_user, passwd=db_pass, db=db_name)
dbh = db.cursor()
bind()
