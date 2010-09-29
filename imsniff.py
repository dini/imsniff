#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2010 Denis Klester. All rights reserved.
#

import sys, os, nfqueue, socket, struct, re, MySQLdb
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
FLAP_ID = 0x2A
MRIM_ID = 0xDEADBEEF

# MySQL
db_host = "localhost"
db_name = "security"
db_user = "root"
db_pass = ""

def parse(data):
    msg = ""
    for i in range(len(data)):
	if (data[i] == chr(0x22) or data[i] == chr(0x27)): msg += "\'"
	else: msg += data[i]
    return re.sub('<[^<]*?>', '', msg)

def proto(data):
    if struct.unpack("<B", data[:1])[0] == FLAP_ID: return OSCAR
    elif struct.unpack("<I", data[:4])[0] == MRIM_ID: return MRIM
    return UNKNOW

def oscar(data):
    flap_id, flap_ch, flap_seq, flap_size = struct.unpack("!2B2H", data[:6]) # parse flap struct
    if (flap_id == FLAP_ID and flap_ch == 2):
	print "FLAP ID: %d, channel: %d, seq: %d, size: %d" % (flap_id, flap_ch, flap_seq, flap_size)
	snac_id, snac_type, snac_flags, snac_seq = struct.unpack("!3HL", data[6:16]) # parse snac struct
	if (snac_id == 4 and (snac_type == 6 or snac_type == 7)):
	    print "  SNAC ID: %d, type: %d, flags: %d, seq: %d" % (snac_id, snac_type, snac_flags, snac_seq)
	    msg_id, msg_ch, uinlen = struct.unpack("!QHB", data[16:27]) # parse snac data
	    uin = str(data[27:27+uinlen]) # get uin
	    print "    Message ID: %d, channel: %d, UIN: %d, len: %d" % (msg_id, msg_ch, int(uin), uinlen)
	    data = data[27+uinlen:flap_size]
	    if snac_type == 7:
		warn_lvl, tlvs = struct.unpack("!2H", data[:4])
		data = data[4:]
	    tlvlen = 0
	    tlvtype = 0
	    if msg_ch == 1:
		# find tlv 0x0002
		while tlvtype != 0x0002:
		    data = data[tlvlen:]
		    tlvtype, tlvlen = struct.unpack("!2H", data[:4])
		    print "      TLV type: %d, len: %d" % (tlvtype, tlvlen)
		    if (tlvtype == 0x0002 and tlvlen < 5): tlvtype = 0
		    tlvlen += 4
		tlvlen = 4
		# find tlv 0x0101
		while tlvtype != 0x0101:
		    data = data[tlvlen:]
		    tlvtype, tlvlen = struct.unpack("!2H", data[:4])
		    print "        Fragment type: %d, len: %d" % (tlvtype, tlvlen)
		    if (tlvtype == 0x0101 and tlvlen < 5): tlvtype = 0
		    tlvlen += 4
		data = data[4:tlvlen]
		charset_num, charset_sub = struct.unpack("!2H", data[:4])
		print "          Charset num: %d, subset: %d" % (charset_num, charset_sub)
		msg = data[4:]
		msgtype = 1
	    elif (msg_ch == 2) or (msg_ch == 4):
		# find tlv 0x0005
		while tlvtype != 0x0005:
		    data = data[tlvlen:]
		    tlvtype, tlvlen = struct.unpack("!2H", data[:4])
		    print "      TLV type: %d, len: %d" % (tlvtype, tlvlen)
		    if (tlvtype == 0x0005 and tlvlen < 5): tlvtype = 0
		    tlvlen +=4
		if msg_ch == 2:
		    msg_type, msg_cookie = struct.unpack("!HQ", data[4:14])
		    guid = struct.unpack("!I2H8B", data[14:30])
		    print "        Msg type: %d, cooking: %d" % (msg_type, msg_cookie), ", GUID: ", list(guid)
		    data = data[30:tlvlen]
		    # find tlv type 0x2711
		    tlvlen = 0
		    while tlvtype != 0x2711:
			data = data[tlvlen:]
			tlvtype, tlvlen = struct.unpack("!2H", data[:4])
			print "          TLV type: %d, len: %d" % (tlvtype, tlvlen)
			tlvlen += 4
		    data = data[4:tlvlen]
		    # parse capability struct
		    datalen, protov = struct.unpack("<2H", data[:4])
		    plug_guid = struct.unpack("!I2H8B", data[4:20])
		    unknow, client_flags, unknow, downcount = struct.unpack("<HIBH", data[20:29])
		    data = data[datalen+2:]
		    # unknow struct
		    datalen, downcount = struct.unpack("<2H", data[:4])
		    data = data[datalen+2:]
		    # parse message struct
		    msgtype, msgflag, status, priority, msglen = struct.unpack("<2B3H", data[:8])
		    print "            Message type: %d, flag: %d, status: %d, priority: %d, len: %d" % (msgtype, msgflag, status, priority, msglen)
		    msg = data[8:8+msglen]
		else:
		    uintemp, msgtype, msgflag, msglen = struct.unpack("<I2BH", data[4:12])
		    print "            Message type: %d, flag: %d, len: %d, uin: %d" % (msgtype, msgflag, msglen, uintemp)
		    msg = data[12:12+msglen]
	    if msgtype == 1:
		if (msg[0] == '\xfe' and msg[1] == '\xff'): msg = msg[2:]
		if (msg[0] == '\x04' or msg[0] == '\x00'):
		    unistr = struct.unpack("!%dH" % (len(msg)/2), msg)
		    msg = ""
		    for i in range(len(unistr)):
			msg += unichr(unistr[i]).encode('utf-8')
		print "              Message: ", msg
                if snac_type == 7: return INCOMING, uin, msg
		else: return OUTGOING, uin, msg
    return UNKNOW, UNKNOW_TXT, UNKNOW_TXT

def mrim(data):
    magic, proto_ver, seq, cmd, datalen, ip_from, fromport = struct.unpack("<7I", data[:28]) # parse mrim struct
    if magic == MRIM_ID:
	print "MRIM ver: %d, MSG: %d, len: %d, ip: %d, port: %d" % (proto_ver, cmd, datalen, ip_from, fromport)
	if (cmd == 0x1008 or cmd == 0x1009):
	    data = data[44:]
	    if cmd == 0x1009: data = data[4:] # msg_id
	    data = data[4:] # flags
	    handlelen = struct.unpack("<I", data[:4])[0] # len handle
	    handle = str(data[4:4+handlelen]) # get handle
	    print "  Handle: %s, len: %d" % (handle, datalen)
	    data = data[4+handlelen:]
	    datalen = struct.unpack("<I", data[:4])[0] # len message
	    msg = data[4:4+datalen]
	    # encode to utf8
	    if (msg[1] == '\x04' or msg[1] == '\x00'):
		unistr = struct.unpack("<%dH" % (datalen/2), msg[:datalen])
		msg = ""
		for i in range(len(unistr)):
		    msg += unichr(unistr[i]).encode('utf-8')
	    else: msg = msg.decode('cp1251')
	    if (datalen == 2 and msg == ' '): return UNKNOW, UNKNOW_TXT, UNKNOW_TXT # null message
	    print "  Message: %s" % msg
	    if cmd == 0x1009: return INCOMING, handle, msg
	    else: return OUTGOING, handle, msg
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
    elif temp == MRIM: route, handle, msg = mrim(buf)
    if route != UNKNOW: msg = parse(msg)
    db = MySQLdb.connect(host=db_host, user=db_user, passwd=db_pass, db=db_name, use_unicode=True, charset="utf8")
    dbh = db.cursor()
    if route == INCOMING:
	print "Message from %s: %s" % (handle, msg)
	print """INSERT INTO sniff (proto, ip, from_handle, msg) VALUES ("%d", "%s", "%s", "%s")""" % (temp, ip_dst, handle, msg)
	dbh.execute("""INSERT INTO sniff (proto, ip, from_handle, msg) VALUES ("%d", "%s", "%s", "%s")""" % (temp, ip_dst, handle, msg))
    elif route == OUTGOING:
	print "Message to %s: %s" % (handle, msg)
	print """INSERT INTO sniff (proto, ip, to_handle, msg) VALUES ("%d", "%s", "%s", "%s")""" % (temp, ip_src, handle, msg)
	dbh.execute("""INSERT INTO sniff (proto, ip, to_handle, msg) VALUES ("%d", "%s", "%s", "%s")""" % (temp, ip_src, handle, msg))
    dbh.close()
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

bind()
