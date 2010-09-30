#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2010 Denis Klester. All rights reserved.
#

import MySQLdb, cgi

# Protocol family id
OSCAR = 1
MRIM = 2

# MySQL
db_host = "localhost"
db_name = "security"
db_user = "root"
db_pass = ""


def main():
    form = cgi.FieldStorage()
    if form.has_key("sheet"): sheet = int(form["sheet"].value)
    else: sheet = 1

    con = MySQLdb.connect(host = db_host, user = db_user, passwd = db_pass, db = db_name, use_unicode=True, charset="utf8")

    print """Content-type: text/html

<html>
<head>
<title>IMSniff</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
</head>
<body>"""

    cur = con.cursor()
    sql = """SELECT * FROM sniff;"""
    cur.execute(sql)
    result = cur.fetchall()
    total = len(result)
    if total > 50:
	print "<table><tr>"
	for i in range(total//50+1):
	    print """<td><a href="index.py?sheet=%d">%d</a></td>""" % (i+1, i+1)
	print "</tr></table>"

    print """<table>
<tr>
    <td width=5%>proto</td>
    <td width=10%>from</td>
    <td width=10%>to</td>
    <td width=12%>time</td>
    <td width=60%>message</td>
    <td width=8%>ip</td>
</tr>"""
    sql = """SELECT * FROM sniff ORDER BY id DESC LIMIT %s, 50;""" % ((sheet-1)*50)
    cur.execute(sql)
    result = cur.fetchall()
    con.close()
    total = len(result)
    if total > 0:
        for record in range(total):
            if record/2.0 == record//2.0: print "<tr bgcolor=#f0f0f0>"
            else: print "<tr bgcolor=#f9f9f9>"
            if result[record][3] == OSCAR: print "<td>ICQ</td>"
            elif result[record][3] == MRIM: print "<td>@mail.ru</td>"
            else: print "<td></td>" 
            if result[record][4]: print "<td>" + result[record][4] + "</td>"
            else: print "<td></td>"
            if result[record][5]: print "<td>" + result[record][5] + "</td>"
            else: print "<td></td>"
            print "<td><font size='-1'>%s</font></td>" % result[record][1]
            print "<td>" + result[record][6].encode('utf-8') + "</td>"
            print "<td>%s</td>" % result[record][2]
            print "</tr>"
    print "</table></body></html>"


if __name__ == '__main__':
    main()
