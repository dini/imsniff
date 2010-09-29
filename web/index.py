#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2010 Denis Klester. All rights reserved.
#

import MySQLdb, sys
#import cgi, session, time

# Protocol family id
OSCAR = 1
MRIM = 2

# MySQL
db_host = "localhost"
db_name = "security"
db_user = "root"
db_pass = ""
myquery = "SELECT * FROM sniff ORDER BY id DESC"

sys.stderr = sys.stdout

db = MySQLdb.connect(host=db_host, user=db_user, passwd=db_pass, db=db_name, use_unicode=True, charset="utf8")
dbh = db.cursor()

dbh.execute(myquery)
result = dbh.fetchall()
dbh.close()
total = len(result)

print """Content-Type: text/html; charset='utf-8'

<html>
<body>
<table>
<tr>
    <td width=10%>from</td>
    <td width=10%>to</td>
    <td width=12%>time</td>
    <td width=60%>message</td>
    <td width=8%>ip</td>
</tr>"""

if total > 0:
    for record in range(total):
	if record/2.0 == record//2.0: print "<tr bgcolor=#f0f0f0>"
	else: print "<tr bgcolor=#f9f9f9>"
	if result[record][4]: print "<td>" + result[record][4] + "</td>"
	else: print "<td></td>"
	if result[record][5]: print "<td>" + result[record][5] + "</td>"
	else: print "<td></td>"
	print "<td>%s</td>" % result[record][1]
	print "<td>" + result[record][6].encode('utf-8') + "</td>"
	print "<td>%s</td>" % result[record][2]
	print "</tr>"
print """</table>
</body>
</html>
"""
