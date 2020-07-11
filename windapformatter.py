#!/usr/bin/python3.8

import sys
import subprocess
import os
import re
import time
import datetime
from datetime import datetime, timedelta
import argcomplete,argparse
'''
Reading Windapsearch output and gather interesting information for pentest/redteams

Installing argcomplete:
python3 -m pip install argcomplete
activate-global-python-argcomplete

Created by DVS
'''
parser = argparse.ArgumentParser(description='Extracts windapsearch output into a pretty format')
parser.add_argument('-f', '--full', help='Get All Info', action='store_true')
parser.add_argument('-spn', '--serviceprinciplename', help='List SPN Users', action='store_true')
parser.add_argument('-pnr', '--passwordnotrequire' ,help='Lists Enabled accounts with Password Not required',action='store_true')
parser.add_argument('-pne', '--passwordneverexpire' ,help='Lists Enabled accounts with Password Never Expire',action='store_true')
parser.add_argument('-prf', '--passwordreversibleformat' ,help='List Account where Passwords stored in Reversible Format',action='store_true')
parser.add_argument('-tfd', '--trustedfordelegation' ,help='Lists Accounts Trusted for Delegation',action='store_true')
parser.add_argument('-admin', '--admin' ,help='Lists Admin accounts',action='store_true')
parser.add_argument('-r', '--read' ,help='Read output from windapsearch')
args = parser.parse_args()
argcomplete.autocomplete(parser)
file1 = args.read

dict = {}

data = False
location = "Blank"
title = "Blank"
pwdlastset = "Blank"
userprincipalname = "Blank"
whencreated = "Blank"
samaccountname = "Blank"
department  = "Blank"
lastlogontimestamp = "Blank"
admincount = "Blank"
timestamp = ""
timestamp2 = ""
loc_dt = ""
loc_dt1 = ""
manager = "Blank"
homedrive= "Blank"
mobile = "Blank"
loc = "Blank"
member = "Blank"
status = "Blank"
spn = "Blank"
members = []
mem = 0
for line in open(file1, encoding = "ISO-8859-1").readlines():
	line = line.strip()
	if line:
		try:
			if line.split(":")[0].lower() == "l".lower():
				location = line.split(":")[1].strip()
				data = True
			if line.split(":")[0].lower() == "physicalDeliveryOfficeName".lower():
				loc = line.split(":")[1].strip()
				data = True
			elif line.split(":")[0].lower() == "title".lower():
				title = line.split(":")[1].strip()
				data = True
			elif line.split(":")[0].lower() == "pwdlastset".lower():
				pwdlastset = line.split(":")[1].strip()
				data = True
			elif line.split(":")[0].lower() == "userprincipalname".lower():
				userprincipalname = line.split(":")[1].strip()
				data = True
			elif line.split(":")[0].lower() == "whencreated".lower():
				whencreated = line.split(":")[1].strip()
				data = True
			elif line.split(":")[0].lower() == "samaccountname".lower():
				samaccountname = line.split(":")[1].strip()
				data = True
			elif line.split(":")[0].lower() == "department".lower():
				department = line.split(":")[1].strip()
				data = True
			elif line.split(":")[0].lower() == "lastlogontimestamp".lower():
				lastlogontimestamp = line.split(":")[1].strip()
				data = True
			elif line.split(":")[0].lower() == "admincount".lower():
				admincount = line.split(":")[1].strip()
				data = True
			elif line.split(":")[0].lower() == "manager".lower():
				manager = line.split(":")[1].split("=")[1].rsplit(",",1)[0].strip()
				data = True
			elif line.split(":")[0].lower() == "homeDirectory".lower():
				homedrive = line.split(":")[1].strip()
				data = True
			elif line.split(":")[0].lower() == "mobile".lower():
				mobile = line.split(":")[1].strip()
				data = True
			elif line.split(":")[0].lower() == "memberOf".lower():
				member = line.split("CN=", 1)[1].split(",")[0].strip()
				data = True
			elif line.split(":")[0].lower() == "userAccountControl".lower():
				status = line.split(": ")[1]
				data = True
			elif line.split(":")[0].lower() == "serviceprincipalname".lower():
				spn = line.split(": ")[1]
				data = True
		except:
			pass
	else:
		if data:
			tempdict = {
			"location" : location,
			"loc" : loc,
			"title" : title,
			"pwdlastset" : pwdlastset,
			"userprincipalname" : userprincipalname,
			"whencreated" : whencreated,
			"samaccountname" : samaccountname,
			"department" : department,
			"lastlogontimestamp" : lastlogontimestamp,
			"admincount" : admincount,
			"manager" : manager,
			"homedrive" : homedrive,
			"mobile" : mobile,
			"member" : member,
			"status" : status,
			"spn" : spn
			}
			dict.update({samaccountname:tempdict})
		data = False
		location = "Blank"
		loc = "Blank"
		title = "Blank"
		pwdlastset = "Blank"
		userprincipalname = "Blank"
		whencreated = "Blank"
		samaccountname = "Blank"
		department  = "Blank"
		lastlogontimestamp = "Blank"
		admincount = "Blank"
		manager = "Blank"
		homedrive = "Blank"
		mobile = "Blank"
		member = "Blank"
		status = "Blank"
		spn = "Blank"
print("Username\tAccountStatus\tEmail\tMobile\tTitle\tLocation\tDepartment\tLastLogon\tPassword Last Set\tAccount Created\tAdmin?\tManager\tHome Drive\tService Account")
count = 0
for user in dict:
	count += 1
	if dict[user]["spn"] != "Blank":
		spn = "Service Account"
	else:
		spn = "Blank"
	if dict[user]["lastlogontimestamp"] != "Blank":
		timestamp = dict[user]["lastlogontimestamp"]
		seconds_since_epoch = int(timestamp)/10**7
		loc_dt = datetime.fromtimestamp(seconds_since_epoch)
		loc_dt -= timedelta(days=(1970 - 1601) * 365 + 89)
	if dict[user]["pwdlastset"] != "Blank":
		timestamp2 = dict[user]["pwdlastset"]
		seconds_since_epoch2 = int(timestamp2)/10**7
		loc_dt1 = datetime.fromtimestamp(seconds_since_epoch2)
		loc_dt1 -= timedelta(days=(1970 - 1601) * 365 + 89)
	if dict[user]["whencreated"] != "Blank":
		d = datetime.strptime(dict[user]["whencreated"].split(".")[0], "%Y%m%d%H%M%S" )
	if  dict[user]["admincount"] == "1":
		dict[user]["admincount"] = "Yes"
	if dict[user]["location"] == "Blank":
		dict[user]["location"] = dict[user]["loc"]
	else:
		dict[user]["location"] = dict[user]["location"]
	if "1601-01-01 01:00:00" != str(loc_dt1):
		loc_dt1 = loc_dt1
	else:
		loc_dt1 = "never"
	if dict[user]["status"] == "512":
		dict[user]["status"] = "Account Enabled"
	elif dict[user]["status"] == "514":
		dict[user]["status"] = "Account Disabled"
	elif dict[user]["status"] == "66048":
		dict[user]["status"] = "Account Enabled + Password Never Expires"
	elif dict[user]["status"] == "66050":
		dict[user]["status"] = "Account Disabled + Password Never Expires"
	elif dict[user]["status"] == "528":
		dict[user]["status"] = "Account Enabed + ACCOUNT LOCKEDOUT"
	elif dict[user]["status"] == "544":
		dict[user]["status"] = "Account Enabld + Password Not Required"
	elif dict[user]["status"] == "546":
		dict[user]["status"] = "Account Disabled + Password Not Required"
	elif dict[user]["status"] == "66080":
		dict[user]["status"] = "Account Enabled + Password Never Expire + Password Not Required"
	elif dict[user]["status"] == "66064":
		dict[user]["status"] = "Account Enabled + Account Locked + Password Never Expires"
	elif dict[user]["status"] == "560":
		 dict[user]["status"] = "Account Enabled + Password Not Required + Account LOCKEDOUT"
	elif dict[user]["status"] == "640":
		dict[user]["status"] = "Account Enabled + Password Stored in Cleartext"
	elif dict[user]["status"] == "66176":
		dict[user]["status"] = "Account Enabled + Password Never Expire + Password Stored in Cleartext"
	elif dict[user]["status"] == "66082":
		dict[user]["status"] = "Account Disabled + Password Not Required + Password Never Expires"
	elif dict[user]["status"] == "532480":
		dict[user]["status"] = "TRUSTED FOR DELEGATION"
	elif dict[user]["status"] == "590336":
	        dict[user]["status"] = "Account Enabled + User Cannot Change Password + Password Never Expires"
	if args.full:
		print(dict[user]["samaccountname"]+"\t"+dict[user]["status"]+"\t"+dict[user]["userprincipalname"]+"\t"+dict[user]["mobile"]+"\t"+dict[user]["title"]+"\t"+dict[user]["location"]+"\t"+dict[user]["department"]+"\t"+str(loc_dt)+"\t"+str(loc_dt1)+"\t"+d.strftime("%d %B %Y")+"\t"+dict[user]["admincount"]+"\t"+dict[user]["manager"]+"\t"+dict[user]["homedrive"]+"\t"+spn)
	if args.serviceprinciplename:
		if spn == "Service Account":
			print(dict[user]["samaccountname"]+"\t"+dict[user]["status"]+"\t"+dict[user]["userprincipalname"]+"\t"+dict[user]["mobile"]+"\t"+dict[user]["title"]+"\t"+dict[user]["location"]+"\t"+dict[user]["department"]+"\t"+str(loc_dt)+"\t"+str(loc_dt1)+"\t"+d.strftime("%d %B %Y")+"\t"+dict[user]["admincount"]+"\t"+dict[user]["manager"]+"\t"+dict[user]["homedrive"]+"\t"+spn)
	if args.passwordnotrequire:
		if  "Password Not Required" in dict[user]["status"] and "Account Enabled" in dict[user]["status"]:
			print(dict[user]["samaccountname"]+"\t"+dict[user]["status"]+"\t"+dict[user]["userprincipalname"]+"\t"+dict[user]["mobile"]+"\t"+dict[user]["title"]+"\t"+dict[user]["location"]+"\t"+dict[user]["department"]+"\t"+str(loc_dt)+"\t"+str(loc_dt1)+"\t"+d.strftime("%d %B %Y")+"\t"+dict[user]["admincount"]+"\t"+dict[user]["manager"]+"\t"+dict[user]["homedrive"]+"\t"+spn)

	if args.passwordneverexpire:
		if  "Password Never Expires" in dict[user]["status"] and "Account Enabled" in dict[user]["status"]:
			print(dict[user]["samaccountname"]+"\t"+dict[user]["status"]+"\t"+dict[user]["userprincipalname"]+"\t"+dict[user]["mobile"]+"\t"+dict[user]["title"]+"\t"+dict[user]["location"]+"\t"+dict[user]["department"]+"\t"+str(loc_dt)+"\t"+str(loc_dt1)+"\t"+d.strftime("%d %B %Y")+"\t"+dict[user]["admincount"]+"\t"+dict[user]["manager"]+"\t"+dict[user]["homedrive"]+"\t"+spn)
	if args.trustedfordelegation:
		if "TRUSTED FOR DELEGATION" in dict[user]["status"]:
			print(dict[user]["samaccountname"]+"\t"+dict[user]["status"]+"\t"+dict[user]["userprincipalname"]+"\t"+dict[user]["mobile"]+"\t"+dict[user]["title"]+"\t"+dict[user]["location"]+"\t"+dict[user]["department"]+"\t"+str(loc_dt)+"\t"+str(loc_dt1)+"\t"+d.strftime("%d %B %Y")+"\t"+dict[user]["admincount"]+"\t"+dict[user]["manager"]+"\t"+dict[user]["homedrive"]+"\t"+spn)

	if args.passwordreversibleformat:
		if "Password Stored in Cleartext" in dict[user]["status"]:
			print(dict[user]["samaccountname"]+"\t"+dict[user]["status"]+"\t"+dict[user]["userprincipalname"]+"\t"+dict[user]["mobile"]+"\t"+dict[user]["title"]+"\t"+dict[user]["location"]+"\t"+dict[user]["department"]+"\t"+str(loc_dt)+"\t"+str(loc_dt1)+"\t"+d.strftime("%d %B %Y")+"\t"+dict[user]["admincount"]+"\t"+dict[user]["manager"]+"\t"+dict[user]["homedrive"]+"\t"+spn)
	if args.admin:
		if "Yes" == dict[user]["admincount"]:
			print(dict[user]["samaccountname"]+"\t"+dict[user]["status"]+"\t"+dict[user]["userprincipalname"]+"\t"+dict[user]["mobile"]+"\t"+dict[user]["title"]+"\t"+dict[user]["location"]+"\t"+dict[user]["department"]+"\t"+str(loc_dt)+"\t"+str(loc_dt1)+"\t"+d.strftime("%d %B %Y")+"\t"+dict[user]["admincount"]+"\t"+dict[user]["manager"]+"\t"+dict[user]["homedrive"]+"\t"+spn)

