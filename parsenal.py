#!/usr/bin/python
""" Parsenal is an Output File Parser using Python
Author : Matt Lorentzen
Original Date: September 2014
"""

from xml.dom import minidom
import sqlite3
import sys
import argparse
import csv

#The parsing loop
# creates a text file in current directory to append with the host name and any/all of the output for the list specified above

#######################################################################
#   Parse Files - Nipper
######################################################################


def parse_nipper_file():
	pass

#######################################################################
#   Parse Files - John
######################################################################


def parse_john_log(logfile, csvfile):
	csv_file = open(csvfile , 'wt')
	writer = csv.writer(csv_file)
	writer.writerow(('TimeCracked','UserAccount','Password'))

	print greentxt("----------------------------------------------")

	log = open(logfile, 'r')
	for line in log:
		if "Cracked" in line:
			line = line.split()
			timestamp = line[0]
			username = line[3].replace(":","")
			password = line[4]
			
			print redtxt(timestamp) + "Cracked : " + username + " : " + password
			writer.writerow((timestamp, username, password))

	print greentxt("----------------------------------------------")
	csv_file.close()

#######################################################################
#   Parse Files - Nessus
######################################################################


def setupDB(db):
	""" Create cursor and setup tables """
	cur = db.cursor()

	cur.execute("""CREATE TABLE IF NOT EXISTS issues(
				id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
				host_ipaddress INTEGER,
				host_name VARCHAR(255),
				host_port INTEGER,
				plugin_name VARCHAR(255),
				plugin_output TEXT
				)
	""")   



def parse_nessus_file_db(nessus_doc, checkfor, db):
	""" Parses nessus file and outputs to sqlite database """
#	issuefile = open(issuefile, 'r')
#	checkfor = issuefile.readlines()
#	issuefile.close()
	for reportHost in nessus_doc.getElementsByTagName("ReportHost"):
		# start individual host parse
		host_name = reportHost.attributes["name"].value
		for reportItem in reportHost.getElementsByTagName("ReportItem"):
			plugin_name =  reportItem.attributes['pluginName'].value
			host_port = reportItem.attributes['port'].value
			# if this is something to check for in the list
			if plugin_name in checkfor:
				print greentxt("[::] Found: ") + host_name + " : " + redtxt(host_port) + " :: " + plugin_name
				# write to database
				plugin_output = reportItem.getElementsByTagName("plugin_output")
				# adds a check for the plugin output being empty ie equal to 0
				# in the db case this needs execute a db_query based on the check
				if len(plugin_output) > 0:
					plugin_output = plugin_output[0].firstChild.nodeValue
					# add this plugin output to the relevant table, formatting of output is kept when populating the table which is cool
					db.execute("INSERT INTO issues(host_ipaddress, host_name, host_port, plugin_name, plugin_output) VALUES(?,?,?,?,?)", (host_name, host_name, host_port, plugin_name, plugin_output))
				else:
					# execute the query without the plugin_output
					db.execute("INSERT INTO issues(host_ipaddress, host_name, host_port, plugin_name) VALUES(?,?,?,?)", (host_name, host_name, host_port, plugin_name))

				db.commit()



def parse_nessus_file_txt(nessus_doc, checkfor):
	""" Writes out to the text file """
	hrline = "-------------------------------------------------------------------------------------\n"
#	issuefile = open(issuefile, 'r')
#	checkfor = issuefile.readlines()
#	issuefile.close()
	for reportHost in nessus_doc.getElementsByTagName("ReportHost"):
		# start individual host parse
		host_name = reportHost.attributes["name"].value
		host_output = open(host_name + "_output.txt" , "w")
		for reportItem in reportHost.getElementsByTagName("ReportItem"):
			plugin_name =  reportItem.attributes['pluginName'].value
			host_port = reportItem.attributes['port'].value
			# if this is something to check for in the list
			if plugin_name in checkfor:
				host_output.write(hrline)
				host_output.write("[::] " + plugin_name + "\n")
				host_output.write(hrline)
				print greentxt("[::] Found: ") + host_name + " : " + redtxt(host_port) + " :: " + plugin_name
				host_output.write(host_name + ":" + host_port + "\n")
				plugin_output = reportItem.getElementsByTagName("plugin_output")
				if len(plugin_output) > 0:
					plugin_output = plugin_output[0].firstChild.nodeValue
					#print plugin_output
					host_output.write(plugin_output + "\n")
					host_output.write("\n")
		# now close the text file for this host
		host_output.close()
	

#######################################################################
#   Formating and helper functions
######################################################################


# Functions Defined in colours.pyc to avoid dependancies
# Returns the string passed into the function, wrapped with the correct terminal codes

def redtxt(text2colour):
	redstart = "\033[0;31m"
	redend = "\033[0m"
	return redstart + text2colour + redend

def greentxt(text2colour):
	greenstart = "\033[0;32m"
	greenend = "\033[0m"
	return greenstart + text2colour + greenend
	
def yellowtxt(text2colour):
	yellowstart = "\033[0;33m"
	yellowend = "\033[0m"
	return yellowstart + text2colour + yellowend
	
def bluetxt(text2colour):
	bluestart = "\033[0;34m"
	blueend = "\033[0m"
	return bluestart + text2colour + blueend


#######################################################################
#	Main Function   
#######################################################################

	
def main():
	parser = argparse.ArgumentParser(description='Parsenal File Options')
	parser.add_argument("mode", help='Program mode (nessus, john, nipper)')
	parser.add_argument("inputfile", help="Path to the file to parse")

		
	# Nessus Parse Group
	nessus_parse_group = parser.add_argument_group('Nessus', 'Nessus File Parsing Options')

	nessus_parse_group.add_argument("-o", "--output", help="Specify the output type : <txt> <db>")


	# John Parse Group
	john_parse_group = parser.add_argument_group('John', 'John File Parsing Options')
	john_parse_group.add_argument("--csvfile", help="Path to CSV File Output for logfile")

	args = parser.parse_args()
	print args
	
	if args.mode == "nessus":
		
		# Nessus Plugin Names to check for
		checkfor = [
		"Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness",
		"Patch Report", 
		"MS08-067: Microsoft Windows Server Service Crafted RPC Request Handling Unspecified Remote Code Execution (958644)",
		"FTP Supports Clear Text Authentication",
		"Microsoft Windows SMB NULL Session Authentication",
		"SSL Self-Signed Certificate",
		"SSL RC4 Cipher Suites Supported",
		"SSLv2",
		"OS Identification",
		"Microsoft Windows Summary of Missing Patches",
		"SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)",
		"Terminal Services Doesn't Use Network Level Authentication (NLA) Only",
		"SSL Version 2 and 3 Protocol Detection"
		
		]
	

		print "The file to parse is from Nessus"
		nessus_doc = minidom.parse(args.inputfile)
	#	issuefile = args.issue
		if args.output == "txt":
			parse_nessus_file_txt(nessus_doc, checkfor)
		else:
			db_name = raw_input("Enter a database name :eg scans.db : ")
			# create a connection to the database
			db = sqlite3.connect(db_name)
			# setup database structure
			setupDB(db)
			parse_nessus_file_db(nessus_doc, checkfor, db)
	
	elif args.mode == "nipper":
		print "The file to parse is Nessus"
	elif args.mode == "john":
		print "The file to parse is a John the Ripper Log File"
		parse_john_log(args.inputfile, args.csvfile)
	else:
		print "Invalid File Type"


	hrline = "-------------------------------------------------------------------------------------\n"

	
if __name__ ==  "__main__":
	main()
