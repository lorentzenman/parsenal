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
import os


def banner():

	banner = """
                                       _
 _ __   __ _ _ __ ___  ___ _ __   __ _| |
| '_ \ / _` | '__/ __|/ _ \ '_ \ / _` | |
| |_) | (_| | |  \__ \  __/ | | | (_| | |
| .__/ \__,_|_|  |___/\___|_| |_|\__,_|_|
|_|
                                           ^
------------------------------------------ |
"""

	print yellowtxt(banner)

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
				plugin_output TEXT,
				severity INTEGER
				)
	""")

def parse_nessus_file_db(nessus_doc, checkfor, db, all_issues, infoplugins):
	""" Parses nessus file and outputs to sqlite database """
	for reportHost in nessus_doc.getElementsByTagName("ReportHost"):
		# start individual host parse
		host_name = reportHost.attributes["name"].value
		for reportItem in reportHost.getElementsByTagName("ReportItem"):
			plugin_name =  reportItem.attributes['pluginName'].value
			host_port = reportItem.attributes['port'].value
			severity_rating = reportItem.attributes['severity'].value
			# new checks to show if all criticals are to be grabbed
			if all_issues == True:
				if severity_rating > 0 or plugin_name in infoplugins:
					# convert string to int and check is this is MEDIUM or higher
					print "The plugin is : " + redtxt(plugin_name) + " >> severity is " + yellowtxt(severity_rating) + " :: " + host_name
					# write to database
					plugin_output = reportItem.getElementsByTagName("plugin_output")

					# adds a check for the plugin output being empty ie equal to 0
					# in the db case this needs execute a db_query based on the check
					if len(plugin_output) > 0:
						plugin_output = plugin_output[0].firstChild.nodeValue

						# add this plugin output to the relevant table, formatting of output is kept when populating the table which is cool
						db.execute("INSERT INTO issues(host_ipaddress, host_name, host_port, plugin_name, plugin_output, severity) VALUES(?,?,?,?,?,?)", (host_name, host_name, host_port, plugin_name, plugin_output, int(severity_rating)))
					else:

						# execute the query without the plugin_output
						db.execute("INSERT INTO issues(host_ipaddress, host_name, host_port, plugin_name, severity) VALUES(?,?,?,?,?)", (host_name, host_name, host_port, plugin_name, int(severity_rating)))

					db.commit()

			else:
					# if this is something to check for in the hard coded list
					if plugin_name in checkfor:
						print greentxt("[::] Found: ") + host_name + " : " + redtxt(host_port) + " :: " + plugin_name + yellowtxt(" > "+  severity_rating)
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
						# ensure that everything is commited to the database
						db.commit()

def parse_nessus_file_txt(nessus_doc, checkfor):
	""" Writes out to the text file """
	hrline = "-------------------------------------------------------------------------------------\n"
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

def grab_directory_listing(directory_list):
	# Gets the files in a supplied directory
	file_collection = os.listdir(directory_list)
	return file_collection



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



def info_plugins():
	# Informational Plugins with 'severity = 0' within nessus XML file
	info_plugins = [
	"Patch Report",
	"OS Identification",
	"Microsoft Windows Summary of Missing Patches",
	"Patch Report"
	]

	return info_plugins



def check_for():
	# Nessus Plugin Names to check for that have severity of informational
	checkfor = [
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
	"SSL Version 2 and 3 Protocol Detection",
	"HP Data Protector 8.x Arbitrary Command Execution (HPSBMU03072)",
	"HP Data Protector 'EXEC_INTEGUTIL' Arbitrary Command Execution",
	"MS14-066: Vulnerability in Schannel Could Allow Remote Code Execution (2992611) (uncredentialed check) ",
	"MS15-034: Vulnerability in HTTP.sys Could Allow Remote Code Execution (3042553) (uncredentialed check)",
	"VMware vCenter Server Multiple Java Vulnerabilities (VMSA-2015-0003) (POODLE)",
	"SNMP Agent Default Community Name (public)",
	"Oracle TNS Listener Remote Poisoning",
	"NTP monlist Command Enabled",
	"NFS Share User Mountable"
	]

	return checkfor


#######################################################################
#	Main Function
#######################################################################


def main():
	banner()

	# Main Parser Setup
	parser = argparse.ArgumentParser(description="Parsenal File Options")
	main_parser = parser.add_argument_group('Main Program', 'Core Program Settings')
	main_parser.add_argument("-m", "--mode", help="Program mode (nessus, john)", required=True)
	# Group to require either file or directory
	input_choice_group = parser.add_argument_group()
	input_choice = input_choice_group.add_mutually_exclusive_group(required=True)
	input_choice.add_argument("-i", "--inputfile", help="Path to the file to parse")
	input_choice.add_argument("-dr", "--directory", help="Specify path to directory containing Files eg /path/folder/")


	# Nessus Parse Group
	nessus_parse_group = parser.add_argument_group('Nessus', 'Nessus File Parsing Options')

	nessus_parse_group.add_argument("-o", "--output", help="Specify the output type : <txt> <db>")
	nessus_parse_group.add_argument("-d", "--dbname", help="Specify the name of the SQLite3 database")
	nessus_parse_group.add_argument("-a", "--all_issues", action="store_true", default=False, help="Using '-a' or '--all_issues' will grab all the ISSUE output into the SQLite3 database")





	# John Parse Group
	john_parse_group = parser.add_argument_group('John', 'John File Parsing Options')
	john_parse_group.add_argument("--csvfile", help="Path to CSV File Output for logfile")

	# counts the supplied number of arguments and prints help if they are missing
	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)
	args = parser.parse_args()

	if args.mode == "nessus":
		# checking lists
		checkfor = check_for()
		infoplugins = info_plugins()

		if args.output == "txt":
			if args.directory:
				directory_to_parse = os.listdir(args.directory)
				print directory_to_parse
				for directory_file in directory_to_parse:
					if directory_file.endswith(".nessus"):
						directory_file = (str(args.directory) + directory_file)
						print directory_file
						nessus_doc = minidom.parse(directory_file)
						parse_nessus_file_txt(nessus_doc, checkfor)
			else:
				nessus_doc = minidom.parse(args.inputfile)
				parse_nessus_file_txt(nessus_doc, checkfor)
		else:
			# setup as sqlite db
			db_name = args.dbname
			db = sqlite3.connect(db_name)
			setupDB(db)

			all_issues = args.all_issues
			if not args.dbname:
				parser.print_help()
			if args.directory:
				directory_to_parse = os.listdir(args.directory)
				for directory_file in directory_to_parse:
					if directory_file.endswith(".nessus"):
						directory_file = (str(args.directory) + directory_file)
						nessus_doc = minidom.parse(directory_file)
						parse_nessus_file_db(nessus_doc, checkfor, db, all_issues, infoplugins)
			else:
				nessus_doc = minidom.parse(args.inputfile)
				parse_nessus_file_db(nessus_doc, checkfor, db, all_issues, infoplugins)

	elif args.mode == "john":
		print "The file to parse is a John the Ripper Log File"
		parse_john_log(args.inputfile, args.csvfile)
	else:
		print "Invalid File Type"
	hrline = "-------------------------------------------------------------------------------------\n"

if __name__ ==  "__main__":
	main()
