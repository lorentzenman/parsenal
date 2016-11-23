#!/usr/bin/python
""" Parsenal is a Nessus Output File Parser using Python
Author  : Matt Lorentzen
Twitter : @lorentzenman 
Original Date: September 2014
"""

#from xml.dom import minidom
import xml.etree.cElementTree as ET
#TODO : add in docx support to output word files
import sqlite3
import sys
import argparse
import csv
import os
import time

def banner():

    banner = """
                                       _
 _ __   __ _ _ __ ___  ___ _ __   __ _| |
| '_ \ / _` | '__/ __|/ _ \ '_ \ / _` | |
| |_) | (_| | |  \__ \  __/ | | | (_| | |
| .__/ \__,_|_|  |___/\___|_| |_|\__,_|_|
|_|
                                      v2.0 ^
------------------------------------------ |
"""

    print yellowtxt(banner)

#######################################################################
#   Parse Files - Nessus
######################################################################

def setupDB(db_cursor):
    """ setup tables """
    cur = db_cursor

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


def parse_nessus_file(nessus_doc, db_cursor, all_issues, infoplugins):
    """ Parses nessus file and sends to write function for  output to sqlite database """
    # debug  print
    for event,elem in ET.iterparse(nessus_doc):
        if event == "end":
            if elem.tag == "ReportHost":
                host_name = elem.attrib["name"]
                for child in elem.iter():
                    if child.tag == "ReportItem":
                        # yeah :) level up dict comprehension
                        item_info = { k : v for k, v in child.items() if k.startswith('pluginName') or k.startswith('severity') or k.startswith('port')} 
                        plugin_name = item_info["pluginName"]
                        severity_rating = int(item_info["severity"])
                        port = item_info["port"]
                    elif child.tag == "plugin_output":
                        if child.text:
                            plugin_output = child.text
                        else:
                            # assign the value to None string
                            plugin_output = "None"
                        print "[!] " + plugin_name + " with a severity of " + str(severity_rating) + " on port " + port
                        #print plugin_output
                # insert into database
                # check to see if all_issues :: ie severity rating of > 0
                        if severity_rating > 0 or plugin_name in infoplugins:
                            db_cursor.execute("INSERT INTO issues(host_ipaddress, host_name, host_port, plugin_name, plugin_output, severity) VALUES(?,?,?,?,?,?)", (host_name, host_name, port, plugin_name, plugin_output, severity_rating))
                            db_cursor.commit() 
              # clear the assigned memory for this loop    
                elem.clear()



def write_to_database(plugin_name, severity_rating, port, plugin_output, db):
    """ writes to the database """


# ---- [ Plugin Output ] ---- #

def info_plugins():
    # Informational Plugins with 'severity = 0' within nessus XML file
    info_plugins = [
    "Patch Report",
    "OS Identification",
    "Microsoft Windows Summary of Missing Patches",
    "Patch Report"
    ]

    return info_plugins


def grab_directory_listing(directory_list):
    # Gets the files in a supplied directory
    file_collection = os.listdir(directory_list)
    return file_collection


#######################################################################
#   Console Functions 
#######################################################################


def launch_console(db_cursor):
    """ Calls the initial console function """
    banner()
    console_banner = """    
Parsenal Interactive SQL Console
------------------------------------------
[!] type 'help' or '?' for command list 

"""
    
    print console_banner
    
    output_to_file = False
    output_file = ""
    #output = None
        
    # ---- [ Console Loop ] ---- #
    while True:
        command_history = []
        # console input
        command = raw_input("#> ")
        
        if command.startswith("help") or command.startswith("?"):
            console_help()
        
        elif command.startswith("output"):
            # break this out to command
            if len(command.split()) < 2:
                print "[!] Usage : output /path/to/file.ext"
                print "[!] Usage : output stdout"
            else:
                #TODO need to add a check for windows paths and replace slashes
                output_file = command.split()[1]
                
                if output_file == "stdout":
                    print "[!] Outputting query results to console"
                    output_to_file = False
                    output_file = "console"
                    print "[!] Output to File : " + str(output_to_file)
                else:
                    print "[*] Output file set to %s." %output_file
                    output_to_file = True
                    print "[!] Output to File : " + str(output_to_file)

        elif command.startswith("show"):
            print "The following file is configured for output : " + output_file
            print "Output to File : " + str(output_to_file)

        elif command.startswith("get"):
            if len(command.split()) < 2:
                print "[!] Usage : get <shortcode>"
                print "[!] Usage : get windows_patches"
                print "[!] Usage : get selfsigned"
                print "[!] Usage : get rc4"
                print "[!] Usage : get sslversion"
            else:
                shortcut = command.split()[1]
                sql_query = get_output(shortcut)
                if output_to_file == True:
                    output = open(output_file, 'w')
                    print "[!] This will be written to : " + output_file
                    for result in console_sql_query(sql_query, db_cursor):
                        print result
                        output.write(result + '\n')
                    output.close()
                
                else:       
                    for result in console_sql_query(sql_query, db_cursor):
                        print result
        

        elif command.startswith("query"):
            # rewrite this to accomodate straight select statement
            if len(command.split()) < 2:
                print "SQL command format : query select * from issues"
                print "query sql_query"
            else:
                # Clean SQL query before passing : means users can write the query however they want, and then it gets cleansed
                sql_query = command.split()[1:]
                sql_query = " ".join(sql_query)

                if sql_query.startswith('"'):
                    sql_query.replace('"', '')
                if not sql_query.endswith(';'):
                    sql_query = sql_query + ';'
    
            if output_to_file == True:
                output = open(output_file, 'w')
                print "[!] This will be written to : " + output_file
                for result in console_sql_query(sql_query, db_cursor):
                    print result
                    output.write(result + '\n')
                output.close()
            
            else:       
                for result in console_sql_query(sql_query, db_cursor):
                    print result
    
        elif command.startswith("select"):
            # Clean SQL query before passing : means users can write the query however they want, and then it gets cleansed
                print "[!] Command starts with 'select' : assuming you want an SQL query statement.\n"
                sql_query = command

                if sql_query.startswith('"'):
                    sql_query.replace('"', '')
                if not sql_query.endswith(';'):
                    sql_query = sql_query + ';'
                
                # as above, check for output file
                if output_to_file == True:
                    output = open(output_file, 'w')
                    print "[!] This will be written to : " + output_file
                    for result in console_sql_query(sql_query, db_cursor):
                        print result
                        output.write(result + '\n')
                    output.close()
    
                else:       
                    for result in console_sql_query(sql_query, db_cursor):
                        print result
    
        elif command.startswith("hosts"):
            sql_query = "select distinct host_name from issues;"
            for result in console_sql_query(sql_query, db_cursor):
                print result
    
        
        elif command.startswith("plugins"):
            sql_query = "select distinct plugin_name from issues;"
            for result in console_sql_query(sql_query, db_cursor):
                print result
    
        elif command.startswith("tables"):
            print_database_table_structure()
    
        elif command.startswith("exit"):
            print "Exiting Parsenal"
            sys.exit(0) 

        else:
            # place holder for other command
            print command

        
def console_sql_query(sql_query, db_cursor):
    """ Performs console SQL query """
    sql_query_results = []  
    for row in db_cursor.execute(sql_query):
        #write_console_output(row)
        sql_query_results.append(row)

    # create a clean list
    clean_results = []
    
    # >> this was pain = learning about sqlite and unicode return strings 
    # original idea was to use the text_factory attribute in sqlite3 but as nessus 'could' store different data
    # I thought it was best to leave the default, and then encode and clean the return queries as I am writing this to files
    ## clean_console_output = [s.encode('ascii', 'ignore') for s in sql_query_results]
    # note the cast to string 'str(s).encode' to avoid the 'int' encoding problem
    # now run through list and display results
    for result in sql_query_results:
        # gets the finding/target list
        # encodes the list to remove unicode
        result = [str(s).encode('utf-8') for s in result]
        # check to see if we are writing to file
        for clean_output in result:
            #print "write : " + output      
            # now print to console
            clean_results.append(clean_output)
    
    return clean_results    


def get_output(shortcut):
    """ Short codes for getting quick output for patches,selfsigned """
    # really nice way of returning output
    # select 'Host : ' || host_name || ' : Port : ' || host_port, plugin_output from issues where plugin_name = 'SSL Self-Signed Certificate';

    sql_query = ""

    if shortcut == 'plugins':
        sql_query = "select distinct plugin_name from issues;"

    elif shortcut == 'windows_patches':
        sql_query = "select host_name, plugin_output from issues where plugin_name = 'Microsoft Windows Summary of Missing Patches';"

    elif shortcut == 'selfsigned':
        sql_query = "select host_name, host_port, plugin_output from issues where plugin_name = 'SSL Self-Signed Certificate';"

    elif shortcut == 'rc4':
        sql_query = "select host_name, host_port, plugin_output from issues where plugin_name = 'SSL RC4 Cipher Suites Supported (Bar Mitzvah)';"

    elif shortcut == 'sslversion':
        sql_query = "select host_name, host_port, plugin_output from issues where plugin_name = 'SSL / TLS Versions Supported';"
    
    #elif shortcut == 
    #   "select distinct host_name from issues;"

    return sql_query
    

def print_command_history(command_history):
    """ Prints command history """
    for previous_command in command_history:
        print previous_command


def print_database_table_structure():
    """ Shows Issues database structure """
    table_structure = """
[!] The 'issues' database is configured with the following fields

host_name   VARCHAR(255),
host_port   INTEGER,
plugin_name     VARCHAR(255),
plugin_output   TEXT,
severity    INTEGER


"""
    print table_structure



def console_help():
    """ Console help functions """
    
    console_help_menu = """

[] Parsenal Console Commands
------------------------------------------

> help or ?         : Prints this help menu
> output <filename>     : outputs the query to a filetype (csv, txt, doc)
> get <common_plugin>   : get common plugins (patches, selfsigned, rc4, sslversion)
> query "sql query"     : query "select distinct plugin_name from issues"   
> select        : shorthand keyword for 'select' database queries
> hosts         : shows all the unique host IP addresses in the database
> plugins       : lists all plugin names in the current database
> show          : show output status
> history       : show command history
> tables        : shows database table structure
> exit          : exit the console

"""
    print console_help_menu

#######################################################################
#   Main Function
#######################################################################


def main():
    banner()

    # Main Parser Setup
    parser = argparse.ArgumentParser(description="Parsenal File Options")
    main_parser = parser.add_argument_group('Main Program', 'Core Program Settings')
    #main_parser.add_argument("-m", "--mode", help="Program mode (nessus, john)", required=True)
    # Group to require either file or directory
    input_choice_group = parser.add_argument_group()
    input_choice = input_choice_group.add_mutually_exclusive_group(required=True)
    input_choice.add_argument("-i", "--inputfile", help="Path to the file to parse")
    input_choice.add_argument("-dr", "--directory", help="Specify path to directory containing Files eg /path/folder/")


    # Nessus Parse Group
    nessus_parse_group = parser.add_argument_group('Nessus', 'Nessus File Parsing Options')

    #nessus_parse_group.add_argument("-o", "--output", help="Specify the output type : <txt> <db>")
    nessus_parse_group.add_argument("-d", "--dbname", help="Specify the name of the SQLite3 database")
    nessus_parse_group.add_argument("-a", "--all_issues", action="store_true", default=False, help="Using '-a' or '--all_issues' will grab all the ISSUE output into the SQLite3 database")
    nessus_parse_group.add_argument("-c", "--console", action="store_true", default=False, help="Launches an interactive SQL console with built in help. Used to export data out of the SQL database for reporting")

    # counts the supplied number of arguments and prints help if they are missing
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()

    # setup as sqlite db
    db_name = args.dbname
    db = sqlite3.connect(db_name)
    # create cursor
    db_cursor = db.cursor()
    # create tables 
    setupDB(db_cursor)
    
    # TODO : keep the all_issues option, this cn be used as a choice, based on severity, so 0 = info, 1 = low, 2 = medium, 3 = high, 4 = critical
    all_issues = args.all_issues
    infoplugins = info_plugins()
    
    if not args.dbname:
        parser.print_help()
    if args.directory:
        list_directory = args.directory
        if not list_directory.endswith("/"):
            list_directory = list_directory + "/"
        directory_to_parse = os.listdir(list_directory)
        for directory_file in directory_to_parse:
            if directory_file.endswith(".nessus"):
                directory_file = (str(args.directory) + directory_file)
                nessus_doc = directory_file
                parse_nessus_file(nessus_doc, db, all_issues, infoplugins)
    else:
        nessus_doc = args.inputfile
        parse_nessus_file(nessus_doc, db, all_issues, infoplugins)

    # now check to see if console switch was added
    if args.console:
        launch_console(db_cursor)       
    
    else:
        print "Invalid File Type"
    hrline = "-------------------------------------------------------------------------------------\n"


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

#################################################################

if __name__ ==  "__main__":
    main()

