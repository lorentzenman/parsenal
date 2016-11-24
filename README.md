# parsenal
Parsing tool for extracting data from XML based tool output like Nessus.

parsenal -h


# [::] Nessus
Using the sqlite database it is possible to run queries and output the results to text files for report inclusion. If all issues are specified then this will grab all plugins and put them into the database. This gives maximum flexibility in query the data held within the nessus file(s).



# [*] Nessus

Usage Examples

parsenal --dbname parsed.db --all_issues /path/to/file.nessus


::  Parse individual Nessus file into a database called 'parsed.db'
parsenal -d parsed.db --all_issues -i /path/to/file.nessus

:: Parse directory of Nessus files into a database called 'parsed.db'
parsenal -d parsed.db --all_issues -dr /path/to/dir

# Access Interactive Console without parsing file

parsenal -d parsed.db --console


# Using Interactive SQL Console
:: An interactive console has now been built into the tool where separate SQLite query tools are not available
:: Invoked with the --console or -c option

Parsenal Console Commands
------------------------------------------

> help or ?             : Prints this help menu
> output <filename>     : outputs the query to a filetype (csv, txt, doc)
> get <common_plugin>   : get common plugins (patches, selfsigned, rc4, sslversion)
> query "sql query"     : query "select distinct plugin_name from issues"   
> select                : shorthand keyword for 'select' database queries
> hosts                 : shows all the unique host IP addresses in the database
> plugins               : lists all plugin names in the current database
> show                  : show output status
> history               : show command history
> tables                : shows database table structure
> exit or quit          : exit the console


# Using shortcuts for common plugins
Calling 'get' without any parameters shows frequent shortcode code lists

[!] Usage : get <shortcode>
[!] Usage : get windows_patches
[!] Usage : get selfsigned
[!] Usage : get rc4
[!] Usage : get sslversion

# Setting Output Files

1) show defines current output setting

2) once completed output set the output switch back to stdout
output stdout



# Direct SQLite Example Queries

:: Set output type and path
.output /root/output.txt

:: Plugin Output
select host_name, host_port, plugin_output from issues where plugin_name = "SSL Self-Signed Certificates";

:: Reset back to stdout
.output stdout

:: Based on Severity - Grabs MEDIUM rating and above
select host_name, plugin_name from issues where severity > 2;

:: List all plugin_names found
select distinct plugin_name from issues;





