# parsenal
Parsing tool for extracting data from XML based tool output like Nessus.

parsenal -h


# [::] Nessus
Using the sqlite database it is possible to run queries and output the results to text files for report inclusion. If all issues are specified then this will grab all plugins and put them into the database. This gives maximum flexibility in query the data held within the nessus file(s).

When using text output, the tool uses the hardcoded list in the script and it will only grab the output from these plugins.

# [::] John
Using this option will take a john log and then write out the username and password together with the timecracked.


# [*] Nessus

Usage Examples

parsenal --output db --dbname parsed.db --all_issues nessus /path/to/file.nessus

:: Note that when using '--output db' the database gets appended so you can parse a number of files in a loop

for nessus in $(ls | grep .nessus);do parsenal --output db --dbname parsed --all_issues nessus $nessus;done


# SQLite Example Queries

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


# [*] John

Usage Examples

parsenal --csvfile /path/to/csv.file john /path/to/john.log



