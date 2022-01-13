# ASA-NAT-Parser

Script that reads ASA "sh run nat" and "show run object" CLI outputs and parses the information into more easily readable format. Instead of having to skip back and forth between NAT statements and network/service objects, the script outputs both "at the same time". This makes it easier for engineers understand what an organization is doing with each NAT statement. 

Currently the script supports manual and auto NATs, and outputs them into a JSON format. Next steps are to print this output into a file, or display into a webpage. Additionally, future state would include netmiko/paramiko usage that gathers the outputs from ASAs automatically.

FYI: All NAT statements seen in this repo are from a home lab environment :) 
