# packet_analysis_v1.2

Python based CLI for capturing packets on linux and saving data. It is useful for analyzing
network traffic on a specific interface. 

#Usage
----
Clone repo to a linux machine that has python. All you need is pythons standard library for this code.
In the directory you cloned this repo to, run setup.py first, and then run the main program packet_cap.py.
You will need sudo privilages to run packet_cap.py. Without any command line arguments passed, the program 
will print a usage message and exit. For saving packet data to file, pass the "-s" flag, and/or to print packet data
to the console pass the "-p" flag to the command line. 

