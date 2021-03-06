# packet_analysis_v1.2

Python based CLI for capturing packets on linux and saving data. This is a starting point for
this project, but the goal is for this project to evolve into an IPS.

#Usage
----
Clone repo to a linux machine that has python. All you need is pythons standard library for this code.
In the directory you cloned this repo to, run setup.py first, and then run the main program packet_cap.py.
You will need sudo privilages to run packet_cap.py. Without any command line arguments passed, the program 
will print a usage message and exit. For saving packet data to file, pass the "-s" flag, and/or to print packet data
to the console pass the "-p" flag to the command line. 

#Big TODO's:
- realtime analysis of packet data
- create a baseline for a specified environment

#Little TODO'S:
- make this readme better (usage sample)
- finish decoding options for icmpv6
- finish decoding icmpv4 headers

#Medium TODO's:
- make storage.py script relevant or scrap it
- create base class for building packets
