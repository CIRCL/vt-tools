CIRCL VirusTotal tools

Tools to interact with VirusTotal

All the tools require an API key which you can get 
from http://www.virustotal.com/ for free for the
public API. It also exists a private API. See 
VirusTotal for more information.
The number of requests is usually limited to
20 per 5 minutes. Higher intervalls are possible
upon request.

A configuration file at ~/.vt-tools.conf is mandatory.
It contains the following: 
  [Global]
  key = YOURAPIKEY
  api = public 		# or private
  requests = 20		# or higher, like 300

An example configuration file is included.

Description of the tools:
* vthash.py
  send one or multiple hashes (MD5/SHA1) to VirusTotal
  and get a human readable list of detections back and
  some statistics.
  The --dump option returns the list in a computer 
  readable format.
  Example: md5 test/* | cut -d"=" -f2 | vthash.py

* vtupload.py
  send one or more files to VirusTotal. Returns a unique
  ID to requests the report later. Scan might need some
  time. Instead of getting the report, using vthash.py
  after uploading does work, too.
  Example: ls test/* | vtupload.py
