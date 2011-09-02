#!/usr/bin/python
#
# vt-tools: vtlib.py
# Licensed under the GNU General Public License v3
# (C) 2011, CIRCL, Smile GIE
# (C) Sascha Rommelfangen
# http://www.circl.lu
# https://github.com/CIRCL/vt-tools

import os
import ConfigParser
import postfile

def isFile(file):
    file = file.strip()
    if (not os.path.isfile(file)):
        return None
    else:
        return file

# Your VirusTotal key
config_file = os.path.expanduser('~/.vt-tools.conf')

if (isFile(config_file)):
    try:
        config = ConfigParser.RawConfigParser()
    except Excetion, e:
        print e
        sys.exit(2)
    try:
        config.read(config_file)
    except ConfigParser.MissingSectionHeaderError:
        print "Missing section header [Global] in configuration file"
        sys.exit(2)
    try:
        key = config.get('Global', 'key')
    except ConfigParser.NoOptionError:
        print "Missing key = YOURAPIKEY section in configuration file"
        sys.exit(2)
    try:
        api = config.get('Global', 'api')
    except ConfigParser.NoOptionError:
        print "Missing api = private|public section in configuration file"
        sys.exit(2)
    try:
        requests = int(config.get('Global', 'requests'))
    except ConfigParser.NoOptionError:
        print "Missing requests = 20 (default) section in configuration file"
        sys.exit(2)
else:
    print "Configuration file not found at ~/.vtapi.key"
    sys.exit(1)

sleeptime = 60 * 5 / requests

if (api == "public"):
    # The VirusTotal public URL
    url_get  = "https://www.virustotal.com/api/get_file_report.json"
    url_scan = "http://www.virustotal.com/api/scan_file.json"
elif (api == "private"):
    # The VirusTotal private URL
    url_get = "http://api.vtapi.net/vtapi/get_file_reports.json"
else:
    print "Configuration: api = must contain private or public"
    sys.exit(2)

