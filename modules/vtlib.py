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
import sys

def isFile(file):
    file = file.strip()
    if (not os.path.isfile(file)):
        return None
    else:
        return file

# Your VirusTotal key
config_file = os.path.expanduser('~/.vt-tools.conf')

public  = False
private = False
public_sleeptime  = 15
private_sleeptime = 1

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
        public = config.get('Global', 'public')
    except:
       pass
    if (public):
        try:
            public_key = config.get('Global', 'public_key')
        except ConfigParser.NoOptionError:
            print "Missing public_key = YOURAPIKEY section in configuration file"
            sys.exit(2)
        try:
            public_requests = int(config.get('Global', 'public_requests'))
        except ConfigParser.NoOptionError:
            print "Missing public_requests = 20 (default) section in configuration file"
            sys.exit(2)
        public_sleeptime = 60 * 5 / public_requests
        public_url_get  = "https://www.virustotal.com/api/get_file_report.json"
        public_url_scan = "http://www.virustotal.com/api/scan_file.json"
    try:
        private = config.get('Global', 'private')
    except:
        pass
    if (private):
        try:
            private_key = config.get('Global', 'private_key')
        except ConfigParser.NoOptionError:
            print "Missing private_key = YOURAPIKEY section in configuration file"
            sys.exit(2)
        try:
            private_requests = int(config.get('Global', 'private_requests'))
        except ConfigParser.NoOptionError:
            print "Missing private_requests = 300 (default) section in configuration file"
            sys.exit(2)
        private_sleeptime = 60 * 5 / private_requests
        private_url_get = "http://api.vtapi.net/vtapi/get_file_infos.json"
else:
    print "Configuration file not found at ~/.vt-tools.conf"
    sys.exit(1)
