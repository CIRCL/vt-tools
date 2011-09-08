#!/usr/bin/python
#
# vt-tools: vtupload.py
# Licensed under the GNU General Public License v3
# (C) 2011, CIRCL, Smile GIE
# (C) Sascha Rommelfangen
# http://www.circl.lu
# https://github.com/CIRCL/vt-tools

import simplejson
import urllib
import urllib2
import sys
import time
import re
import os

def guesspath():
    pp = os.path.realpath(sys.argv[0])
    lpath = os.path.split(pp)
    return lpath[0]

modulespath = guesspath() + "/modules/"
sys.path.append(modulespath)
import vtlib

def sendFile(file):
    host = "www.virustotal.com"
    fields = [("key", vtlib.public_key)]
    file_to_send = open(file, "rb").read()
    files = [("file", file, file_to_send)]
    json = vtlib.postfile.post_multipart(host, vtlib.public_url_scan, fields, files)
    print json

def showUsage():
    print 'CIRCL Virus Total tools - vtupload.py'
    print '    Usage example: [list of filenames] | ./vtupload.py'
    print '    Returns VT scan ID\'s for submitted files'

if (sys.stdin.isatty()):
    showUsage()
    sys.exit(1)
else:
    for file in sys.stdin:
        print "Processing file: ", file
        file = vtlib.isFile(file)
        if (not file):
            print "Not a valid file"
        else:
            try:
                sendFile(file)
            except Exception, e:
                print "File failed: " + file + ": ", e
sys.exit(0)
