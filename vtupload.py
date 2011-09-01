#!/usr/bin/python
import simplejson
import urllib
import urllib2
import sys
import time
import re
import os
sys.path.append('./modules/')
import vtlib 

def sendFile(file):
    host = "www.virustotal.com"
    fields = [("key", vtlib.key)]
    file_to_send = open(file, "rb").read()
    files = [("file", file, file_to_send)]
    json = vtlib.postfile.post_multipart(host, vtlib.url_scan, fields, files)
    print json

def showUsage():
    print 'CIRCL Virus Total tools - vtupload.py'
    print '    Usage example: [list of filenames] | ./vtupload.py'
    print '    Returns VT scan ID\'s for submittet files'

if (sys.stdin.isatty()):
    showUsage()
    sys.exit(1)
else:
    for file in sys.stdin:
        print "===\nProcessing file: ", file
        file = vtlib.isFile(file)
        if (not file):
            print "Not a valid file"
        else:
            try:
                sendFile(file)
            except Exception, e:
                print "File failed: " + file + ": ", e
        time.sleep(vtlib.sleeptime)
sys.exit(0)
