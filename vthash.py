#!/usr/bin/python
#
# vt-tools: vthash.py
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
import ConfigParser

def guesspath():
    pp = os.path.realpath(sys.argv[0])
    lpath = os.path.split(pp)
    return lpath[0]

modulespath = guesspath() + "/modules/"
sys.path.append(modulespath)
import vtlib

regex_md5  = "^[0-9a-f]{32}$"
regex_sha1 = "^[0-9a-f]{40}$"

def showUsage():
    print 'CIRCL Virus Total tools - vthash.py'
    print '    Usage examples:'
    print '    MD5|SHA1 [MD5|SHA1] | ./vthash.py'
    print '    or'
    print '    ./vthash.py MD5|SHA1 [MD5|SHA1]'
    print '    Specify `--dump\' option for json output' 
    print '    Returns VT results for submittet hashes'

def isHash(hash):
    hash = hash.strip()
    if ((not re.match(regex_md5, hash)) and (not re.match(regex_sha1, hash))):
        return None
    else:
        return hash

def outputResult(hash, report):
    print "VirusTotal result for hash:", hash
    if (api == "public"):
        if (report == None):
            print "Not uploaded, yet"
        else:
            scan_time    = report[0]
            scan_results = report[1]
            scan_entries = len(scan_results)
            detections = 0
            for product, detection in scan_results.iteritems(): 
                if (detection != ""):
                    if (len(product) > 11):
                        print product + ":\t" + detection
                    elif (len(product) > 6):
                        print product + ":\t\t" + detection
                    else:
                        print product + ":\t\t\t" + detection
                    detections += 1
            percent = round(detections * 100 / int(scan_entries)) 
            print "Scanned: " + str(scan_time) + " - " + str(scan_entries) + " scans - " + str(detections) + " detections (" + str(percent) + "%)"
    elif (api == "private"):
        if (report.get('result') == 0):
            print "Not uploaded, yet"
        else:
            report_link      = report.get('last-scan-permalink')
            report_resource  = report.get('resource')
            report_result    = report.get('result')
            report_reports   = report.get('last-scan-report')
            report_tool_info = report.get('tool-info')
            report_firstseen = report.get('first-seen')
            report_lastseen  = report.get('last-seen')
            report_size      = report.get('size')
            report_filenames = report.get('filenames')
            report_unique_submissions = report.get('unique-submissions')
            report_tags      = report.get('tags')
            scan_entries = len(report_reports)
            detections = 0
            print "Link: ", report_link
            repfilesout = "Reported filenames:\t"
            if (report_filenames != None):
                for filename in report_filenames:
                    repfilesout += filename + ", "
            else:
                repfilesout += "-"
            print repfilesout
            print "Size:\t\t\t", report_size
            print "Unique submissions:\t", report_unique_submissions
            utout = "VT-user tags:\t\t"
            if (len(report_tags) != 0):
                for tag in report_tags:
                    utout += tag
            else:
                utout += "-"
            print utout
            print "First seen:\t\t" + str(report_firstseen)
            print "Last seen:\t\t" + str(report_lastseen)
            # Debug output:
            #print report_tool_info
            if (report_tool_info.get('trid') != None): 
                print "File info:"
                print report_tool_info.get('trid')
            if (report_tool_info.get('sections') != None):
                print "Sections:"
                print "Section\t\tVirt. Address\tVirt. Size\tRaw Size\tEntropy\tMD5"
                for a, b, c, d, e, f in report_tool_info.get('sections'):
                    print a + "\t\t" + b + "\t\t" + c + "\t\t" + d + "\t\t" + e + "\t" + f
            if (report_tool_info.get('sigcheck') != None):
                print "Signature check:"
                for key, value in report_tool_info.get('sigcheck').iteritems():
                    print "  " + key + ":\t\t" + value
            if (report_tool_info.get('imports') != None):
                print "Imports:"
                for key, value in report_tool_info.get('imports').iteritems():
                    impout = "  " + key + ":\t\t"
                    for function in value:
                        impout += function + ", "
                    print impout
            if (report_tool_info.get('exiftool') != None):
                print "Exiftools:"
                for key, value in report_tool_info.get('exiftool').iteritems():
                    if ((value != None) and (value != "")):
                        if (len(key) > 12):
                            print "  " + key + ":\t" + value
                        elif (len(key) > 5):
                            print "  " + key + ":\t\t" + value
                        elif (len(key) > 3):
                            print "  " + key + ":\t\t\t" + value
            
            if (report_tool_info.get('deepguard') != None): 
                print "Deepguard info:\t\t" + report_tool_info.get('deepguard')
            if (report_tool_info.get('suspicious-insight') != None): 
                print "Suspicious-insight:\t" + str(report_tool_info.get('suspicious-insight'))
            for product, detection in report_reports.iteritems():
                malware   = detection[0]
                signature = detection[1]
                date      = detection[2]
                if (malware != None):
                    if (len(product) > 13):
                        print product + ":\t" + malware + "\t(" + signature + " from " + date + ")"
                    elif (len(product) > 6):
                        print product + ":\t\t" + malware + "\t(" + signature + " from " + date + ")"
                    else:
                        print product + ":\t\t\t" + malware + "\t(" + signature + " from " + date + ")"
                    detections += 1
            percent = round(detections * 100 / int(scan_entries))
            print "Statistics:\t\t" + str(scan_entries) + " scans - " + str(detections) + " detections (" + str(percent) + "%)"

def sendHash(hash, dump):
    if (api == "public"):
        parameters = {"resource": hash,
                    "key": vtlib.public_key}
    elif (api == "private"):
        parameters = {"resources": hash,
                      "apikey": vtlib.private_key}
    data = urllib.urlencode(parameters)
    if (api == "public"):
        try: 
            req = urllib2.Request(vtlib.public_url_get, data)
        except Exception, e:
            raise e
    if (api == "private"):
        try: 
            req = urllib2.Request(vtlib.private_url_get, data)
        except Exception, e:
            raise e
    response = urllib2.urlopen(req)
    json = response.read()
    response_dict = simplejson.loads(json)
    if (api == "public"):
        if (dump):
            print hash, "=", response_dict.get("report")
        else:
            report = response_dict.get("report")
            if (report == None):
                outputResult(hash, None)
            else:
                outputResult(hash, report)
    elif (api == "private"):
        if (dump):
            print hash, "=", response_dict
        else:
            report = response_dict[0]
            if (report == None):
                outputResult(hash, None)
            else:
                outputResult(hash, report)

def processHash(hash, dump):
    orig_hash = hash
    hash = isHash(hash)
    if (not dump):
        print "Processing hash: ", hash
    if (not hash):
        if (not dump):
            print "Not a valid MD5 or SHA1 hash"
        else:
            print orig_hash, "= []"
    else:
        try:
            sendHash(hash, dump)
        except urllib2.HTTPError, e:
            if (e.code == 403): 
                print "API key not valid. Please check."
        except Exception, e:
            print "Hash failed: " + hash + ": ", str(e)
    time.sleep(sleeptime)

if (sys.argv[0] == "vthash-pro.py"):
    api = "private"
    if (not vtlib.private):
        print "Please check configuration for private API"
        sys.exit(2)
    sleeptime = vtlib.private_sleeptime
else:
    api = "public"
    if (not vtlib.public):
        print "Please check configuration for public API"
        sys.exit(2)
    sleeptime = vtlib.public_sleeptime

if (sys.stdin.isatty()):
    if (len(sys.argv) < 2):
        showUsage()
        sys.exit(1)
    else:
        sys.argv.pop(0)
        if (sys.argv[0] == "--dump"):
            sys.argv.pop(0)
            if (len(sys.argv) < 1):
                showUsage()
                print "Error: please specify hash"
                sys.exit(1)
            else:
                for hash in sys.argv:
                    processHash(hash, 1)
                sys.exit(0)
        else:
            for hash in sys.argv:
                processHash(hash, 0)
            sys.exit(0)
else:
    if (len(sys.argv) > 1):
        if (sys.argv[1] == "--dump"):
            for hash in sys.stdin:
                processHash(hash, 1)
    else:
        for hash in sys.stdin:
            processHash(hash, 0)
sys.exit(0)
