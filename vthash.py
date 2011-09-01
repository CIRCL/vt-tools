#!/usr/bin/python
import simplejson
import urllib
import urllib2
import sys
import time
import re
import os
import ConfigParser
sys.path.append('./modules/')
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

def sendHash(hash, dump):
    parameters = {"resource": hash,
                "key": vtlib.key}
    data = urllib.urlencode(parameters)
    try: 
        req = urllib2.Request(vtlib.url_get, data)
    except HTTPError, e:
        raise e
    except URLError, e:
        raise e
    response = urllib2.urlopen(req)
    json = response.read()
    response_dict = simplejson.loads(json)
    if (dump):
        print hash, "=", response_dict.get("report")
    else:
        report = response_dict.get("report")
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
    time.sleep(vtlib.sleeptime)

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
