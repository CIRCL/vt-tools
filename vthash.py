#!/usr/bin/python
import simplejson
import urllib
import urllib2
import sys
import time
import re
import os
import ConfigParser


# Request rate (usually 20 per 5 minutes)
requests = 300
sleeptime = 60 * 5 / requests 
regex_md5  = "^[0-9a-f]{32}$"
regex_sha1 = "^[0-9a-f]{40}$"

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
else:
    print "Configuration file not found at ~/.vtapi.key"
    sys.exit(1)

if (api == "public"):
    # The VirusTotal public URL
    url = "https://www.virustotal.com/api/get_file_report.json"
elif (api == "private"):
    # The VirusTotal private URL
    url = "http://api.vtapi.net/vtapi/get_file_reports.json"
else:
    print "Configuration: api = must contain private or public"
    sys.exit(2)

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
                "key": key}
    data = urllib.urlencode(parameters)
    try: 
        req = urllib2.Request(url, data)
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
    time.sleep(sleeptime)

if (key == ""):
    print "In order to make this work, request an API key from VirusTotal"
    print "and paste it as value for the 'key' variable in the configuration file."
    sys.exit(2)
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
