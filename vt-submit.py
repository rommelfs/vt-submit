#!/usr/bin/env python

__description__ = 'Submit files and comments to VirusTotal or lookup scan results by file or hash'
__author__ = 'Sascha Rommelfangen'
__version__ = '0.0.2'
__date__ = '2016/06/02'

"""
    vt-submit.py, inspired by earlier work of myself and code by Didier Stevens.
    
    Purposes: 
                Get results from VirusTotal for a given file
                Upload file to VirusTotal if explicitly specified
                Add user comment to resource at VirusTotal
    
    Copyright:  Sascha Rommelfangen, CIRCL, Smile g.i.e, 2016
    
    License:    GNU General Public License v2.0
"""

import optparse
import urllib
import urllib2
import time
import sys
import os
import hashlib
import re

try:
    import poster
except:
    print('Module poster missing: https://pypi.python.org/pypi/poster')
    sys.exit(22)
try:
    import json
    jsonalias = json
except:
    try:
        import simplejson
        jsonalias = simplejson
    except:
        print('Modules json and simplejson missing')
        sys.exit(22)

home = os.path.expanduser('~')
keyfile = home + '/.virustotal.key'
try:
    api_key = open(keyfile)
    VIRUSTOTAL_API2_KEY = api_key.read().strip()
    api_key.close()
except:
    print "Couldn't open virustotal key file ~/.virustotal.key"
    sys.exit(99)

VIRUSTOTAL_SCAN_URL     = 'https://www.virustotal.com/vtapi/v2/file/scan'
VIRUSTOTAL_LOOKUP_URL   = 'https://www.virustotal.com/vtapi/v2/file/report'
VIRUSTOTAL_COMMENT_URL  = "https://www.virustotal.com/vtapi/v2/comments/put"

regex_md5    = "^[0-9a-fA-F]{32}$"
regex_sha1   = "^[0-9a-fA-F]{40}$"
regex_sha224 ="^[0-9a-fA-F]{56}$"
regex_sha256 ="^[0-9a-fA-F]{64}$"

def isHash(hash):
    hash = hash.strip()
    if ((not re.match(regex_md5, hash)) and (not re.match(regex_sha1, hash)) and (not re.match(regex_sha224, hash)) and (not re.match(regex_sha256, hash))):
        return None
    else:
        return hash

def VTHTTPHashRequest(filename, options):
    positives = 0
    total = 0
    date = ""
    permalink = ""
    hash = None
    if options.hash:
        hash = isHash(filename)
        if hash is None:
            print "Input was specified to be a hash, but was not parsed as valid hash"
            sys.exit(3)
    else:
        try:
            hash = hashlib.sha256(open(filename, 'rb').read()).hexdigest()
        except:
            print "Cannot calculate hash from file %s." % filename
            sys.exit(2)

    parameters = {  "resource": hash,
                    "apikey": VIRUSTOTAL_API2_KEY}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(VIRUSTOTAL_LOOKUP_URL, data)
    try:
        response = urllib2.urlopen(req)
    except:    
        print "Cannot communicate with VirusTotal (Network? VirusTotal key?). Aborting."
        sys.exit(1)
    string = response.read().decode('utf-8')
    response = False
    try:
        json_obj = json.loads(string)
        response = json_obj['response_code']
        positives = json_obj['positives']
        total = json_obj['total']
        date = json_obj['scan_date']
        permalink = json_obj['permalink']
    except:
        response = False
    if response == 1:
        scans = json_obj['scans']
        print "File is known by VirusTotal since %s with detection ratio of %i/%i" % (date, positives, total)
        if options.verbose:
            print "MD5:\t%s" % json_obj['md5']
            print "SHA1:\t%s" % json_obj['sha1']
            print "SHA256:\t%s" % json_obj['sha256']
            for product, results in scans.iteritems():
                if results['detected']:
                    print "    {0:17} {1:40} {2}".format(product, results['result'], results['update'])
        print permalink
        response = True
    else:
        print "File unknown at VirusTotal"
    return (response, hash, positives, total, date, permalink)

def VTHTTPScanRequest(filename, options):
    file = None
    try:
        file = open(filename, 'rb')
        data = file.read()
        postfilename = filename
    except IOError as e:
        return None, str(e)
    finally:
        if file:
            file.close()
    params = []
    params.append(poster.encode.MultipartParam('apikey', VIRUSTOTAL_API2_KEY))
    params.append(poster.encode.MultipartParam('file', value=data, filename=os.path.basename(postfilename)))
    datagen, headers = poster.encode.multipart_encode(params)
    req = urllib2.Request(VIRUSTOTAL_SCAN_URL, datagen, headers)
    try:
        hRequest = urllib2.urlopen(req)
    except urllib2.HTTPError as e:
        return None, str(e)
    try:
        data = hRequest.read()
    except:
        return None, 'Error'
    finally:
        hRequest.close()
    return data, None

def SubmitComment(hash, comment):
    VIRUSTOTAL_COMMENT_URL = "https://www.virustotal.com/vtapi/v2/comments/put"
    parameters = {  "resource": hash,
                    "comment" : comment,
                    "apikey"  : VIRUSTOTAL_API2_KEY}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(VIRUSTOTAL_COMMENT_URL, data)
    try:
        response = urllib2.urlopen(req)
    except:
        print "Cannot communicate with VirusTotal (Network? VirusTotal key?). Aborting."
        sys.exit(1)
    string = response.read().decode('utf-8')
    response = 0
    try:
        json_obj = json.loads(string)
        response = json_obj['response_code']      
    except:
        response = 0
    try:
        # Factually the same if comment was uploaded or already registered
        if response == 1 or (response == 0 and json_obj['verbose_msg'] == "Duplicate comment"):
            return True
    except:
        return False

def TrySubmitComment(hash, comment):
    displayed_waiting = False
    while not SubmitComment(hash, comment):
        if not displayed_waiting:
            sys.stdout.flush()
            sys.stdout.write("Waiting for VT to accept the comment")
            sys.stdout.flush()
            displayed_waiting = True
        else:
            time.sleep(5)
            sys.stdout.write(".")
            sys.stdout.flush()
    if displayed_waiting:
        print "\n"
    print "Comment for hash %s posted (or it existed already)." % hash
    return True 

def VirusTotalSubmit(filename, options):
    
    (file_is_known, hash, positives, total, date, permalink) = VTHTTPHashRequest(filename, options)
    if file_is_known:
        if options.comment:
            TrySubmitComment(hash, options.comment)
        sys.exit(0)
    else:
        if not options.upload:
            print "To upload it, add --upload (-u) to your request."
            sys.exit(124)
        else:
            sys.stdout.write("Trying to upload file %s: " % filename)
            sys.stdout.flush()
            poster.streaminghttp.register_openers()
            jsonResponse, error = VTHTTPScanRequest(filename, options)
            if jsonResponse == None:
                sys.stdout.write("failed for unknown reason!")
                sys.stdout.flush()
            else:
                oResult = jsonalias.loads(jsonResponse)
                if oResult['response_code'] == 1:
                    print "success!" 
                    print "Permalink: %s" % oResult['permalink']
                    if options.comment and oResult['sha256']:
                        TrySubmitComment(hash, options.comment)
                else:
                    sys.stdout.write("failed! ")
                    sys.stdout.flush()
                    sys.exit(-1)
def Main():
    global VIRUSTOTAL_API2_KEY
    oParser = optparse.OptionParser(usage='usage: %prog [options] file\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-c', '--comment', default='', help='Comment to be posted along with the file') 
    oParser.add_option('-u', '--upload', action='store_true', help='Really upload files to VT instead of fetching info based on hash')
    oParser.add_option('-v', '--verbose', action='store_true', help='Be more verbose, especially while displaying VirusTotal results')
    oParser.add_option('-H', '--hash', action='store_true', help='Input is a cryptographic hash instead of filename') 
    (options, args) = oParser.parse_args()
    if len(args) == 0:
        print options
        oParser.print_help()
        print('')
        return
    if VIRUSTOTAL_API2_KEY == '':
        print('You need to get a VirusTotal API key and paste it into ~/.virustotal.key.\nTo get your API key, you need a VirusTotal account.')
    else:
        VirusTotalSubmit(args[0], options)

if __name__ == '__main__':
    Main()

