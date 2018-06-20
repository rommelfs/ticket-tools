#!/usr/bin/python
import ssl
import sys
from string import Template
from defang import defang
from defang import refang
import os

import urllib
import urllib2 

sys.path.append("/home/urlabuse/")
import url_abuse as urlabuse

from rtkit.resource import RTResource
from rtkit.authenticators import CookieAuthenticator
from rtkit.errors import RTResourceError

from rtkit import set_logging
import logging
import sphinxapi

if len(sys.argv) < 4:
    print "Usage: %s Incident-ID Templatename URL [Onlinecheck:True|False] [Queue]" % sys.argv[0]
    sys.exit(1)

incident = sys.argv[1]
template = sys.argv[2]
url	 = sys.argv[3]
try:
    onlinecheck = sys.argv[4]
except:
    onlinecheck = True
try:
    queue = sys.argv[5]
except:
    queue = 5

mypath = os.path.dirname(os.path.realpath(sys.argv[0]))
template = os.path.join(mypath, template)


# Config
min_size = 5000
ua = cfg.ua
rt_url = cfg.rt_url
rt_user = cfg.rt_user
rt_pass = cfg.rt_pass
sphinx_server = cfg.sphinx_server
sphinx_port = cfg.sphing_port
excludelist = cfg.known_good_excludelist
debug = False 

def is_online(resource):
    try:
	global ua
        global min_size
        request = urllib2.Request(resource)
        request.add_header('User-agent', ua)
        response = urllib2.urlopen(request)
        size = len(response.read())
        if int(size) > min_size:
            return True, size
        else:
            return False, size
    except Exception as e:
        print e
        return False, -1


# RT
set_logging('error')
logger = logging.getLogger('rtkit')
resource = RTResource(rt_url, rt_user, rt_pass, CookieAuthenticator)

# Sphinx
client = sphinxapi.SphinxClient()
client.SetServer(sphinx_server, sphinx_port)
client.SetMatchMode(2)


def is_ticket_open(id):
    status = False
    try:
        ticket="ticket/%s" % id
        response = resource.get(path=ticket)
        for r in response.parsed:
            l = { a:b for a,b in r }
            ticket_status = l["Status"]
            if ticket_status == "open" or ticket_status == "new":
                status = id 
    except:
        return False
    return status

def open_tickets_for_url(url):
    q   = "\"%s\"" % url
    res = 0
    tickets = []
    result = client.Query(q)
    for match in result['matches']:
        res = is_ticket_open(match['id'])
    return res 


print "Checking URL: %s" % url

if onlinecheck is True:
    open_tickets = open_tickets_for_url(url)
    if open_tickets > 0:
        print "Ticket for this URL (%s) already exists: %s" % (url, open_tickets)
        sys.exit(0)
    online,size = is_online(url)
    if not online:
        print "Resource %s is offline (size: %s)" % (url, size)
        sys.exit(1)

emails, text, asn = urlabuse.run_lookup(url)
text = defang(urllib.quote(text))
d={ 'details' : text }

try:
    f = open(template)
    subject = f.readline().rstrip()
    templatecontent = Template( f.read() )
    body = templatecontent.substitute(d)
except:
    print "Couldn't open template file (%s)" % template
    sys.exit(1)
f.close()

#print emails
#emails = "sascha@rommelfangen.de"

asn_out=[]
for x in asn:
    asn_out.append(",".join(x))
asn_out = "|".join(asn_out)
subject = "%s (%s)" % (subject, asn_out)
content = {
    'content': {
        'queue': queue,
        'requestor': emails,
        'subject': urllib.quote(subject),
        'text': body,
    }
}

if debug:
    sys.exit(42)

try:
    response = resource.post(path='ticket/new', payload=content,)
    logger.info(response.parsed)
    for t in response.parsed:
        ticketid = t[0][1]
    print "Ticket created: %s" % ticketid
except RTResourceError as e:
    logger.error(e.response.status_int)
    logger.error(e.response.status)
    logger.error(e.response.parsed)


#update ticket link
content = {
    'content': {
        'memberof': incident,
    }
}
try:
    ticketpath="%s/links" % ticketid
    response = resource.post(path=ticketpath, payload=content,)
    logger.info(response.parsed)
except rtresourceerror as e:
    logger.error(e.response.status_int)
    logger.error(e.response.status)
    logger.error(e.repoinse.parsed)

