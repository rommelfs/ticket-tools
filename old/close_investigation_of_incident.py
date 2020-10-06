#!/usr/bin/python
import ssl
import sys
#ssl._create_default_https_context = ssl._create_unverified_context
from string import Template
import defang
import os
import re
import urllib
import urllib2 
import config as cfg
rt_url = cfg.rt_url
rt_user = cfg.rt_user
rt_pass = cfg.rt_pass

sys.path.append("/home/urlabuse/")
import url_abuse as urlabuse

if len(sys.argv) < 2:
    print "Usage: %s Incident-ID" % sys.argv[0]
    sys.exit(1)

incident = sys.argv[1]



def is_online(resource):
    try:
        ua = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C)"
        request = urllib2.Request(resource)
        request.add_header('User-agent', ua)
        response = urllib2.urlopen(request, timeout=20)
        size = len(response.read())
        if int(size) >= 7500:
            return True, size
        else:
            return False, size
    except Exception as e:
        print e
        return False, -1




from rtkit.resource import RTResource
from rtkit.authenticators import CookieAuthenticator
from rtkit.errors import RTResourceError

from rtkit import set_logging
import logging
#set_logging('info')
logger = logging.getLogger('rtkit')

resource = RTResource(rt_url, rt_user, rt_pass, CookieAuthenticator)


def close_ticket(id):
    print "Closing investigation %s" % id
    ticketpath = 'ticket/%s' % id
    content = {
        'content': {
            'Status': 'resolved',
         }
    }
    response = resource.post(path=ticketpath, payload=content,)
    logger.info(response.parsed)
    print "Adding comment to investigation %s" % id
    ticketpath = 'ticket/%s/comment' % id
    content = {
        'content': {
            'Action': 'comment',
            'Text'  : 'Automatically closed by script after checking resource',
         }
    }
    response = resource.post(path=ticketpath, payload=content,)
    logger.info(response.parsed)
        

def print_active_ticket(id):
    try:
        ticket="ticket/%s" % id
        response = resource.get(path=ticket)
        for r in response.parsed:
            l = { a:b for a,b in r }
            ticket_status = l["Status"]
            if ticket_status == "open" or ticket_status == "new":
                #print r
                attachments="ticket/%s/attachments" % id
                response = resource.get(path=attachments)
                for r in response.parsed:
                    l = { a:b for a,b in r }
                    ticket_attachments = l["Attachments"]
                    attachment = ticket_attachments.split(":")
                    ta = attachment[0]
                    ticket_attachment = "ticket/%s/attachments/%s/content" % (id, ta)
                    print ticket_attachment
                    response = resource.get(path=ticket_attachment)
                    body = response.body
                    body = defang.refang(body)
                    extracted_url = re.search("(?P<url>https?://[^\s]+)", body).group("url")
                    print extracted_url
                    online,size = is_online(extracted_url)
                    if not online:
                        print "Resource %s is offline (size: %s)" % (extracted_url, size)
                        close_ticket(id)			
    except RTResourceError as e:
        logger.error(e.response.status_int)
        logger.error(e.response.status)
        logger.error(e.response.parsed)


#show ticket links
try:
    ticketpath="ticket/%s/links/show" % incident
    response = resource.get(path=ticketpath)
    for r in response.parsed:
        for t in r[1][1].split("\n"):
            investigation = ""
            investigation_id = ""
            if t.startswith('fsck'):
                investigation = t 
                print investigation
                investigation_id = re.findall('\d+', investigation)
                for i in investigation_id:
                    print i
                    print_active_ticket(i) 
except Exception as e:
    print e

