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
    print "Usage: %s Incident-ID Templatename csv-file" % sys.argv[0]
    sys.exit(1)

incident = sys.argv[1]
template = sys.argv[2]
csvfile	 = sys.argv[3]
try:
    use_ignore = sys.argv[4]
except:
    use_ignore = 0

mypath = os.path.dirname(os.path.realpath(sys.argv[0]))
#template = os.path.join(mypath, template)


# Config
import config as cfg
rt_url = cfg.rt_url
rt_user = cfg.rt_user
rt_pass = cfg.rt_pass
sphinx_server = cfg.sphinx_server
sphinx_port = cfg.sphinx_port
excludelist = cfg.known_good_excludelist
report_ignore_list = cfg.report_ignore_list
report_ignore_email = cfg.report_ignore_email
debug = False 

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

import csv
import pythonwhois

#inputfile = 'ava.txt'
inputfile = csvfile
f = open(inputfile, 'r')
headerline = f.readline().strip()
f.close()


if 'asn' in headerline or 'src_asn' in headerline:
    asns = set()
    if 'src_asn' in headerline:
        asn_field = 'src_asn'
    else:
        asn_field = 'asn'
    with open(inputfile, 'rb') as f:
        reader = csv.DictReader(f)
        my_list= list(reader)
    for item in my_list:
        if item and (item['ip'] not in excludelist or item['hostname'] not in excludelist or item['ip'] not in report_ignore_list or item['hostename'] not in report_ignore_list):
            asns.add(item[asn_field])

    for asn in asns:
        sendto = []
        asn_string = "AS" + asn.strip()
        print asn_string
        data = pythonwhois.net.get_whois_raw(asn_string)
        parsed = pythonwhois.parse.parse_raw_whois(data, normalized=True)

        for key, value in parsed.items():
            if 'emails' in key:
                for email in value:
                    if 'peering' not in email:
                        if use_ignore is 1:
                            if email in report_ignore_email:
                                sendto = []
                            else:
                                sendto.append(email)
                        else:
                            sendto.append(email)
        #
        print sendto
        #
        #print reader.fieldnames 
        detail_text = ', '.join(reader.fieldnames) + "\n "
        for item in my_list:
            if item[asn_field] == asn:
                detail_text += ", ".join([item[key].strip() for key in reader.fieldnames])
                detail_text += "\n "
        text = urllib.quote(detail_text)
        d={ 'details' : text }
        print detail_text
        try:
            f = open(template.strip())
            subject = f.readline().rstrip()
            templatecontent = Template( f.read() )
            body = templatecontent.substitute(d)
        except:
            print "Couldn't open template file (%s)" % template
            sys.exit(1)
        f.close()


        emails = ', '.join(sendto)
        print emails
        #emails = "sascha@rommelfangen.de"
        subject = "%s (%s)" % (subject, asn)
        content = {
            'content': {
            'queue': 5,
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

