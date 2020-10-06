#!/usr/bin/python
import sys
from string import Template
import os

from pyurlabuse import PyURLAbuse
import rt
import logging
import sphinxapi
import time
import csv

if len(sys.argv) < 4:
    print("Usage: %s Incident-ID Templatename csv-file" % sys.argv[0])
    sys.exit(1)

incident = sys.argv[1]
template = sys.argv[2]
csvfile = sys.argv[3]

mypath = os.path.dirname(os.path.realpath(sys.argv[0]))
template = os.path.join(mypath, template)


# Config
import config as cfg
rt_url = cfg.rt_url
rt_user = cfg.rt_user
rt_pass = cfg.rt_pass
sphinx_server = cfg.sphinx_server
sphinx_port = cfg.sphinx_port
excludelist = cfg.known_good_excludelist
debug = True

# RT
logger = logging.getLogger('rt')
tracker = rt.Rt(rt_url, rt_user, rt_pass, verify_cert=False)
tracker.login()

# Sphinx
client = sphinxapi.SphinxClient()
client.SetServer(sphinx_server, sphinx_port)
client.SetMatchMode(2)


def is_ticket_open(id):
    status = False
    try:
        rt_response = tracker.get_ticket(id)
        ticket_status = rt_response['Status']
        if ticket_status == "open" or ticket_status == "new":
            status = id
    except Exception:
        return False
    return status


def open_tickets_for_url(url):
    q = "\"%s\"" % url
    res = 0
    result = client.Query(q)
    for match in result['matches']:
        res = is_ticket_open(match['id'])
    return res


# inputfile = 'ava.txt'
inputfile = csvfile
f = open(inputfile, 'r')
headerline = f.readline().strip()
f.close()


if 'Format' in headerline:
    asns = set()

    with open(inputfile, 'rt') as f:
        reader = csv.reader(f)
        my_list = list(reader)
    for item in my_list:
        if (item and 'Format' not in item[0]) and item[1] not in excludelist:
            asns.add(item[0])

    for asn in asns:
        sendto = []
        print(asn)
        # asn_string = "AS" + asn.strip()
        asn_string = asn.strip()
        my_pyurlabuse = PyURLAbuse()
        response = my_pyurlabuse.run_query(asn, with_digest=True)
        time.sleep(5)
        response = my_pyurlabuse.run_query(asn, with_digest=True)
        for email in response['digest'][1]:
            print("".join(email))
            sendto.append("".join(email))
        asns = response['digest'][2]

        #
        print("Sendto: " + ", ".join(sendto))
        #
        print(headerline)
        detail_text = headerline
        for item in my_list:
            if item and 'Format' not in item[0]:
                if item[0] == asn:
                    detail_text += "\n " + ','.join(item)
                    #
                    print(','.join(item))

        text = detail_text
        d = {'details': text}

        try:
            f = open(template)
            subject = f.readline().rstrip()
            templatecontent = Template(f.read())
            body = templatecontent.substitute(d)
        except Exception:
            print("Couldn't open template file (%s)" % template)
            sys.exit(1)
        f.close()

        if debug:
            sendto = ["sascha@rommelfangen.de"]
        requestor = ", ".join(sendto)
        subject = "%s (%s)" % (subject, asn)
        if debug:
            print(subject)
        #    sys.exit(42)
        try:
            ticketid = tracker.create_ticket(Queue=5, Subject=subject, Text=body, Requestors=requestor)
            print("Ticket created: %s" % ticketid)
        except rt.RtError as e:
            logger.error(e)

        # update ticket link
        try:
            rt_response = tracker.edit_ticket_links(ticketid, MemberOf=incident)
            logger.info(rt_response)
        except rt.RtError as e:
            logger.error(e)
        if debug:
            # One testmail is enough
            sys.exit(42)
else:
    print("Header doesn't contain 'Format:' string")
