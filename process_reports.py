#!/usr/bin/python3
import sys
from string import Template
import os
from time import time

from pyurlabuse import PyURLAbuse
import rt

import logging
import csv
import pythonwhois
import urllib

if len(sys.argv) < 4:
    print("Usage: %s Incident-ID Templatename csv-file" % sys.argv[0])
    sys.exit(1)

incident = sys.argv[1]
template = sys.argv[2].strip()
csvfile = sys.argv[3]
use_ignore = sys.argv[4]
ticket = sys.argv[5]

mypath = os.path.dirname(os.path.realpath(sys.argv[0]))
#template = os.path.join(mypath, template)


# Config
import config as cfg
rt_url = cfg.rt_url
rt_user = cfg.rt_user
rt_pass = cfg.rt_pass
excludelist = cfg.known_good_excludelist
report_ignore_list = cfg.report_ignore_list
report_ignore_email = cfg.report_ignore_email
debug = False 

# RT
logger = logging.getLogger('rt')
tracker = rt.Rt(rt_url, rt_user, rt_pass, verify_cert=False)
tracker.login()


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
    return False 


# inputfile = 'ava.txt'
inputfile = csvfile
f = open(inputfile, 'rt')
headerline = f.readline().strip()
f.close()


if 'asn' in headerline or 'src_asn' in headerline:
    asns = set()
    if 'src_asn' in headerline:
        asn_field = 'src_asn'
    else:
        asn_field = 'asn'
    if 'src_ip' in headerline:
        ip_field = 'src_ip'
    else:
        ip_field = 'ip'
    with open(inputfile, 'rt') as f:
        reader = csv.DictReader(f)
        my_list = list(reader)
    for item in my_list:
        if item and (item[ip_field] not in excludelist or item['hostname'] not in excludelist or item[ip_field] not in report_ignore_list or item['hostname'] not in report_ignore_list):
            asns.add(item[asn_field])

    for asn in asns:
        sendto = []
        #asn_string = asn.strip()
        asn_string = "AS" + asn.strip()
        print(asn_string)
        data = pythonwhois.net.get_whois_raw(asn_string)
        parsed = pythonwhois.parse.parse_raw_whois(data, normalized=True)

        for key, value in parsed.items():
            if 'emails' in key:
                for email in value:
                    if 'peering' not in email:
                        if use_ignore == 1:
                            if 'abuse@acett.networ' in email:
                                sendto.append('abuse@acett.network')
                            elif email in report_ignore_email:
                                sendto = []
                            else:
                                sendto.append(email)
                        else:
                            sendto.append(email)
        #
        print(sendto)
        #
        detail_text = ', '.join(reader.fieldnames) + "\n " 
        for item in my_list:
            if item[asn_field] == asn:
                detail_text += ", ".join([item[key].strip() for key in reader.fieldnames])
                detail_text += "\n "
                #
                #print(','.join(item))

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

        # Last resort to skip the mail if on exclude list
        try:
            for item in sendto:
                if item in report_ignore_email:
                        sendto = []
                        break
        except:
            print("Should have stopped here")
        emails = ", ".join(sendto)
 
        #emails = "sascha@rommelfangen.de"
        subject = "%s (%s)" % (subject, asn)
        #print(subject)
        #print(body)
        #print(emails)
        if debug:
            sys.exit(42)

        try:
            ticketid = tracker.create_ticket(Queue='Automated security notifications', Subject=subject, Text=body, Requestors=emails)
            print("Ticket created: %s" % ticketid)
            success = tracker.reply(ticketid, text=body)
        except rt.RtError as e:
            logger.error(e)

        # update ticket link
        try:
            rt_response = tracker.edit_ticket_links(ticketid, MemberOf=incident)
            logger.info(rt_response)
            rt_response = tracker.edit_ticket_links(ticketid, RefersTo=ticket)
            logger.info(rt_response)
        except rt.RtError as e:
            logger.error(e)
        
        try:
            time = time()
            file = open('/tmp/shadowserver.timestamp', 'w')
            file.write(str(int(time)) + '\n')
            file.close()
        except Exception as e:
            print("something went wrong while writing the timestamp file")
            print(str(e))
