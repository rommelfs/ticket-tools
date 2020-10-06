#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import os
import json

import ssl
import sys
from string import Template
import os

import urllib
import urllib2

from rtkit.resource import RTResource
from rtkit.authenticators import CookieAuthenticator
from rtkit.errors import RTResourceError
from rtkit import set_logging
import logging

import config as cfg
excludelist = ['http://virustotal.com/', 'http://microsoft.com/', 'http://vedicmotet.com/', '.onion.to/', '.tor2web.org/']
rt_url = cfg.rt_url
rt_user = cfg.rt_user
rt_pass = cfg.rt_pass


def create_ticket(mispid, subject):
    set_logging('error')
    logger = logging.getLogger('rtkit')
    resource = RTResource(rt_url, rt_user, rt_pass, CookieAuthenticator)

    emails = "sascha.rommelfangen@circl.lu"

    subject = "%s - takedown" % (subject)
    body    = "Automatically imported via MISP # %s" % (mispid)
    content = {
        'content': {
            'queue': 3,
            'requestor': emails,
            'subject': urllib.quote(subject),
            'text': body,
        }
    }

    try:
        response = resource.post(path='ticket/new', payload=content,)
        logger.info(response.parsed)
        for t in response.parsed:
            ticketid = t[0][1]
        return ticketid.replace('ticket/', '')
    except RTResourceError as e:
        logger.error(e.response.status_int)
        logger.error(e.response.status)
        logger.error(e.response.parsed)


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')


def search(m, event, out=None):
    global excludelist
    result = m.get_event(event)
#    if out is None:
#        print(json.dumps(result) + '\n')
    if out is None: 
        event_name = result['Event']["info"].replace('\r\n','')
        event_id   = result['Event']["id"]
        event_tag  = result['Event']["Tag"][0]["name"]
        if event_tag != "tlp:white":
            print "Attention! This MISP event is not TLP:WHITE!"
            print "Make sure you are allowed to handle this %s event." % (event_tag)
            input = raw_input("Continue? (y/N) ") or "n"
            if input == "y" or input == "Y":
                print " Continuing..."
            else:
                print " Aborting."
                sys.exit(0)
        ticket_id = create_ticket(event, event_name)
        attribute = result['Event']["Attribute"]
        f = open('/tmp/f1', 'w')
        for e in attribute:
            if e['type'] == "url":
                isExcluded = False
                for excl in excludelist:
                    if excl in e['value']:
                        isExcluded = True
                if not isExcluded:
                    #print e['value']
                    f.write(e['value'] + "\n")
        f.close() 
        print ticket_id
    else:
        print('No results for that time period')
        exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Download events from a MISP instance (with filters).')
    parser.add_argument("-e", "--event", required=True, help="specify an event id")
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    search(misp, args.event)
