#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp import PyMISP, MISPEvent, MISPObject
from keys import misp_url, misp_key, misp_verifycert
import sys
from io import BytesIO
import datetime


misp_id = sys.argv[1]
url = sys.argv[2]
hostname = sys.argv[3]
screenshot = hostname + '.png'
ticket_id = sys.argv[4]

def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

#misp.add_url(event, url, category='Network activity', to_ids=True)


misp = init(misp_url, misp_key)
event = misp.get(misp_id)
existing_event = MISPEvent()
existing_event.load(event)

mispObject = MISPObject('phishing')
mispObject.add_attribute('url', value=url)
#mispObject.add_attribute('hostname', value=hostname)
mispObject.add_attribute('screenshot', value=screenshot, data=BytesIO(open('screenshots/' + screenshot, 'rb').read()))
mispObject.add_attribute('verification-time', value=datetime.datetime.now().isoformat())
mispObject.add_attribute('takedown-request', value=datetime.datetime.now().isoformat())
mispObject.add_attribute('internal reference', value=ticket_id, distribution=0)
mispObject.add_attribute('online', value="Yes")
mispObject.add_attribute('verified', value="Yes")
existing_event.add_object(mispObject)

misp.update(existing_event)

