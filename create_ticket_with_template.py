#!/usr/bin/python3
import sys
from string import Template
import ioc_fanger

import os

from pyurlabuse import PyURLAbuse
from pymisp import PyMISP, MISPEvent, MISPObject
from keys import misp_url, misp_key, misp_verifycert

from io import BytesIO
import datetime

import rt
import requests

import logging
import sphinxapi
import urllib3
import json
from pyfaup.faup import Faup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if len(sys.argv) < 4:
    print("Usage: %s Incident-ID Templatename URL [Onlinecheck:True|False] [Queue]" % sys.argv[0])
    sys.exit(1)

incident = sys.argv[1]
template = sys.argv[2]
url = sys.argv[3]
try:
    onlinecheck = sys.argv[4]
except Exception:
    onlinecheck = 1 
try:
    queue = sys.argv[5]
except Exception:
    queue = 5
try:
    misp_id = sys.argv[6]
except Exception:
    misp_id = False

mypath = os.path.dirname(os.path.realpath(sys.argv[0]))
template = os.path.join(mypath, template)

# Config
min_size = 5000
import config as cfg
ua = cfg.ua
rt_url = cfg.rt_url
rt_user = cfg.rt_user
rt_pass = cfg.rt_pass
sphinx_server = cfg.sphinx_server
sphinx_port = cfg.sphinx_port
excludelist = cfg.known_good_excludelist
debug = False

def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

def is_online(resource):
    try:
        session = requests.Session()
        session.headers.update({'User-agent': ua})
        response = session.get(resource)
        size = len(response.content)
        if int(size) > min_size:
            return True, size
        else:
            return False, size
    except Exception as e:
        print(e)
        return False, -1


# RT
logger = logging.getLogger('rtkit')
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
    # tickets = []
    result = client.Query(q)
    for match in result['matches']:
        res = is_ticket_open(match['id'])
    return res


print("Checking URL: %s" % url)

if onlinecheck == 2:
    open_tickets = open_tickets_for_url(url)
    if open_tickets > 0:
        print("Ticket for this URL (%s) already exists: %s" % (url, open_tickets))
        sys.exit(0)

if onlinecheck == 1:
    open_tickets = open_tickets_for_url(url)
    if open_tickets > 0:
        print("Ticket for this URL (%s) already exists: %s" % (url, open_tickets))
        sys.exit(0)
    online, size = is_online(url)
    if not online:
        print("Resource %s is offline (size: %s)" % (url, size))
        sys.exit(1)

my_pyurlabuse = PyURLAbuse()
response = my_pyurlabuse.run_query(url, with_digest=True)
emails = ",".join([email.strip('.') for email in response['digest'][1]])
asns = response['digest'][2]
text = ioc_fanger.defang(response['digest'][0])
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

# print emails
#emails = "sascha@rommelfangen.de"

subject = "%s (%s)" % (subject, "|".join(asns))

if debug:
    sys.exit(42)

#try:
ticketid = tracker.create_ticket(Queue=queue, Subject=subject, Text=body, Requestors=emails)
print("Ticket created: {}".format(ticketid))
#except rt.RtError as e:
#    logger.error(e)


# update ticket link
try:
    rt_response = tracker.edit_ticket_links(ticketid, MemberOf=incident)
    logger.info(rt_response)
except rt.RtError as e:
    logger.error(e)

tracker.logout()

if misp_id is not False:
    misp = init(misp_url, misp_key)
    
    res_search = misp.search(controller='attributes',eventid=misp_id, value=url)
    uuid = None
    for attribs in res_search['response']['Attribute']:
        uuid = attribs['uuid']
    if uuid is not None:
        print("URL is already present.")
        # add sighting
        # if MISP allows to sight on add, we should implement it here, too
        misp.sighting(uuid=uuid, source="URLabuse")
        sys.exit(0)
    event = misp.get(misp_id)
    existing_event = MISPEvent()
    existing_event.load(event)
    redirect_count = 0
    fex = Faup()
    fex.decode(url)
    hostname = fex.get_host().lower()
    screenshot = hostname.decode() + '.png'
    mispObject = MISPObject('phishing')
    mispObject.add_attribute('hostname', value=hostname.decode())
    for key in response['result']:
        u = list(key.keys())[0]
        if redirect_count == 0:
            comment = "initial URL"
            mispObject.add_attribute('url', value=u, comment=comment)
        else:
            comment = "redirect URL: {}"
            mispObject.add_attribute('url-redirect', value=u, comment=comment.format(redirect_count))
        redirect_count += 1
        fex.decode(u)
        nexthost = fex.get_host().lower()
        if nexthost != hostname:
            hostname = nexthost
            mispObject.add_attribute('hostname', to_ids=False, value=hostname.decode()) 
    for email in response['digest'][1]:
        mispObject.add_attribute('takedown-request-to', value=email)
    screenshot_path = 'screenshots/' + screenshot
    if os.path.exists(screenshot_path) and os.path.getsize(screenshot_path) > 0: 
        try:
            mispObject.add_attribute('screenshot', value=screenshot, data=BytesIO(open(screenshot_path, 'rb').read()))
        except:
            pass
    mispObject.add_attribute('verification-time', value=datetime.datetime.now().isoformat())
    mispObject.add_attribute('takedown-request', value=datetime.datetime.now().isoformat())
    mispObject.add_attribute('internal reference', value=ticketid, distribution=0)
    mispObject.add_attribute('online', value="Yes")
    mispObject.add_attribute('verified', value="Yes")
    misp.add_object(misp_id, mispObject.template_uuid, mispObject)
    # This is not working in this condition. The event is too large for updating it.
    # The server gets stuck preparing something, there's a 240s timeout and the server returns a 500.
    # The above method is better.
    # existing_event.add_object(mispObject)
    # misp.update(existing_event)
    misp.fast_publish(misp_id)
