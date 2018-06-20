#!/usr/bin/python
import ssl
import sys
from string import Template
from defang import defang
from defang import refang
import os

import urllib
import urllib2 

from rtkit.resource import RTResource
from rtkit.authenticators import CookieAuthenticator
from rtkit.errors import RTResourceError

from rtkit import set_logging
import logging
import sphinxapi

import config as cfg

rt_url = cfg.rt_url
rt_user = cfg.rt_user
rt_pass = cfg.rt_pass


if len(sys.argv) < 3:
    print "Usage: %s MISP_ID Subject" % sys.argv[0]
    sys.exit(1)

mispid  = sys.argv[1]
subject = sys.argv[2]


# RT
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
    print ticketid.replace('ticket/', '')
except RTResourceError as e:
    logger.error(e.response.status_int)
    logger.error(e.response.status)
    logger.error(e.response.parsed)

