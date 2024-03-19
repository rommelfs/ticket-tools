import re
import sys
import datetime
from pymisp import ExpandedPyMISP, PyMISP, MISPEvent, MISPObject
from keys import misp_url, misp_key, misp_verifycert



def init(url, key):
    return ExpandedPyMISP(url, key, misp_verifycert, 'json')

def get_event_id():
    misp = init(misp_url, misp_key)
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    title = "Weekly CIRCL processed phishing URLs ({})".format(date)
    try:
        misp_id = misp.new_event(info=title)['Event']
        #misp.tag(misp_id['uuid'], 'circl:osint-feed')
        misp.tag(misp_id['uuid'], 'tlp:white')
        #misp.tag(misp_id['uuid'], 'misp:confidence-level="fairly-confident"')
        return misp_id['id']
    except Exception as e:
        print("Couldn't create MISP event. Exiting!")
        print(e)
        sys.exit(1)
print(get_event_id())
