#!/bin/bash
EVENTID=`python3.6 create_weekly_event.py 2>/dev/null`
if [[ $EVENTID =~ ^-?[0-9]+$ ]]
then
    echo "$EVENTID"
    OLDID=`. ./get-reports.inc; echo $MISP_PHISHING_ID_PHISHTANK`
    echo $OLDID
else
    echo "event creation failed"
fi
