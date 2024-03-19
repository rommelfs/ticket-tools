#!/bin/bash
. ./inc_rt.conf
. ./inc_xmpp.conf
. ./inc_external.conf

URLLIST=""
multi="False"

take_screenshot () {
    URL="`echo $1|sed -e 's/&/\&/g'`"
    SCREENSHOT=`faup -f host $URL`
    #export URL; ssh ${SCREENSHOT_QUERY_USER}@${SCREENSHOT_SERVER} "$URL" && scp ${SCREENSHOT_FETCH_USER}@${SCREENSHOT_SERVER}:~/screenshots/${SCREENSHOT}.png screenshots/
    if [[ $tn ]]
    then
        $RT_BIN comment $tn -m "screenshot of $URL" -a screenshots/${SCREENSHOT}.png
    fi
}

URL="$1"
tn="$2"

take_screenshot "$URL" "$tn"
