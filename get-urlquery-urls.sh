#!/bin/bash 
# Process tickets and anounce via XMPP

. ./inc_rt.conf
. ./inc_xmpp.conf
LOGFILE="/home/rommelfs/ticket-tools/logs/urlquery-last.log"
URLLIST=""
cd /opt/rt4/bin/
LASTPROCESSED=`tail -n 1 $LOGFILE`
LAST=`./rt list "id > $LASTPROCESSED and Queue='Z_autoreport' and Subject like 'UrlQuery report ' and Requestor.EmailAddress='raphael.vinot@circl.lu'" -f ticket |grep -v "id" |tail -n 5000`
if [[ $LAST = "No matching results." ]]
then
  echo "no matching tickets"
  exit
fi
for tn in $LAST 
do
  if [ `grep $tn $LOGFILE` ] 
  then 
    echo "Ticket #$tn already processed"
  else
    echo "Processing ticket #$tn"
    HIT=`./rt show $tn|grep alert_count|cut -d":" -f2|grep -v 0` 
    if [ "$HIT" ]
    then
      URLS=`./rt show $tn | grep '"url"' | cut -d'"' -f 4|sort|uniq -w 14`
      URLLIST="$URLLIST\n#$tn: $URLS"
      echo "We have a hit for: $URLS"
    fi  
    if [ ! -z "${tn##*[!0-9]*}" ] 
      then 
        echo $tn >> $LOGFILE
    fi
  fi
done
if [ "$URLLIST" ]
then
  #echo -e "New domains from URLQuery:\n$URLLIST"
  echo -e "New domains from URLQuery:\n$URLLIST"|sendxmpp -u $XMPPuser -p $XMPPpass -r $XMPPresource -j $XMPPserv -t -c $XMPProom 
fi


