#!/bin/bash
. ./inc_rt.conf
. ./inc_xmpp.conf
LOGFILE="/home/rommelfs/ticket-tools/logs/urlmon-last.log"

cd /opt/rt4/bin/

LAST=`./rt list "Queue='Z_autoreport' and Subject like 'URL mon ' and Requestor.EmailAddress='adulau@cpb.circl.lu'" -f ticket |tail -n 5`
for tn in $LAST 
do
  if [ `grep $tn $LOGFILE` ] 
  then 
    echo "Ticket #$tn already processed"
  else
    echo "Processing ticket #$tn"
    URLS=`./rt show $tn|egrep "http|ftp"|cut -d"," -f 4 |sort|uniq -w 14`
    #URLS=`./rt show $tn |grep hxxp|sort|uniq -w 14`
    if [ "$URLS" ]
    then
      #echo -e "New domains from URL mon (Ticket $RTTICKET$tn):\n$URLS"
      echo -e "New domains from URL mon (Ticket $RTTICKET$tn):\n$URLS"|sendxmpp -u $XMPPuser -p $XMPPpass -r $XMPPresource -j $XMPPserv -t -c $XMPProom 
    else 
      #echo -e "New ticket from URL mon (Ticket $RTTICKET$tn) without URLs (check content?)"
      echo -e "New ticket from URL mon (Ticket $RTTICKET$tn) without URLs (check content?)"|sendxmpp -u $XMPPuser -p $XMPPpass -r $XMPPresource -j $XMPPserv -t -c $XMPProom
    fi
    echo $tn >> $LOGFILE
  fi
done


