#!/bin/bash 

LOGFILE="/home/rommelfs/ticket-tools/logs/ms-last.log"
. ./inc_rt.conf
. ./inc_xmpp.conf
. ./inc_gpg.conf
cd /opt/rt4/bin/

LAST=`./rt list "Queue='Z_autoreport' and Subject like 'Data report for ccTLD lu' and Requestor.EmailAddress='secure@microsoft.com'" -f ticket |tail -n 5`
for tn in $LAST 
do
  if [ `grep $tn $LOGFILE` ] 
  then 
    echo "Ticket #$tn already processed"
  else
    echo "Processing ticket #$tn"
    URLS=`./rt show $tn | gpg --passphrase="$GPGPASSPHRASE" -d --homedir=/opt/rt4/var/gpg|grep hxxp|sort|uniq -w 14`
    if [ "$URLS" ]
    then
      echo -e "New domains from MS (Ticket $RTTICKET$tn):\n$URLS"|sendxmpp -u $XMPPuser -p $XMPPpass -r $XMPPresource -j $XMPPserv -t -c $XMPProom 
    else 
      URLS=`./rt show $tn | grep hxxp|sort|uniq -w 14`
      if [ "$URLS" ]
      then
        echo -e "New domains from MS (Ticket $RTTICKET$tn):\n$URLS"|sendxmpp -u $XMPPuser -p $XMPPpass -r $XMPPresource -j $XMPPserv -t -c $XMPProom 
      else
        echo -e "New ticket from MS (Ticket $RTTICKET$tn) without URLs (check content?)"|sendxmpp -u $XMPPuser -p $XMPPpass -r $XMPPresource -j $XMPPserv -t -c $XMPProom
      fi
    fi
    echo $tn >> $LOGFILE
  fi
done


