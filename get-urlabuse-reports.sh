#!/bin/bash 
. ./inc_rt.conf
. ./inc_xmpp.conf
LOGFILE="/home/rommelfs/ticket-tools/logs/urlabuse-last.log"
URLLIST=""
cd /opt/rt4/bin/
LASTPROCESSED=`tail -n 1 $LOGFILE`
LAST=`./rt list "id > $LASTPROCESSED and Queue='Z_Autoreport' and (Status='new' or Status='open') and Subject like 'URL Abuse report' and Requestor.EmailAddress='urlabuse@circl.lu'" -f ticket |grep -v "id" |tail -n 5000`
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
    URL=`./rt show $tn|grep http -m 1` 
    #./rt show $tn 
    echo $URL
    UA_RESULT="`echo $URL | python /home/urlabuse/server.py`"
    echo "$UA_RESULT"
    echo "Take-down consideration"
    echo "Emails" 
    echo "$UA_RESULT" | grep "All emails" | cut -d ":" -f2
    read -rsn1 -p"press (1) for phishing, (2) for malware, (9) ignore, (0) for exit" option;echo
    case $option in
    1)  echo "Phishing server take-down request"
        python /home/rommelfs/ticket-tools/create_ticket_with_template.py $tn /home/rommelfs/ticket-tools/templates/phishing_server.tmpl $URL False 5
        /opt/rt4/bin/rt resolve $tn
        #echo $tn >> $LOGFILE
        ;;
    2)  echo "Malware server take-down request"
        python /home/rommelfs/ticket-tools/create_ticket_with_template.py $tn /home/rommelfs/ticket-tools/templates/malicious_files_hosted.tmpl $URL False 5
        /opt/rt4/bin/rt resolve $tn
        #echo $tn >> $LOGFILE
        ;;
    9)  # echo $tn >> $LOGFILE
        /opt/rt4/bin/rt resolve $tn
        ;;
    0)  exit
        ;;
    *)  echo "unrecognized option"
        ;;
    esac  
    #if [ ! -z "${tn##*[!0-9]*}" ] 
    #then 
    #    echo $tn >> $LOGFILE
    #fi
  fi
done
#if [ "$URLLIST" ]
#then
  #echo -e "New domains from URLQuery:\n$URLLIST"
  #echo -e "New domains from URLQuery:\n$URLLIST"|sendxmpp -u $XMPPuser -p $XMPPpass -r $XMPPresource -j $XMPPserv -t -c $XMPProom 
#fi


