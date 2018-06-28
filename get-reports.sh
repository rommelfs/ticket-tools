#!/bin/bash 
. ./inc_rt.conf
. ./inc_xmpp.conf
URLLIST=""
if [[ -z "$1" ]]
then
    echo "Usage: $0 report-type"
    echo "report types:"
    cat get-reports.inc |grep ")"| cut -d ")" -f1 |grep -v "*"
    exit 1
fi
. ./get-reports.inc $1
if [[ $LAST = "No matching results." ]]
then
  echo "no matching tickets"
  exit
fi
for tn in $LAST 
do
    echo "Processing ticket #$tn"
    URL=`./rt show $tn |egrep -o "h[tx][tx]ps?://[^ ]+" | head -n 1` 
    #./rt show $tn 
    URL=`echo $URL|sed -e "s/h[xX][xX]p\:/http\:/"`
    URL=`echo $URL|sed -e "s/h[xX][xX]ps\:/https\:/"`
    echo $URL
    UA_RESULT="`echo $URL | python /home/urlabuse/server.py`"
    echo "$UA_RESULT"
    echo "Take-down consideration"
    echo "Emails" 
    echo "$UA_RESULT" | grep "All emails" | cut -d ":" -f2
    read -rsn1 -p"press (1) for phishing, (2) for malware, (3) for defacement, (8) ignore, (9) ignore and close, (0) for exit" option;echo
    case $option in
    1)  echo "Phishing server take-down request"
        python /home/rommelfs/ticket-tools/create_ticket_with_template.py $tn /home/rommelfs/ticket-tools/templates/phishing_server.tmpl $URL False
        #/opt/rt4/bin/rt resolve $tn
        /opt/rt4/bin/rt edit $tn set queue="Incidents" CF-Classification="Phishing"
        ;;
    2)  echo "Malware server take-down request"
        python /home/rommelfs/ticket-tools/create_ticket_with_template.py $tn /home/rommelfs/ticket-tools/templates/malicious_files_hosted.tmpl $URL False
        #/opt/rt4/bin/rt resolve $tn
        /opt/rt4/bin/rt edit $tn set queue="Incidents" CF-Classification="Malware"
        ;;
    3)  echo "Defaced server take-down request"
        python /home/rommelfs/ticket-tools/create_ticket_with_template.py $tn /home/rommelfs/ticket-tools/templates/defaced_website.tmpl $URL False
        #/opt/rt4/bin/rt resolve $tn
        /opt/rt4/bin/rt edit $tn set queue="Incidents" CF-Classification="System Compromise"
        ;;
    9)  /opt/rt4/bin/rt resolve $tn
        ;;
    0)  exit
        ;;
    *)  echo "unrecognized option"
        ;;
    esac  
done
