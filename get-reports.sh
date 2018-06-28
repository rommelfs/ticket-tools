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
. ./get-reports.inc "$1"
if [[ $LAST = "No matching results." ]]
then
  echo "no matching tickets"
  exit
fi
for tn in $LAST 
do
    echo "Processing ticket #$tn"
    URL=`$RT_BIN show $tn |egrep -o "h[tx][tx]ps?://[^ ]+" | head -n 1` 
    #./rt show $tn 
    URL=`echo $URL|sed -e "s/h[xX][xX]p\:/http\:/"`
    URL=`echo $URL|sed -e "s/h[xX][xX]ps\:/https\:/"`
    UA_RESULT="`echo $URL | $URLABUSE_BIN`"
    echo "$UA_RESULT"
    echo "Take-down consideration"
    echo "Emails" 
    echo "$UA_RESULT" | grep "All emails" | cut -d ":" -f2
    echo $URL
    read -rsn1 -p"press (1) for phishing, (2) for malware, (3) for defacement, (8) ignore, (9) ignore and close, (0) for exit" option;echo
    case $option in
    1)  echo "Phishing server take-down request"
        $CREATETICKET_BIN $tn $TEMPLATE_PHISHING $URL False
        #/opt/rt4/bin/rt resolve $tn
        $RT_BIN edit $tn set queue="Incidents" CF-Classification="Phishing"
        ;;
    2)  echo "Malware server take-down request"
        $CREATETICKET_BIN $tn $TEMPLATE_MALWARE $URL False
        #/opt/rt4/bin/rt resolve $tn
        $RT_BIN edit $tn set queue="Incidents" CF-Classification="Malware"
        ;;
    3)  echo "Defaced server take-down request"
        $CREATETICKET_BIN $tn $TEMPLATE_DEFACEMENT $URL False
        #/opt/rt4/bin/rt resolve $tn
        $RT_BIN edit $tn set queue="Incidents" Classification="System Compromise"
        ;;
    9)  $RT_BIN resolve $tn
        ;;
    0)  exit
        ;;
    *)  echo "unrecognized option"
        ;;
    esac  
done
