cd /opt/rt4/bin/
LASTPROCESSED=`tail -n 1 $LOGFILE`
case "$1" in 
"phishlabs")    LAST=`./rt list "id > $LASTPROCESSED and (Status='new' or Status='open') and Queue='General' and Requestor.EmailAddress='soc@phishlabs.com'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
"urlabuse")     LAST=`./rt list "id > $LASTPROCESSED and Queue='Z_Autoreport' and (Status='new' or Status='open') and Subject like 'URL Abuse report' and Requestor.EmailAddress='urlabuse@circl.lu'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
"netcraft")     LAST=`./rt list "id > $LASTPROCESSED and Queue='General' and (Status='new' or Status='open') and Subject like 'Issue' and Requestor.EmailAddress like '@netcraft.com'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
*)  exit 1
    ;;
esac
