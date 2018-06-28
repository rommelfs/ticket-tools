URLABUSE_BIN="python /home/urlabuse/server.py"
CREATETICKET_BIN="python /home/rommelfs/ticket-tools/create_ticket_with_template.py"
TEMPLATE_PHISHING="/home/rommelfs/ticket-tools/templates/phishing_server.tmpl"
TEMPLATE_MALWARE="/home/rommelfs/ticket-tools/templates/malicious_files_hosted.tmpl"
TEMPLATE_DEFACEMENT="/home/rommelfs/ticket-tools/templates/defaced_website.tmpl"
RT_BIN="/opt/rt4/bin/rt"

case "$1" in 
"phishlabs")    LAST=`$RT_BIN list "(Status='new' or Status='open') and Queue='General' and Requestor.EmailAddress='soc@phishlabs.com'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
"urlabuse")     LAST=`$RT_BIN list "Queue='Z_Autoreport' and (Status='new' or Status='open') and Subject like 'URL Abuse report' and Requestor.EmailAddress='urlabuse@circl.lu'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
"netcraft")     LAST=`$RT_BIN list "Queue='General' and (Status='new' or Status='open') and Subject like 'Issue' and Requestor.EmailAddress like '@netcraft.com'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
*)  exit 1
    ;;
esac
