URLABUSE_BIN="python /home/urlabuse/server.py"
CREATE_BULK_BIN="/home/rommelfs/ticket-tools/process_reports.py"
CREATETICKET_BIN="/home/rommelfs/ticket-tools/create_ticket_with_template.py"
TEMPLATE_DIR="/home/rommelfs/ticket-tools/templates"
TEMPLATE_PHISHING="$TEMPLATE_DIR/phishing_server.tmpl"
TEMPLATE_MALWARE="$TEMPLATE_DIR/malicious_files_hosted.tmpl"
TEMPLATE_DEFACEMENT="$TEMPLATE_DIR/defaced_website.tmpl"
TEMPLATE_COMPROMISED_WEBSHELL="$TEMPLATE_DIR/compromised_website-with-webshell.tmpl"
TEMPLATE_CYBERSQUATTING="$TEMPLATE_DIR/cybersquatting.tmpl"
CERTBUND_TOPICS="Malware infections in country, $TEMPLATE_DIR/cb_malware-infections.tmpl, 2001248
Avalanche, $TEMPLATE_DIR/cb_malware-compromised-avalance-client.tmpl, 2001249"

SHADOWSERVER_TOPICS="NTP Monitor, $TEMPLATE_DIR/ss_ntp-monitor.tmpl, 2001222
Accessible Cisco Smart Install, $TEMPLATE_DIR/ss_accessible-cisco-smart-install.tmpl, 2001225
Accessible CWMP, $TEMPLATE_DIR/ss_accessible-cwmp.tmpl, 2001226
Open mDNS Servers, $TEMPLATE_DIR/ss_accessible-mdns.tmpl, 2001227
Hadoop Service, $TEMPLATE_DIR/ss_accessible-hadoop.tmpl, 2001228
Spam URL, $TEMPLATE_DIR/ss_spam-url.tmpl, 2001229 
Compromised Website, $TEMPLATE_DIR/ss_compromised-website.tmpl, 2001230 
Vulnerable HTTP Report, $TEMPLATE_DIR/ss_vulnerable-http-report.tmpl, 3763146
Open Redis Server, $TEMPLATE_DIR/ss_open-redis-server.tmpl, 2001231
DNS Open Resolvers, $TEMPLATE_DIR/ss_dns-open-resolvers.tmpl, 2001233
Open TFTP Server, $TEMPLATE_DIR/ss_open-tftp-servers.tmpl, 2001234
Vulnerable NAT-PMP Systems, $TEMPLATE_DIR/ss_vulnerable-nat-pmp-systems.tmpl, 2001235
Open Memcached Server, $TEMPLATE_DIR/ss_open-memcached-server.tmpl, 2001236
Open MS-SQL Server, $TEMPLATE_DIR/ss_open-mssql-server.tmpl, 2001237
Open Portmapper Scan, $TEMPLATE_DIR/ss_open-portmapper.tmpl, 2001238
Accessible/Open MongoDB Service, $TEMPLATE_DIR/ss_open-mongodb-service.tmpl, 2001239
Open Elasticsearch Server, $TEMPLATE_DIR/ss_open-elasticsearch-server.tmpl, 2001240
Open LDAP Services, $TEMPLATE_DIR/ss_open-ldap-server.tmpl, 2001241
Command and Control, $TEMPLATE_DIR/ss_command_and_control.tmpl, 2001242
NTP Version, $TEMPLATE_DIR/ss_ntp_scan.tmpl, 2001243
SNMP Report, $TEMPLATE_DIR/ss_open-snmp-server.tmpl, 2001244
Sinkhole HTTP Events Report, $TEMPLATE_DIR/ss_sinkhole_http_events.tmpl, 2043494
Open IPP Report, $TEMPLATE_DIR/ss_open-ipp-server.tmpl, 2001245
Vulnerable Exchange Server Report, $TEMPLATE_DIR/ss_vulnerable-exchange-servers.tmpl, 2001246
Accessible MSMQ Service, $TEMPLATE_DIR/ss_accessible-msmq.tmpl, 3472259
Vulnerable Exchange Servers Special Report, $TEMPLATE_DIR/ss_vulnerable-exchange-servers.tmpl, 2001246"

 
#SMB Service, $TEMPLATE_DIR/defaced_website.tmpl, 582974
#VNC Service, $TEMPLATE_DIR/defaced_website.tmpl, 582975
#Drone Brute Force, $TEMPLATE_DIR/defaced_website.tmpl, 582941
#Sandbox URL, $TEMPLATE_DIR/defaced_website.tmpl, 582942
#Netbios Report, $TEMPLATE_DIR/defaced_website.tmpl, 582949
#SSDP Report, $TEMPLATE_DIR/defaced_website.tmpl, 582950
#Chargen Report, $TEMPLATE_DIR/defaced_website.tmpl, 582951
#QOTD Report, $TEMPLATE_DIR/defaced_website.tmpl, 582952
#Accessible HTTP, $TEMPLATE_DIR/defaced_website.tmpl, 582954
#Accessible RDP, $TEMPLATE_DIR/defaced_website.tmpl, 582955
#Accessible Telnet, $TEMPLATE_DIR/defaced_website.tmpl, 582956
#SSLv3/Poodle Vulnerable Servers, $TEMPLATE_DIR/defaced_website.tmpl, 582957
#IPMI Report, $TEMPLATE_DIR/defaced_website.tmpl, 582958
#SSL/Freak Vulnerable Servers, $TEMPLATE_DIR/defaced_website.tmpl, 582965
#ISAKMP Vulnerability Scan, $TEMPLATE_DIR/defaced_website.tmpl, 582969
#Blacklisted IP Addresses, $TEMPLATE_DIR/defaced_website.tmpl, 582976

MISP_PHISHING_ID="206979"
MISP_PHISHING_ID_PHISHTANK="206978"

REPLACED_DOMAIN="taggingserver\.com"

RT_BIN="/opt/rt5/bin/rt"
case "$1" in 
"check")    LAST=`$RT_BIN list "Queue='Incidents' and (Status='new' or Status='open') and ( Requestor.EmailAddress like '@netcraft.com' or Requestor.EmailAddress like 'urlabuse@circl.lu' )" -f ticket |grep -v "id" |tail -n 5000`
    ;;

"phishlabs")    LAST=`$RT_BIN list "(Status='new' or Status='open') and Queue='Z_autoreport' and Requestor.EmailAddress='soc@phishlabs.com'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
"lookyloo")     LAST=`$RT_BIN list "((Queue='Lookyloo' or Queue='Phish & Spam')) and (Status='new' or Status='open') and Subject like 'Capture from Lookyloo to review'" -f ticket |grep -v "id"|tail -n 5000`
    ;;
"urlabuse")     LAST=`$RT_BIN list "Queue='URL Abuse' and (Status='new' or Status='open') and Subject like 'URL Abuse report' and Requestor.EmailAddress='urlabuse@circl.lu'" -f ticket |grep -v "id"|tail -n 5000`
    ;;
"netcraft")     LAST=`$RT_BIN list "Queue='Z_autoreport' and (Status='new' or Status='open') and Subject like 'Issue' and Requestor.EmailAddress like '@netcraft.com'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
"validated")     LAST=`$RT_BIN list "Queue='Validated Phishing' and (Status='new' or Status='open')" -f ticket |grep -v "id" |tail -n 5000`
    ;;
"incibe")   LAST=`$RT_BIN list "Queue='General' and (Status='new' or Status='open') and (Subject like 'Phishing' or Subject like 'Malicious' or Subject like 'C&C') and Requestor.EmailAddress='incidencias@incibe-cert.es'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
"shadowserver")     LAST=`$RT_BIN list "Queue='Shadowserver' and (Status='new' or Status='open') and Subject like 'Shadowserver Luxembourg (ASN)' and Requestor.EmailAddress like 'autoreports@shadowserver.org'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
"shadowserver-variot")     LAST=`$RT_BIN list "Queue='VARIOT' and (Status='new' or Status='open') and Subject like 'IoT' and Requestor.EmailAddress like 'autoreports@shadowserver.org'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
"cert-bund")    LAST=`$RT_BIN list "Queue='CERT-Bund' and (Status='new' or Status='open') and Subject like 'CB-Report' and Requestor.EmailAddress='reports@reports.cert-bund.de'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
"cert-eu")   LAST=`$RT_BIN list "Queue='Z_autoreport' and (Status='new' or Status='open') and Subject like 'Summary of your network security incidents' and Requestor.EmailAddress='nobody@cert.europa.eu'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
"phishtank")    LAST="$1"
    ;;
"test")  LAST="1278807"
    ;;
*)  if [[ "$1" =~ http(s)?:// ]]
    then 
      LAST=`$RT_BIN create -t ticket set subject='Abuse report: Phishing site' queue='General' | grep "created" | cut -d " " -f 3`
      $RT_BIN comment -m "$1" $LAST
    elif [[ "$1" =~ ^[0-9]+$ ]]
    then
      LAST="$1"
    else
      exit 1
    fi
    ;;
esac
