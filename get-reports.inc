URLABUSE_BIN="python /home/urlabuse/server.py"
CREATE_BULK_BIN="/home/rommelfs/ticket-tools/process_reports.py"
CREATETICKET_BIN="/home/rommelfs/ticket-tools/create_ticket_with_template.py"
TEMPLATE_DIR="/home/rommelfs/ticket-tools/templates"
TEMPLATE_PHISHING="$TEMPLATE_DIR/phishing_server.tmpl"
TEMPLATE_MALWARE="$TEMPLATE_DIR/malicious_files_hosted.tmpl"
TEMPLATE_DEFACEMENT="$TEMPLATE_DIR/defaced_website.tmpl"
TEMPLATE_COMPROMISED_WEBSHELL="$TEMPLATE_DIR/compromised_website-with-webshell.tmpl"
CERTBUND_TOPICS="Malware infections in country, $TEMPLATE_DIR/cb_malware-infections.tmpl, 582865
Avalanche, $TEMPLATE_DIR/cb_malware-compromised-avalance-client.tmpl, 582867"

SHADOWSERVER_TOPICS="NTP Monitor, $TEMPLATE_DIR/ss_ntp-monitor.tmpl, 582270
Accessible Cisco Smart Install, $TEMPLATE_DIR/ss_accessible-cisco-smart-install.tmpl, 582271
Accessible CWMP, $TEMPLATE_DIR/ss_accessible-cwmp.tmpl, 582971
Open mDNS Servers, $TEMPLATE_DIR/ss_accessible-mdns.tmpl, 582968
Hadoop Service, $TEMPLATE_DIR/ss_accessible-hadoop.tmpl, 582973
Spam URL, $TEMPLATE_DIR/ss_spam-url.tmpl, 582792 
Compromised Website, $TEMPLATE_DIR/ss_compromised-website.tmpl, 582938 
Open Redis Server, $TEMPLATE_DIR/ss_open-redis-server.tmpl, 582939
DNS Open Resolvers, $TEMPLATE_DIR/ss_dns-open-resolvers.tmpl, 582946
Open TFTP Server, $TEMPLATE_DIR/ss_open-tftp-servers.tmpl, 582953
Vulnerable NAT-PMP Systems, $TEMPLATE_DIR/ss_vulnerable-nat-pmp-systems.tmpl, 582764 
Open Memcached Server, $TEMPLATE_DIR/ss_open-memcached-server.tmpl, 582961
Open MS-SQL Server, $TEMPLATE_DIR/ss_open-mssql-server.tmpl, 582962
Open Portmapper Scan, $TEMPLATE_DIR/ss_open-portmapper.tmpl, 582967
Accessible/Open MongoDB Service, $TEMPLATE_DIR/ss_open-mongodb-service.tmpl, 582963
Open Elasticsearch Server, $TEMPLATE_DIR/ss_open-elasticsearch-server.tmpl, 582966
Open LDAP Services, $TEMPLATE_DIR/ss_open-ldap-server.tmpl, 582970"

#SMB Service, $TEMPLATE_DIR/defaced_website.tmpl, 582974
#VNC Service, $TEMPLATE_DIR/defaced_website.tmpl, 582975
#Drone Report, $TEMPLATE_DIR/defaced_website.tmpl, 582940
#Drone Brute Force, $TEMPLATE_DIR/defaced_website.tmpl, 582941
#Sandbox URL, $TEMPLATE_DIR/defaced_website.tmpl, 582942
#Command and Control, $TEMPLATE_DIR/defaced_website.tmpl, 582943
#Sinkhole HTTP Drone, $TEMPLATE_DIR/defaced_website.tmpl, 582944
#Microsoft Sinkhole, $TEMPLATE_DIR/defaced_website.tmpl, 582945
#NTP Version, $TEMPLATE_DIR/defaced_website.tmpl, 582947
#SNMP Report, $TEMPLATE_DIR/defaced_website.tmpl, 582948
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

RT_BIN="/opt/rt4/bin/rt"
case "$1" in 
"phishlabs")    LAST=`$RT_BIN list "(Status='new' or Status='open') and Queue='General' and Requestor.EmailAddress='soc@phishlabs.com'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
"urlabuse")     LAST=`$RT_BIN list "Queue='Z_Autoreport' and (Status='new' or Status='open') and Subject like 'URL Abuse report' and Requestor.EmailAddress='urlabuse@circl.lu'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
"netcraft")     LAST=`$RT_BIN list "Queue='General' and (Status='new' or Status='open') and Subject like 'Issue' and Requestor.EmailAddress like '@netcraft.com'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
"shadowserver")     LAST=`$RT_BIN list "Queue='Z_Autoreport' and (Status='new' or Status='open') and Subject like 'Shadowserver Luxembourg (ASN)' and Requestor.EmailAddress like 'autoreports@shadowserver.org'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
"cert-bund")    LAST=`$RT_BIN list "Queue='General' and (Status='new' or Status='open') and Subject like 'CB-Report' and Requestor.EmailAddress='reports@reports.cert-bund.de'" -f ticket |grep -v "id" |tail -n 5000`
    ;;
''|*[0-9]*) LAST="$1" 
    ;;
*)  exit 1
    ;;
esac
