#!/bin/bash 

set -o noglob

# Read config file (API key)
. ./inc_leakix.conf

function extractEmails () {
    echo "$1" | grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" 
}

function removeEmails() {
    echo "$1" | egrep -v "hostmaster@eurodns.com|abuse@ripe.net"
}

function mergeEmails() {
    echo "$1" | tr '\n' ','|sed -e 's/,$//' | tr -d '[:space:]'
}

function deduplicateEmails() {
    echo "$1" | tr ',' '\n' | sort -u | tr '\n' ','|sed -e 's/,$//'
}

function parse_and_process() {
	INPUT_TYPE="$1"
	MASTER_TICKET="$2"
	HISTORY_FILE="$3"
	TEMPLATE="$4"
	INPUT="$5"
	if [[ ! -f "$TEMPLATE" ]] 
	then
		echo "Template file $TEMPLATE doesn't exist. Please check. Exiting."
		exit 1
	fi
        while read -r INPUT <&3
        do
		#echo $INPUT
                OUTPUT=""
                EMAIL=""
		HIST_EMAIL=""
                IP=""
		DOMAIN=""
		VERSION="n/a"
		out=""
		if [[ $INPUT_TYPE == "JSON" ]]
		then
			IP=`echo $INPUT | jq -r ".ip"`
			echo $IP
                	PORT=`echo $INPUT | jq -r ".port"`
                	RESULT=`echo $INPUT | jq -r ".summary"`
                	TIME=`echo $INPUT | jq -r ".time"`
			TRY_VERSION=`echo $INPUT | jq -r ".service.software.version"`
			if [ ! -z $TRY_VERSION ]
			then
				VERSION="$TRY_VERSION"
			fi
		elif [[ $INPUT_TYPE == "SHODAN-JSON" ]]
		then
			IP=`echo $INPUT | jq -r ".ip_str"`
			echo $IP
                	PORT=`echo $INPUT | jq -r ".port"`
                	RESULT=`echo $INPUT | jq -r ".product"`
                	TIME=`echo $INPUT | jq -r ".timestamp"`
			TRY_VERSION=`echo $INPUT | jq -r ".service.software.version"`
			if [ ! -z $TRY_VERSION ]
			then
				VERSION="$TRY_VERSION"
			fi
		elif [[ $INPUT_TYPE == "CSV" ]]
		then
                	IP=`echo $INPUT | cut -d ',' -f 2 | cut -d '"' -f 2`
                	PORT=`echo $INPUT | cut -d ',' -f 4`
			TIME=`echo $INPUT | cut -d ',' -f 1`
			RESULT=`echo $INPUT | cut -d ',' -f 6`
		else
			echo "No parsable input type. Exiting."
			exit 1
		fi
		echo -n "$IP:$PORT"
                if [[ "$IGNORE_HISTFILE" == 0 ]]
		then
			if [[ `egrep "^$IP" $HISTORY_FILE | egrep "$VERSION"` ]]
                	then
                        	echo " ... skipped (already processed, version: $VERSION)"
                        	continue
			elif [[ `egrep "$IP" $HISTORY_FILE | cut -s -d " " -f 2 |tail -n 1` ]]
			then
				echo " ... old version: `egrep "$IP" $HISTORY_FILE | cut -s -d " " -f 2 |tail -n 1`, current version: $VERSION"
			elif [[ `egrep "^$IP" $HISTORY_FILE` ]]
                	then
                        	echo " ... skipped (already processed)"
                        	continue
			else
				echo " ... processing now!"
                	fi
		fi
		HIST_EMAIL=`egrep "^$IP" $HISTORY_FILE | cut -s -d " " -f 3| tail -n 1`
		echo "$HIST_EMAIL"
		#echo "Result: $RESULT"
		echo "$VERSION"
		CERTIFICATE=$(echo | timeout 15 openssl s_client -servername $IP -connect $IP:$PORT 2>/dev/null)
        	if [[ $? -eq 0 ]]
        	then
                	DOMAIN=$(echo "$CERTIFICATE"| openssl x509 -noout -ext subjectAltName -subject|tail -1|egrep "DNS|subject" | sed -e 's/DNS://g'|sed -e 's/subject//g'|tr -d '[:space:]' | tr ',' '\n' | sed -e 's/CN=//g' | sed -e 's/=//g')
                	echo -e "\nList of domains:"
                	for domain in `echo "$DOMAIN"`
                	do
                        	echo "  - $domain"
                	done
                	for ip in `echo "$DOMAIN"`
                	do
                        	if [[ `echo $ip | wc -m` -gt `echo $out | wc -m` ]]
                        	then
                                	out=$ip
                        	fi
                	done
                	DOMAIN=$out
                	echo "Using domain: $DOMAIN"
                	DOMAIN=$(echo "  - $DOMAIN"| cut -d '=' -f 3 | faup -f domain)
        	else
                	echo "The SSL Setup of $IP is incorrect. Manual investigation required."
                	DOMAIN="$IP"
        	fi
                OUTPUT+="$IP:$PORT\n"
                if [ ! -z "$RESULT" ]
		then
			OUTPUT+="$RESULT"
		fi
		if [[ $(type -t validate_hook) == function ]] 
		then
			VAL=$(validate_hook "$IP:$PORT")
			RETVAL=$?
			if [[ $RETVAL == 1 ]]
			then
				echo -e "\nValidation result: $VAL"
				echo "$IP $VERSION" >> $HISTORY_FILE
				continue
			else
				echo -e "\nValidation result: $VAL"
				OUTPUT+="\nValidation result: $VAL"
			fi
		fi
		OUTPUT+="\n(scanned on $TIME)"
                EMAIL+=$($CMD_WHOIS $IP|egrep -i "abuse"|grep "@" | grep -v "No abuse contact registered" |uniq)
		echo "DOMAIN: $DOMAIN"
		if [ ! -z "$DOMAIN" ]
		then
			EMAIL+=$($CMD_WHOIS_EXTRA $DOMAIN|grep -v "registrar" | grep "@"|uniq)
		fi
		EMAIL=$(extractEmails "$EMAIL")
		if [ ! -z "$HIST_EMAIL" ]
		then
			EMAIL+=",$HIST_EMAIL"
		fi
                EMAIL=$(removeEmails "$EMAIL")
                EMAIL=$(mergeEmails "$EMAIL")
                EMAIL=$(deduplicateEmails "$EMAIL")
                echo -e "\nURL: $OUTPUT"
		echo "Preparing email (ticket) to: $EMAIL"
		echo "Master ticket: $MASTER_TICKET - Template: $TEMPLATE"
                read -e -p "Is the list of recipients correct (y), do you want to edit the list (e) or cancel and ignore? (y/e/c)" -n1 ans
                if [[ $ans == "e" ]]
                then
                	read -e -p "Edit email addresses: " -i "$EMAIL" EMAIL
                        EMAIL=$(mergeEmails "$EMAIL")
                fi
                if [[ $ans == 'c' ]]
                then
                        echo "$IP $VERSION $EMAIL" >> $HISTORY_FILE
                        continue
                fi
                echo -e "$OUTPUT" | $CMD_LEAKIX_PY $MASTER_TICKET $TEMPLATE $IP $EMAIL 5
                echo "$IP $VERSION $MAIL" >> $HISTORY_FILE
        done 3<<< "$INPUT"
}

config=""
result_numbers=200
type=""
LIST=""

# Default Input Type
INPUT_TYPE="JSON"
IGNORE_HISTFILE=0

if [ -z "$1" ]
then
	echo "Usage: $0 <config>"
	echo "Known configurations:"
	cat $0 | grep -A 1000 'case "$1" in' | grep '")' | tail -n +2
	exit 1
else
	if [ ! -z "$2" ]
	then
		if [[ "$2" == "-i" ]]
		then
			IGNORE_HISTFILE=1
		fi
	fi
	echo "IGNORE STATE: $IGNORE_HISTFILE"
	echo -n "Fetching LeakIX results for search terms: "
	case "$1" in
		"1")	config='+country:"Luxembourg" +plugin:"ExchangeVersion"'
        		MASTER_TICKET="2850595"
        		TEMPLATE="templates/leakix-vulnerable-exchange-notification.tmpl"
			;;
		"2")	config='+country:"Luxembourg" +plugin:"ApacheStatusPlugin" +port:80'
        		MASTER_TICKET="3015637"
        		TEMPLATE="templates/leakix-apache-status-notification.tmpl"
			function validate_hook
			{
				TUPEL="$1"
                		test=$(bash -c "curl --connect-timeout 5 -s http://$TUPEL/server-status?auto |egrep '^Uptime'; exit $?" 2>&1)
                		if [[ "$test" ]]
                		then
					# In case of successfull test, return a string from the validation
					echo " /server-status is accessible. Sample output -> $test"
					# and a return code - 0 = validated, 1 = not validated
					return 0
				fi
				return 1
			}
			;;
		"3")	config='+(country:"Luxembourg" host:"lu") +plugin:"ZimbraPlugin"'
        		MASTER_TICKET="3032574"
        		TEMPLATE="templates/leakix-zimbra-vulnerability.tmpl"
			;;
		"4")	config='+country:"Luxembourg" +plugin:"PulseConnectPlugin"'
       			MASTER_TICKET="3061413"
        		TEMPLATE="templates/leakix-pulseconnect-vulnerability.tmpl"
			;;
		"5")	config='+country:"Luxembourg" +plugin:"FortiOSPlugin"'
        		MASTER_TICKET="3063008"
        		TEMPLATE="templates/leakix-vulnerable-fortigateplugin-notification.tmpl"
			;;
		"6")	config='+country:"Luxembourg" +plugin:"EsxVersionPlugin"'
        		MASTER_TICKET="3131881"
        		TEMPLATE="templates/leakix-vulnerable-vmware-esxi-notification.tmpl"
			;;
		"7")	config='+country:"Luxembourg" +plugin:"VeeamPlugin"'
        		MASTER_TICKET="3202939"
        		TEMPLATE="templates/leakix-vulnerable-veeam-notification.tmpl"
			;;
		"8")	config='+country:"Luxembourg" +plugin:"SophosPlugin"'
        		MASTER_TICKET="3294860"
        		TEMPLATE="templates/leakix-vulnerable-sophos-notification.tmpl"
			;;
		"9")	config='+country:"Luxembourg" +plugin:"FortiGatePlugin"'
        		MASTER_TICKET="3366753"
        		TEMPLATE="templates/leakix-vulnerable-fortios-CVE-2023-27997.tmpl"
			;;
		"10")	config='+country:"Luxembourg" +plugin:"CitrixADCPlugin"'
        		MASTER_TICKET="3413686"
        		TEMPLATE="templates/leakix-vulnerable-citrix-CVE-2023-3519.tmpl"
			;;
		"11")	config='+country:"Luxembourg" +plugin:"MobileIronCorePlugin"'
        		MASTER_TICKET="3419288"
        		TEMPLATE="templates/ss-vulnerable-IvantiMobileIron.tmpl"
			function validate_hook
			{
				TUPEL="$1"
				test=$(curl -k https://$TUPEL/mifs/aad/api/v2/ping)
				echo $test
			}
			;;
		"12")	config='+country:"Luxembourg" +plugin:"IOSEXPlugin"'
        		MASTER_TICKET="3582250"
        		TEMPLATE="templates/leakix-vulnerable-cisco-CVE-2023-20198.tmpl"
			;;
		"13")	config='+country:"Luxembourg" +plugin:"QnapVersion"'
        		MASTER_TICKET="3604782"
        		TEMPLATE="templates/leakix-vulnerable-qnap.tmpl"
			;;
		"14")	config='+country:"Luxembourg" +plugin:"MobileIronSentryPlugin"'
        		MASTER_TICKET="3419288"
        		TEMPLATE="templates/ss-vulnerable-IvantiMobileIron.tmpl"
			;;
		"15")	config='+country:"Luxembourg" +plugin:"IvantiConnectSecure"'
        		MASTER_TICKET="3061413"
        		TEMPLATE="templates/leakix-compromised-ivanti-connect-secure-policy-secure.tmpl"
			;;
		"16")	config='+country:"Luxembourg" +plugin:"ZyxelVersion"'
        		MASTER_TICKET="3702090"
        		TEMPLATE="templates/leakix-vulnerable-zyxel.tmpl"
			;;
		"s1")   config="Shadowserver Ivanti MobileIron hack (don't use unless you know what to do)"
			LIST=`cat input`
			INPUT_TYPE="CSV"
        		MASTER_TICKET="3419288"
			TEMPLATE="templates/ss-vulnerable-IvantiMobileIron.tmpl"
			;;
		"s2")   config="Shodan JSON hack for Ivanti Connect Secure and Ivanti Policy Secure Gateways (don't use unless you know what to do)"
			LIST=`cat t.json`
			INPUT_TYPE="SHODAN-JSON"
        		MASTER_TICKET="3682084"
			TEMPLATE="templates/shodan-vulnerable-ivanti-connect-secure-policy-secure.tmpl"
			;;
		*)	echo "Configuration $1 not known"
		        exit 1
			;;
	esac	
	echo $config
        HISTORY_FILE="leakix_processed_$1.txt"
	if [[ "$INPUT_TYPE" == "JSON" ]]
	then
		LIST=`cd $DIR_LEAKIX_CLI ; $CMD_LEAKIX_CLI -k $LEAKIX_API_KEY -q "$config" -j -l $result_numbers`
	fi
	parse_and_process "$INPUT_TYPE" "$MASTER_TICKET" "$HISTORY_FILE" "$TEMPLATE" "$LIST"
fi


exit 0 
