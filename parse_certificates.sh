#!/bin/bash
IP=$1
PORT=$2

CERTIFICATE=$(echo | timeout 15 openssl s_client -servername $IP -connect $IP:$PORT 2>/dev/null)
if [[ $? -eq 0 ]]
then
	DOMAIN=$(echo "$CERTIFICATE"| openssl x509 -noout -ext subjectAltName -subject|tail -1|egrep "DNS|subject" | sed -e 's/DNS://g'|sed -e 's/subject//g'|tr -d '[:space:]' | tr ',' '\n' | sed -e 's/CN=//g' | sed -e 's/=//g')
fi
echo $DOMAIN
