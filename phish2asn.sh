#!/bin/bash
URL="$1"
HOST=`faup -f host "$URL"`
IS_REPORTED="$2"

IP=`dig +short "$HOST"`

ASN=$(dig +short TXT ` echo $IP| awk -F. '{print $4"."$3"." $2"."$1".origin.asn.cymru.com"}'`|cut -d '"' -f 2|cut -d " " -f 1 |head -n1)
EPOC=`date '+%s'`
echo $ASN, $IP, $HOST, $URL, $EPOC
