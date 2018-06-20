#!/bin/bash 
#
#  Automatic bulk ticket creation based on a list of hosts or 
#  IP addresses (a mix is ok). 
#  Script will do lookup of associated email addresses,
#  create a ticket according to template and send message
#  to email addresses.
#
#  2014-04-15 Sascha Rommelfangen, CIRCL
#  
################################################################
#
# Import RT settings
. ./inc_rt.conf
#
################################################################
#
# Input file, is one host or IP per line
INPUTFILE="/home/rommelfs/domainsfixed"
#
#
BULKSLEEP=1 # sleep between WHOIS lookups
#
################################################################
#
TESTING=0   # 1 = dry run
#	      0 = really closing tickets 
#
#
################################################################
################################################################

#            NOTHING TO SEE HERE, WALK ALONG!                  # 

################################################################
################################################################

nl='
'
GLOBIGNORE="*"

while read HOST
do
  echo $HOST
  if [[ $TESTING -eq 0 ]]
  then
    TICKET_EXISTS=`/opt/rt4/bin/rt list -i -q Investigations "(Subject like '${HOST}') and (Status=open or Status=new)"`
    ERROR=$?
    while [[ $ERROR -gt 0 ]]
    do  
      TICKET_EXISTS=`/opt/rt4/bin/rt list -i -q Investigations "(Subject like '${HOST}') and (Status=open or Status=new)"`
      ERROR=$?
      echo "Error $ERROR contacting RT. Retrying."
      sleep 2
    done
    EXISTING_TICKET=`echo $TICKET_EXISTS | cut -d"/" -f 2 | cut -d " " -f 1 | egrep "[0-9]{5,}"`
    if [ ! -z "$EXISTING_TICKET" ]
    then
      echo "Found ticket $EXISTING_TICKET"
      OUTPUT=`/opt/rt4/bin/rt resolve $EXISTING_TICKET`
      if [[ `echo $OUTPUT |grep "# Ticket $EXISTING_TICKET updated."` ]]
      then
        echo "Ticket $EXISTING_TICKET for $HOST resolved".
        echo "$EXISTING_TICKET $HOST" >> $INPUTFILE-RESOLVED
      else
        echo "Ticket $EXISTING_TICKET for $HOST FAILED to resolve."
        echo "$EXISTING_TICKET $HOST" >> $INPUTFILE-FAILED
        echo "$OUTPUT" >> $INPUTFILE-FAILED
      fi
    else
      echo "No matching ticket for $HOST"
      echo "$HOST" >> $INPUTFILE-SKIPPED
    fi
  fi
sleep $BULKSLEEP 
done < "$INPUTFILE"

