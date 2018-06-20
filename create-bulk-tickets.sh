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
# Import functions
. ./create-bulk-tickets.inc
#
################################################################
#
# Input file, is one host or IP per line
INPUTFILE="/home/rommelfs/domains"
#
#TICKET_CC="raphael.vinot@circl.lu"
#
BULKSLEEP=2 # sleep between WHOIS lookups
#
SLEEP=5     # initial sleep when facing errors on WHOIS lookups
#
VALID=1	    # 1 = create tickets
#	      0 = just do lookups (for testing)
#
USE_TIMESTAMPFILE=0
TIMESTAMPFILE="/home/rommelfs/heartbleed.csv"
#
FALLBACK_EMAILS="sascha.rommelfangen@circl.lu"
#
################################################################
#
TESTING=0   # 1 = send test mail only
#	      0 = send mail to looked-up emails
#
# Email address for sending test mail to
TESTEMAIL="sascha.rommelfangen@circl.lu"
#
#
################################################################
#        BELOW ARE THE TEMPLATES, PLEASE CHANGE!               #
################################################################

# Adjust this to the format of the timestamp file
function GetTimeStamp() {
  echo `grep $IP $TIMESTAMPFILE | cut -d',' -f 1`
}

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
  NSINFO=""
  DOMAIN=""
  EMAILS=""
  WHOIS=""
  IPINFO=""
  TIMESTAMP=""
  TIMESTAMPSTRING=""
  # if input is an IP address and not a hostname:
  if [[ `echo $HOST| egrep '[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}'` ]]
  then 
    NSINFO=$HOST
  else
    # revert back to faup asap
    # until then use this to remove the first part of a url
    #DOMAIN=`echo $HOST |cut -d"." -f 2-`
    # or this to _keep_ the last two parts (usually domain.tld)
    #DOMAIN=`echo $HOST|rev|cut -d"." -f1,2|rev`
    # or this if domain=host
    DOMAIN=$HOST
    NSINFO=`dig +noadditional +noauthority $HOST | egrep -v "CNAME|NS" | grep NOERROR -A 1000 | egrep -v "^;|^$" | sort -u | tr -s "\t" " " | cut -d" " -f 5`
    WHOIS=`whois $DOMAIN | tr -s '\n' '^'`
    # Do whois lookup and check if we have a result or an error message
    while true
    do
      if [[ `echo $WHOIS | grep "Maximum query rate reached"` \
         || `echo $WHOIS | grep "access control limit exceeded"` \
         || `echo $WHOIS | grep "Try again later"` \
         || `echo $WHOIS | grep "restricted due to excessive access"` ]]
      then
        echo "DEBUG: Maximum query rate reached, sleeping $SLEEP seconds."
        echo "DEBUG: $DOMAIN"
        echo "DEBUG: $WHOIS"
        # in case of error, sleep
        sleep $SLEEP
        # and increase sleep fast
        SLEEP=$[SLEEP*2]
      else
        break
      fi
      WHOIS=`whois $DOMAIN | tr -s '\n' '^'`
    done
  fi
  for IP in $NSINFO;
  do
    IP_WHOIS="`whois $IP`"
    if [[ `echo $IP_WHOIS | grep "Unknown AS number or IP network"` ]]
    then
      echo "Unknown IP network for IP $IP, trying something else now..."
      ASN="`whois -h whois.circl.lu $IP | head -n1 | cut -d '|' -f 3`"
      AS_CONTACT=`whois -h whois.ripe.net AS$ASN`
      EMAILS="$EMAILS `echo $AS_CONTACT | egrep -i '@' | egrep -o '[-A-Za-z0-9.]+@[-A-Za-z0-9.]+' | sort | uniq | egrep -v 'peering@|ripe.net|apnic.net'`"
      IPINFO="$IPINFO"$nl$(echo -e "$HOST ($IP - hosted at `echo $AS_CONTACT |tr -s " " "\n"|grep as-name -A 1|tail -n 1`)")
    else
      EMAILS="$EMAILS `echo $IP_WHOIS | egrep -i '@' | egrep -o '[-A-Za-z0-9.]+@[-A-Za-z0-9.]+' | sort | uniq | egrep -v 'peering@|ripe.net|apnic.net'`"
      IPINFO="$IPINFO"$nl$(echo -e "$HOST ($IP - hosted at `whois $IP | egrep -v 'APNIC|RIPE' | grep -i 'netname:' | tr -s ' ' ' ' | cut -d' ' -f 2`)")
    fi
  done           
  EMAILS="$EMAILS `echo $WHOIS | tr -s '^' '\n' | egrep -iv 'changed|Registrar' | egrep -i '@' | egrep -o '[-A-Za-z0-9.]+@[-A-Za-z0-9.]+' | sort | uniq | egrep -v 'dns.lu|domreg@|@godaddy'`"
  if [[ $EMAILS ]]
  then
    # Create comma separated list of recipients
    EMAILS=`echo "$EMAILS" | tr ' ' '\n' | sort -u | sed 's/\.$//g' | tr '\n' ','`
    if [[ $EMAILS != "," ]]
    then
      # If list is not empty, strip surrounding commas
      EMAILS="${EMAILS:1:${#EMAILS}-2}"
      # replace known non-working email or 'blacklisted' addresses with valid ones
      EMAILS=`echo $EMAILS | sed 's/abuse@ispsystem.com/abuse@ispserver.com/g'`
      EMAILS=`echo $EMAILS | sed 's/abuse@ispsystem.net/abuse@ispserver.com/g'`
      EMAILS=`echo $EMAILS | sed 's/hostmaster@root.lu/abuse@as5577.net/g'`
      EMAILS=`echo $EMAILS | sed 's/noc@as5577.net/abuse@as5577.net/g'`
    else
      # Fallback for the case there is no email address at all
      echo "$HOST: no Email found - setting fallback address"
      EMAILS="$FALLBACK_EMAILS"      
    fi
  fi
  echo "$HOST: $EMAILS"

    ###############################
   # Below the ticket is created #
  ###############################
  
  if [[ $TESTING -eq 1 ]]
  then
    if [[ $TESTEMAIL ]]
    then
      EMAILS=""
      EMAILS="$TESTEMAIL"
    else
      echo "You set this to testing but forgot to specify an email address (\$TESTEMAIL)"
      echo "Exiting"
      exit 1
    fi
  fi
  # Attention: TICKET_EXISTS checks open, new and resolved tickets. Change in case of new campaign!
  #            Future idea: use campaign code in Subject that can be matched.
  #TICKET_EXISTS=`/opt/rt4/bin/rt list -i -q Investigations "((Subject like '${IP}') or (Subject like '${HOST}')) and (Status=open or Status=new or Status=resolved)"`
  TICKET_EXISTS=`/opt/rt4/bin/rt list -i -q Investigations "(Subject like '${HOST}') and (Status=open or Status=new or Status=resolved)"`
  ERROR=$?
  while [[ $ERROR -gt 0 ]]
  do  
    #TICKET_EXISTS=`/opt/rt4/bin/rt list -i -q Investigations "((Subject like '${IP}') or (Subject like '${HOST}')) and (Status=open or Status=new or Status=resolved)"`
    TICKET_EXISTS=`/opt/rt4/bin/rt list -i -q Investigations "(Subject like '${HOST}') and (Status=open or Status=new or Status=resolved)"`
    ERROR=$?
    echo "Error $ERROR contacting RT. Retrying."
    sleep 2
  done
  EXISTING_TICKET=`echo $TICKET_EXISTS | cut -d"/" -f 2 | cut -d " " -f 1 | egrep "[0-9]{5,}"`
  if [[ $EXISTING_TICKET ]]
  then
    echo "Ticket already created for $IP, ticket ID is #$EXISTING_TICKET Link: $RTTICKET$EXISTING_TICKET"
    echo "Not creating new ticket, storing $IP in duplicate file $INPUTFILE-DUPLICATE"
    echo "$HOST" >> "$INPUTFILE-DUPLICATE"
  else
    echo "Creating ticket now"
    if [[ $USE_TIMESTAMPFILE -eq 1 ]]
    then
      TIMESTAMPSTRING="Date and time of scan: $( GetTimeStamp ) (UTC)"
    fi
    if [[ $VALID -eq 1 ]]
    then
      if [[ $TICKET_CC ]]
      then
        OUTPUT1=`/opt/rt4/bin/rt create -t ticket set subject="$( EmailSubject )" requestor="$EMAILS" add cc="$TICKET_CC"`
      else
        OUTPUT1=`/opt/rt4/bin/rt create -t ticket set subject="$( EmailSubject )" requestor="$EMAILS"`
      fi
      echo $OUTPUT1
      if [[ `echo "$OUTPUT1" | egrep "Ticket [0-9]{5,} created."` ]]
      then
        TICKETID=`echo "$OUTPUT1" | egrep -o "[0-9]{5,}"`
        OUTPUT2=`/opt/rt4/bin/rt correspond -m "$( EmailTemplate )" $TICKETID`
        if [[ `echo "$OUTPUT2" | egrep "# Message recorded"` ]]
        then 
          echo "Successfully created ticket #$TICKETID $EMAILS $IPINFO"
          echo "Link: $RTTICKET$TICKETID"
        else
          echo "Error while processing $HOST!"
        fi
      else
        echo "Unable to create ticket for $IPINFO ($HOST)"
        echo "Storing $( HOST ) in $( INPUTFILE )-FAILED"
        echo "$HOST" >> "$INPUTFILE-FAILED"
      fi
    else
      echo "Would have created a ticket for $HOST to $EMAILS"
    fi
  fi

echo "sleeping $BULKSLEEP seconds"
sleep $BULKSLEEP 
done < "$INPUTFILE"

