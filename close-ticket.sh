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
TICKETID="$1"
OUTPUT=`/opt/rt4/bin/rt resolve $TICKETID`
if [[ `echo $OUTPUT |grep "# Ticket $TICKETID updated."` ]]
then
    echo "Ticket $TICKETID resolved".
else
    echo "Ticket #$TICKETID FAILED to resolve."
fi

