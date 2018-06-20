#!/bin/bash
#
#  2014-04-29 Sascha Rommelfangen, CIRCL
#  
################################################################
#
# Import RT settings
. ./inc_rt.conf
#
################################################################
#
GLOBIGNORE="*"

while true
do
  TICKET=""
  TICKETID=""
  ATTACHMENT=""
  ATTACHMENTID=""
  date
  TICKET=`/opt/rt4/bin/rt ls -i -t ticket -q General "Subject like 'ProxyList for Today' and Status=new and requestor='noreply@pl.hidemyass.com'"|tail -n 1`
  ERROR=$?
  if [[ $ERROR -eq 0 ]] && [ -n "$TICKET" ]
  then
    TICKETID=`echo $TICKET | cut -d"/" -f 2 | cut -d " " -f 1 | egrep "[0-9]{5,}"`
    if [ -n "$TICKETID" ]
    then
      echo $TICKETID
      ATTACHMENT=`/opt/rt4/bin/rt show ticket/$TICKETID/attachments/ | grep 'application/zip'`
      if [ -n "$ATTACHMENT" ]
      then 
        ATTACHMENTID=`echo $ATTACHMENT | cut -d ":" -f 1 | egrep "[0-9]{5,}"`
        if [ -n "$TICKETID" ]  && [ -n "$ATTACHMENTID" ]
        then 
          echo "$ATTACHMENTID"
          /opt/rt4/bin/rt show ticket/$TICKETID/attachments/$ATTACHMENTID/content > /tmp/proxyfile.zip 
          7z -so x /tmp/proxyfile.zip full_list_nopl/_full_list.txt > /tmp/proxy.txt
          echo "127.0.0.1:8123" >> /tmp/proxy.txt
          mv /tmp/proxy.txt /var/www/html/upload
          if [[ `file -i /var/www/html/upload/proxy.txt | grep 'text/plain; charset=us-ascii'` ]]
          then
            /opt/rt4/bin/rt resolve $TICKETID
            echo "Ticket $TICKETID resolved"
          fi
        fi
      fi
    fi 
  else
    echo "No ticket :(" 
  fi
  echo "Sleeping 1 hour..."
  sleep 3600
done
