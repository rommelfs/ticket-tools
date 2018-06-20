#!/bin/bash
TICKETID=$1


confirm () {
    # call with a prompt string or use a default
    read -r -p "${1:-Are you sure? [y/N]} " response
    case $response in
        [yY][eE][sS]|[yY])
            true
            ;;
        *)
            exit
            false
            ;;
    esac
}



cat /tmp/f1
confirm "Start take-down process for this list of URLs? [y|N]"
for i in `cat /tmp/f1`
do 
  ./create_ticket_with_template.py $TICKETID templates/malicious_files_hosted.tmpl $i
done
echo $TICKETID | cat - open_tickets_list.txt > open_tickets_list.tmp && mv open_tickets_list.tmp open_tickets_list.txt
