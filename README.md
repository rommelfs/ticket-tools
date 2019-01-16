# ticket-tools

More tools are about to be released

## get-reports.sh
`get-reports.sh` is a standalone tool to iterate through defined submission types. It keeps a list of definitions in  `get-reports.inc`. 
The submission is checked by `UrlAbuse` and offers the possibility to 
- automatically create a take-down request based on templates (from `./templates`), the source ticket will be moved to the incident queue. A classification will be added according to the take-down type.
- ignore the ticket (ticket will be closed without further action)
- exit the program (start next time at the ticket where exited)

The tool relies on a working version of `create_ticket_with_template.py`
This tool deprecates the following three tools.

### create_ticket_with_template.py

`create_ticket_with_template.py` 
`Usage: create_ticket_with_template.py Incident-ID Templatename URL [Onlinecheck:True|False] [Queue]`

This tools creates a take-down request as an investigation to an incident (`Incident-ID`). It uses the given `Templatename` (from `./templates`).
The input is based on the given `URL`, which is checked with `UrlAbuse`. The verification of the content being online can be skipeed (`False`).
A specific queue can be mentioned (default is 5).

Requires `UrlAbuse` from https://github.com/CIRCL/url-abuse



### get-urlabuse-reports.sh (deprecated)
`get-urlabuse-reports.sh` is a standalone tool to iterate through new `UrlAbuse` submissions (https://www.circl.lu/urlabuse/ and https://www.circl.lu/services/urlabuse/) from users to the ticket system.
The submission is checked by `UrlAbuse` and offers the possibility to 
- automatically create a take-down request based on templates (from `./templates`), the source ticket will be closed
- ignore the ticket (ticket will be closed without further action)
- exit the program (start next time at the ticket where exited)

The tool relies on a working version of `create_ticket_with_template.py`

### get-phishlab-reports.sh (deprecated)
`get-phishlab-reports.sh` is a standalone tool to iterate through new Phishlab reports to the ticket system.
The submission is checked by `UrlAbuse` and offers the possibility to 
- automatically create a take-down request based on templates (from `./templates`), the source ticket will be closed
- ignore the ticket (ticket will be closed without further action)
- exit the program (start next time at the ticket where exited)

The tool relies on a working version of `create_ticket_with_template.py`

## create_bulk_ticket_with_template.py

`create_bulk_ticket_with_template.py`
`Usage: create_bulk_ticket_with_template.py Incident-ID Templatename csv-file`

This tool creates a take-down request as an investigation to an incident (`Incident-ID`). It uses the given `Templatename` (from `./templates`).
The input is based on a `CSV` list as in the following format (example data):
```
Format: ASN,IP,Country code,Last seen (UTC),Malware,Source Port,Destination IP,Destination Port,Destination Hostname

"12345","1.2.3.4","2018-06-17 16:11:33","necurs","6789","2.3.4.5","80","","tcp"
```
Entries are grouped by ASN and only one notification per AS number is sent.


## get-urlquery-urls.sh
`get-urlquery-urls.sh` fetches the content of new urlquery reports and sends the entries to an XMPP chatroom

## get-urlmon-urls.sh
`get-urlmon-urls.sh` fetches the content of new urlquery reports and sends the entries to an XMPP chatroom

## get-ms-urls.sh
`get-ms-urls.sh` fetches the content of new urlquery reports and sends the entries to an XMPP chatroom
