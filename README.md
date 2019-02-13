# ticket-tools

## Description

A collection of tools interfacing with RT/RTIR in order to interact with the world (e.g. send out take-down requests or other notifications)

## Dependencies
- `UrlAbuse` from https://github.com/CIRCL/url-abuse
- `RT` from https://bestpractical.com
- `sed`, `cut`, `grep`
- `faup` from https://github.com/stricaud/faup
- Python >=3.4
- Python dependencies: `string`, `ioc_fanger`, `pyurlabuse`, `rt`, `requests`, `logging`, `sphinxapi`, `urllib3`

## Outlook
More tools are likely to be released

# Description of the tools

## get-reports.sh
`get-reports.sh` is a standalone tool to iterate through defined submission types. Submission types can be defined as an RT/RTIR search. It keeps a list of definitions in  `get-reports.inc`. There are two modes of operation:
- Automatic processing of the incoming tickets (e.g. any 30 minutes with a cronjob: `30 * * * * "cd /home/rommelfs/ticket-tools; ./get-reports.sh shadowserver"`)
- Semi-automatic processing (automatic display of a list of open tickets from one category. One-key decision and processing: 
The submission is checked by `UrlAbuse` and offers the possibility to 
- automatically create a take-down request based on templates (from `./templates`), the source ticket will be moved to the incident queue. A classification will be added according to the take-down type.
- Pre-defined are these types of submissions: phishing, malware, defacement, webshell
- Possible actions are:
  - ignore the ticket (keep it open for next run), and continue
  - ignore and close the ticket (ticket will be closed without further action, leaving a comment in the ticket)
  - exit the program (start next time at the ticket where exited)
- When set up, an external screenshot taking tool can produce a screenshot of the offending site. It will be attached as comment to the ticket.

The tool relies on a working version of `create_ticket_with_template.py`

### create_ticket_with_template.py

`create_ticket_with_template.py` 
`Usage: create_ticket_with_template.py Incident-ID Templatename URL [Onlinecheck:True|False] [Queue]`

This tools creates a take-down request as an investigation to an incident (`Incident-ID`). It uses the given `Templatename` (from `./templates`).
The input is based on the given `URL`, which is checked with `UrlAbuse`. The verification of the content being online can be skipped (`False`).
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
