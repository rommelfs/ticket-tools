#!/bin/bash



# Adjust to reflect subject of the current issue
function EmailSubject() {
  echo "Critical vulnerability in your server $HOST"
}


# Adjust to reflect body of message of the current issue
# Use variables HOST, DOMAIN and IPINFO within the text

function EmailTemplate() {
  echo "To Whom It May Concern:

(This message is only available in English, but feel free to contact us
in French, German or Luxembourgish)

(Ce message est uniquement en anglais, mais n'hésitez pas à nous
contacter en français)

(Diese Benachrichtigung is in Englisch verfasst, unsere Unterstützung
bieten wir aber auch auf Deutsch an)

(Dëse Message ass exklusiv op Englesch, mä dir kënnt eis gär op
Lëtzebuergesch kontaktéieren)

This is a message from CIRCL, Computer Incident Response Center Luxembourg,
a government-driven and funded initiative designed to gather, review,
report and respond to computer security threats and incidents.
CIRCL is the CERT/CSIRT (Computer Emergency Response Team/Computer Security Incident Response Team) for the private sector, communes and non-governmental entities in Luxembourg.

It seems that the server(s) listed below are accepting SSL connections on
port 443 are potentially vulnerable to CVE-2014-0160 (more details at [1]):

$IPINFO
$TIMESTAMPSTRING

OpenSSL is vulnerable to memory leakage to the connected client or server.
In other words, anyone can remotely retrieve sensitive information
(e.g. secret keys, passwords, confidential document) from the memory of
the remote servers without leaving traces.

This is a critical vulnerability and you must patch your OpenSSL
software as soon as possible.

Could you check with your security team in charge of this server to
patch and regenerate the key materials as soon as possible?
And obviously reset all the credentials on affected systems after the
patches.

If you are an ISP and not directly responsible of those systems, it is
very important you forward this message to your customers or the operators
maintaining the above mentioned system.

If the concerned IP address is dynamically assigned, please note that the
information has been collected within the last 48 hours.

This message has been generated automatically, thus we are sorry of it
reached the wrong mailbox or if you received it multiple times
or if the server was patched in the mean time.

If you have any question or remarks, please reply to this mail or send a
new email to info@circl.lu, using the subject line of this mail.

Thank you very much for your help.

Kind regards.

[1] https://www.circl.lu/pub/tr-21/

--
CIRCL - Computer Incident Response Center Luxembourg
41, avenue de la Gare L-1611 Luxembourg
http://www.circl.lu/

"
}
