#!/usr/bin/python3
import sys
import re
import dns.resolver
from pyfaup.faup import Faup


url = sys.argv[1]
identified = 0
ipfs_url_pattern="((.*/ipfs/([a-zA-Z0-9]{46}))|([a-zA-Z0-9]{59}\.ipfs))"
print("Examining URL: " + url)
dig="dig +short TXT _dnslink.best-practice.se"
result = re.match(ipfs_url_pattern, url)

if (result):
    print("[+] URL regex matched")
    identified+=1
else:
    print("[-] URL regex did not match")


f = Faup()
f.decode(url)
result = f.get_domain()
query = "_dnslink." + result
print("Examining DNS: " + query)
try:
    dns_result = dns.resolver.query(query,"TXT").response.answer[0][-1].strings[0]
except:
    print("[-] no DNS result")
    dns_result = False 

if (dns_result):
    pattern=".*\/ipfs\/.*"
    result = re.match(pattern, dns_result.decode())
    print("[+] DNS regex matched")
    identified+=1

print("Total matches: " + str(identified))
if (identified >= 1):
    print("Verdict: " + url + " is IPFS. Send abuse mail to abuse@ipfs.io")
else:
    print("Verdict: " + url + " is probably not IPFS. Send abuse mail to ISP, hosting company and domain registrant")
