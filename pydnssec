# inspired by https://stackoverflow.com/a/26137120
import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype

target = 'domain.com'
# get nameservers for target domain
response = dns.resolver.resolve(target+".", 'NS')

# we'll use the first nameserver in this example
nsname = response.rrset[0].to_text() # name
response = dns.resolver.resolve(nsname, 'A')
nsaddr = response.rrset[0].to_text() # IPv4

# get DNSKEY for zone
request = dns.message.make_query(target+".",
                                 dns.rdatatype.DNSKEY,
                                 want_dnssec=True)

# send the query
response = dns.query.udp(request,nsaddr)
if response.rcode() != 0:
    # HANDLE QUERY FAILED (SERVER ERROR OR NO DNSKEY RECORD)
    print('QUERY FAILED')

# answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY)
answer = response.answer
if len(answer) != 2:
    # SOMETHING WENT WRONG
    print('response does not contain DNSKEY and RRSIG(DNSKEY)')

# the DNSKEY should be self signed, validate it
name = dns.name.from_text(target+".")
try:
    dns.dnssec.validate(answer[0],answer[1],{name:answer[0]})
except dns.dnssec.ValidationFailure:
    # BE SUSPICIOUS
    print('DNSKEY is not self-signed')
else:
    # WE'RE GOOD, THERE'S A VALID DNSSEC SELF-SIGNED KEY FOR example.com
    print('DNSKEY is self-signed')
