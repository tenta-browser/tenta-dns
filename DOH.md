# Tenta DNS and DNS over HTTPS (DoH)
After a lengthy iteration, we are finally launching our v2 DNS resolver, incorporating hundreds of fixes and improvements.
Tenta DNS at its core, is about three things: speed, precision and privacy. This is why besides the standard TCP and UDP protocols, we support DNS-over-TLS and DNS-over-HTTPS. What we have learned from the first iteration, we perfected in this one. Tenta DNS has always-on DNSSEC validation, a more robust handling of the occasional implementation inconsistencies,
and a caching subsystem tailored specifically for a DNS resolver. Finally, our DNS-over-TLS service is active (albeit, probably unused in the vast majority of cases) during upstream queries too.

To use DNS-over-HTTPS, we have set up two domains, https://opennic.tenta.io/dns-query and https://iana.tenta.io/dns-query,  which use OpenNIC and ICANN root servers, respectively. 

The querying works in a REST API fashion. It takes two arguments, `name` and `type` (eg: https://opennic.tenta.io/dns-query?name=example.com&type=A), and provides an answer in JSON format.  

We opted for a simplified JSON API approach to DoH because it removes the difficulty of including DNS queries into lightweight applications.

Our response format for DoH queries is as follows:  
**Status**: integer; analogous to classic DNS message's RCODE  
**TC**, **RD**, **RA**, **AD**, **CD**: boolean; relevant flags describing the nature of the DNS response, same as in a classic DNS message  
**Question**: structure (string, integer), describing the queried name, and the queried type  
**Answer**, **Authority**, **Additional**: array of structures (string, integer, integer, string); describing every DNS records name, type, and TTL value and their record-specific data.

An _example_ response (to the _example_ request) is
```javascript
{
  "Status":0,
  "TC":false,
  "RD":true,
  "RA":true,
  "AD":false,
  "CD":false,
  "Question":[
    {"Name":"example.com","Type":1}],
  "Answer":[
    {"Name":"example.com.","Type":1,"TTL":86400,"Data":"93.184.216.34"},
    {"Name":"example.com.","Type":46,"TTL":86400,"Data":"A 8 2 86400 20180627015845 20180606075626 4354 example.com. gpgx3XIhF4XZg5Nw0eo7TmCD1zfKX9YtMq9PuSh3eAc4fJrvyS/VWy2bz/KYhgiXQe6PvtOLZbgTT2O9knkHIlAsmnznEowSrgWYaCkkkNnoC8Ii1Ikg87PCZ7FffTposk/4HRG6yXZlo9+++YZAfAC0cc9FFYpQXqxVLf9/aDQ="}]
}
```
