## Security considerations

Please consider checking the list of known issues before using picoTCP in production.


## Known issues

### Version 2.1

Vulnerabilities that can be found in picoTCP-NG v.2.1:

* ❗ Improper bound checking against the parsing of domain names may result in remote code execution (CVE-2020-24338)
  * Triaged. Awaiting assignment.

* ❗ Improper bound checking against the parsing of domain names may result in a denial of service (CVE-2020-24339)
  * Triaged. Awaiting assignment.

* ❗ Improper checks in the process of DNS response handling which may lead to memory corruption (CVE-2020-24340)
  * Triaged. Awaiting assignment.

Vulnerabilities fixed in this version:

* Improper checks against the payload length field of IPv6 extension headers which may lead to an information leak or denial of service (CVE-2020-17441)
  *  **Fixed in v2.1** :heavy_check_mark:

* Improper checks against the length of the Hop-by-Hop extension header may result in an infinite loop which leads to a denial of service (CVE-2020-17442)
  *  **Fixed in v2.1** :heavy_check_mark:

* Improper checks against ICMPv6 headers when processing ICMPv6 echo requests may lead to a denial of service (CVE-2020-17443)
  *  **Fixed in v2.1** :heavy_check_mark:

* Improper checks against the lengths of extension header options when processing IPv6 headers may result into a denial of service (CVE-2020-17444)
  *  **Fixed in v2.1** :heavy_check_mark:

* Improper checks against options lengths when processing the IPv6 Destination Options extension header may result in a denial of service (CVE-2020-17445)
  *  **Fixed in v2.1** :heavy_check_mark:

* Improper length validation of TCP options in IPv4 may results in a denial of service (CVE-2020-24337)
  *  **Fixed in v2.1** :heavy_check_mark:

* Improper checks against the length of incoming TCP packets may enable an out-of-bound read and/or memory corruption (CVE-2020-24341)
  *  **Fixed in v2.1** :heavy_check_mark:

