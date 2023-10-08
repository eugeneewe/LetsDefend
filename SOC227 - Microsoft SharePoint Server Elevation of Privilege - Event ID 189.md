# SOC227 - Microsoft SharePoint Server Elevation of Privilege - Event ID 189

## Summary

```bash
EventID : 189
Event Time : Oct, 06, 2023, 08:05 PM
Rule :  - Possible CVE-2023-29357 Exploitation
Level : Security Analyst
Hostname : MS-SharePointServer
Destination IP Address : 172.16.17.233
Source IP Address : 39.91.166.222
HTTP Request Method : GET
Requested URL : /_api/web/siteusers
User-Agent : python-requests/2.28.1
Alert Trigger Reason : This activity may be indicative of an attempt to exploit the CVE-2023-29357 vulnerability, which could potentially lead to unauthorized access and privilege escalation within the SharePoint server.
Device Action : Allowed
File (Password:infected) : [Download](https://files-ld.s3.us-east-2.amazonaws.com/static/SP-IIS.zip)
```

## Findings

> ***Understand Why the Alert Was Triggered***
> 

In order to perform a better analysis and to determine whether the triggered alert is false positive, it is first necessary to understand why the rule was triggered. Instead of starting the analysis directly, first understand why this rule was triggered.

- Examine the rule name. Rule names are usually created specifically for the attack to be detected. By examining the rule name, you can understand which attack you are facing.

As from the rule name, the attack we’re facing is **[CVE-2023-29357](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29357)**.

- Detect between which two devices the traffic is occurring. It's a good starting point to understand the situation by learning about the direction of traffic, what protocol is used between devices, etc.

First go to download the infected file, and inside it is a IIS logs. Open with notepad++. From [reference link](https://starlabs.sg/blog/2023/09-sharepoint-pre-auth-rce-chain/) we can understand that the to launch the SharePoint application authentication bypass attack, the request URL will contains one of these patterns, it will be allowed to use OAuth authentication

Look through the code, I am managed by found /_api/ only.

```prolog
95.214.53.99 - - [06/Oct/2023:20:05:06 +0000] "GET /_api/web/siteusers HTTP/1.1" 200 1453 "-" "python-requests/2.28.1"
95.214.53.99 - - [06/Oct/2023:20:05:06 +0000] "GET /_api/web/siteusers/web/siteusers HTTP/1.1" 404 1453 "-" "python-requests/2.28.1"
95.214.53.99 - - [06/Oct/2023:20:05:06 +0000] "GET /_api/web/currentuser HTTP/1.1" 200 1071 "-" "python-requests/2.28.1"
```

Protocol used between attackers and servers is HTTP GET request and both are **successful 200!!**

> ***Collect Data***
> 

Gather some information that can be gathered quickly to get a better understanding of the traffic. These can be summarized as follows.

- Ownership of the IP addresses and devices.
- If the traffic is coming from outside (Internet);
    - Ownership of IP address (Static or Pool Address? Who owns it? Is it web hosting?)
    Ownership of 95.214.53.99 ([Link](https://dnschecker.org/ip-whois-lookup.php?query=95.214.53.99)). Owned by MEVSPACE sp. z o.o.
    - Reputation of IP Address (Search in VirusTotal, AbuseIPDB, Cisco Talos)
    VirusTotal flagged 15/89 ([References](https://www.virustotal.com/gui/ip-address/95.214.53.99/detection))
    AbuseIPDB flagged 100% abuse ([References](https://www.abuseipdb.com/check/95.214.53.99))
    Cisco Talos flagged untrusted ([References](https://www.talosintelligence.com/reputation_center/lookup?search=95.214.53.99))

> ***Is Traffic Malicious***
> 

Based on the above data collect, it is considered as **Malicious**

> ***What is The Attack Type?***
> 

Other, it is the Elevation of Privilege vulnerability.

> ***Check If It Is a Planned Test***
> 

Not Planned

> ***What is the Direction of Traffic***
> 

Internet → Company Network as the `95.214.53.99` is public IP.

> ****Was the Attack Successful?****
> 

Yes, it was due to the HTTP GET request status is 200 successful.

> ***Containment***
> 

Let’s contain the server.

> ***Do You Need Tier 2 Escalation?***
> 

Yes, as the attack succeeds.

## Reference

[Microsoft SharePoint Server Elevation of Privilege Vulnerability Exploit (CVE-2023-29357)](https://socradar.io/microsoft-sharepoint-server-elevation-of-privilege-vulnerability-exploit-cve-2023-29357/)

[[P2O Vancouver 2023] SharePoint Pre-Auth RCE chain (CVE-2023–29357 & CVE-2023–24955)](https://starlabs.sg/blog/2023/09-sharepoint-pre-auth-rce-chain/)
