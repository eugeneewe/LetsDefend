# SOC101 - Phishing Mail Detected - EventID 8

## Summary

```markdown
EventID : 8
Event Time :Aug, 29, 2020, 11:05 PM
Rule :SOC101 - Phishing Mail Detected
Level :Security Analyst
SMTP Address :63.35.133.186
Source Address :info@nexoiberica.com
Destination Address :mark@letsdefend.io
E-mail Subject :UPS Express
Device Action :Allowed
```

## Findings

> ***Parse Email***
> 
- When was it sent? Aug, 29, 2020, 11:05 PM
- What is the email's SMTP address? 63.35.133.186
- What is the sender address? info@nexoiberica.com
- What is the recipient address? mark@letsdefend.io
- Is the mail content suspicious?  Yes
- Are there any attachment? Yes

> ***Analyze Url/Attachment***
> 

[VirusTotal](https://www.virustotal.com/gui/file/0b22278ddb598d63f07eb983bcf307e0852cd3005c5bc15d4a4f26455562c8ec/detection) had flagged the attachment inside is ‘malicious’ and identified as Trojan doc. 

We can look into the malicious file code. The file first downloads a malicious file from “[http://qstride](http://qstride/)[.]com/img/0/” and then requests “67[.]68[.]210[.]95/sYRi1gXh/MT11zmUJJnEPL0yFBD/2eq2F/F9qzZD2wEYCCLpw/EJpn0u/”

AnyRun link: [https://app.any.run/tasks/f16207fe-0981-45c0-9fdb-47e71d65df7a](https://app.any.run/tasks/f16207fe-0981-45c0-9fdb-47e71d65df7a)

> ***Check if the Mail Delivered to User?***
> 

As the device action is Allowed so is considered Delivered.

> ***Check If Someone Opened the Malicios File/URL?***
> 

From the Log Management, we saw there are 2 traffics being captured by Firewall access to 67[.]68[.]210[.]95. So, is considered as Opened.

> ***Add Artifacts***
> 

14f4c470c207e22c3b0a4efa7b4200e8 - MD5 Hash

info@nexoiberica.com - email sender

nexoiberica.com - email domain

http://qstride[.]com/img/0/ - URL

67[.]68[.]210[.]95 - IP address

## Conclusion

TRUE POSITIVE, although Marks is not open the attachment, but others had open it. 
