# SOC101 - Phishing Mail Detected - Event ID 59

## Summary

```bash
EventID :59
Event Time :Feb, 14, 2021, 03:00 AM
Rule :SOC101 - Phishing Mail Detected
Level :Security Analyst
SMTP Address :27.128.173.81
Source Address :hahaha@ihackedyourcomputer.com
Destination Address :mark@letsdefend.io
E-mail Subject :I hacked your computer
Device Action :Blocked
```

## Findings

> ***Parse Email***
> 
- When was it sent? Feb, 14, 2021, 03:00 AM
- What is the email's SMTP address? 27.128.173.81
- What is the sender address? hahaha@ihackedyourcomputer.com
- What is the recipient address? mark@letsdefend.io
- Is the mail content suspicious? Yes
- Are there any attachment? No

> ***Are there attachments or URLs in the email?***
> 

No

> ***Add Artifacts***
> 

27.128.173.81 IP Address

 hahaha@ihackedyourcomputer.com Email Sender

[ihackedyourcomputer.com](http://ihackedyourcomputer.com) Email domain

> ***Conclusion***
> 

TRUE POSITIVE, scam email but get blocked by email security.
