# Email Analysis - LetsDefend Challenge

### Summary

You recently received an email from someone trying to impersonate a company, your job is to analyze the email to see if it is suspicious.

**Email Link:** [Download](https://letsdefend-images.s3.us-east-2.amazonaws.com/Challenge/Email-Analysis/BusinessEmail.zip)

**Password:** infected

**Attachment:** [Download](https://letsdefend-images.s3.us-east-2.amazonaws.com/Challenge/Email-Analysis/united+scientific+equipent.zip)

**Password:** infected

This challenge prepared by [ZaadoOfc](https://www.linkedin.com/in/zaid-shah-05527a22b/)

### Questions

1. What is the sending email address?
2. What is the email address of the recipient?
3. What is the subject line of the email?
4. What date was the Email sent? Date format: MM/DD/YYYY
5. What is the originating IP?
6. What country is the IP address from?
7. What is the name of the attachment when you unzip it? (with extension)
8. What is the sha256 hash of the File?
9. Is the email attachment malicious? Yes/No

### Findings

1. First download the email file and attachment from the link provided.
2. Two file is being extracted “BusinessEmail.eml” and “united scientific equipent.exe”. 
You may answer question no 7.
3. Use Subline Security EML analyzer to read the BusinessEmail.eml header. Now you can answer question No 1-5. [Sublime Security](https://analyzer.sublime.security/)
4. Ques no 6 is to find out what is the country of that IP address from use the IP Lookup. We can use DNSChecker online tools to solve it. [IP Address Lookup - Instantly Locate Your Public IP](https://dnschecker.org/ip-location.php?ip=71.19.248.52)
5. To find out the sha256 hash of the file and is the email attachment malicious, we can use [VirusTotal](http://virustotal.com) to capture the information. Now you can answer question no 7-8.
