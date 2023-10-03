# Infection with Cobalt Strike - LetsDefend Challenge

[Getting Started to LetsDefend](https://app.letsdefend.io/challenge/infection-cobalt-strike)

## Summary

We got network traffic from password stealer. You should do root cause analysis.

PCAP File (pass:321): [Download](https://files-ld.s3.us-east-2.amazonaws.com/5H42K.zip)

This challenge prepared by [@Bohan Zhang](https://www.linkedin.com/in/bohan-zhang-078751137/)

PCAP Source: [malware-traffic-analysis](https://www.malware-traffic-analysis.net/)

## Question

1. Investigate the PCAP file, what is one of the popular documents signing services used by the attacker to deliver the malware?
2. Investigate the PCAP file, what is the full URL used by the attacker to create the malicious document?
3. On the malicious website from the previous question, what kind of encoding technique used by the attacker to create the malicious document?
4. What is the name of the malicious document opened by the user?
5. What malware family this malicious file belongs to?
6. After the user interacts with the malicious file, it runs malicious DLL on the system. What is the DLL run command?
7. What is the C2 URL?
8. What is the URL that serves the payload?
9. What is the name of the malware this payload links back to?
10. What is the popular hacking framework being used in this campaign?
11. What is the popular storage service used by the attacker to deliver the malware?

## Findings

1. Let's download the PCAP file and open with NetworkMiner. 
2. ‘*Investigate the PCAP file, what is one of the popular documents signing services used by the attacker to deliver the malware?’* Tons of the network traffic being found from the PCAP file, but we could found there is only one documents signing services found where it is well recognized “Docusign”
3. Inside the PCAP file there is alot of HTTPS connection with the “.cer” files where we can filter out the “.cer” files so we can concentrate on more important files. We can exclude the “.cer” files on the “file” tab by putting `^((?!cer).)*$` in the search box and change the filter options to “RegEx” and “Extension.”
4. As for the outcome of the exclude “.cer” we can start looking into ***swellheaded.php.html*** and ***swellheaded.php[1].html*** from ***107.180.41.251 (ecofiltroform.triciclogo.com).*** We can check the code of these .php.html source code file under “**`/opt/NetworkMiner_2-8-1/AssembledFiles/107.180.41.251/TCP-80/swellheaded.php.html`**” (I am using NetworkMiner on debian-based OS).
    **`swellheaded.php.html`** looks nothing but only sets a cookie and reloads the same webpage with the new cookie. With the cookies sets, a different reply occurs from the webpage redirect to ********************************************`**swellheaded.php[1].html**`******************************************** 
    ********************************************`**swellheaded.php[1].html**`******************************************** in the line 24, we saw there is a function() with atob() functions which is used to decodes a string of data which has been encoded using Base64 encoding and bottom of those encoded code, we can see it will be `saveAs(blob1, ‘0524_4109399728218.doc’);` function. Where from this part we can ensure that the PHP script is malicious. Above information will helps to solve question no 3 and 4.
    **References:** [atob() global function - Web APIs | MDN (mozilla.org)](https://developer.mozilla.org/en-US/docs/Web/API/atob) 
5. “*Investigate the PCAP file, what is the full URL used by the attacker to create the malicious document?*” As we know that **`swellheaded.php.html`** is malicious, but we need to find out what is the exact URL that users download it. Therefore “WireShark” software is required to be used in this scenario to open the .pcap file for detailed of network packet. In the WireShark filter, based on the ***107.180.41.251 (ecofiltroform.triciclogo.com)*** we will filter into the WireShark using `ip.addr == 107.180.41.251` then follow the TCP stream.
    From the TCP stream information, we can see that it is using gzip for GET HTTP method and the ‘**Referer:’** shows the answer of *full URL used by attacker to create the malicious document*.
    
6. Next, we are decrypt the base64encoded blob using CyberChef. Let’s copy the content of `atob(’{blob}’)` and decode it with “From Base64” recipe. Output of the decoded blob is unable to understand but remember there is a code on steps 4 showing `saveAs(blob1, ‘0524_4109399728218.doc’);` it will be saving into `0524_4109399728218.doc`. In order to verify the code is compatible with doc file, lets use ‘Detect File Type’ recipe in the CyberChef to find out what is it.
    ```html
    File type:   Microsoft Office document/OLE2
    Extension:   ole2,doc,xls,dot,ppt,xla,ppa,pps,pot,msi,sdw,db,vsd,msg
    MIME type:   application/msword,application/vnd.ms-excel,application/vnd.ms-powerpoint
    Description: Microsoft Office documents
    ```
    As for the above CyberChef detection, it is verified file type is Microsoft Office document. Now we can save the output of the decoded blob into ‘*0524_4109399728218.doc*’ and upload it into VirusTotal. [Results](https://www.virustotal.com/gui/file/0b22278ddb598d63f07eb983bcf307e0852cd3005c5bc15d4a4f26455562c8ec/)
7. ‘*What malware family this malicious file belongs to?*’ VirusTotal had confirmed that the .doc file is malicious and Microsoft have the answer for this malware family. 
8. “*After the user interacts with the malicious file, it runs malicious DLL on the system. What is the DLL run command?*” To extract the command, we can use [Any.Run](http://Any.Run) to simulate the scenario again ([Any.run Report](https://app.any.run/tasks/fdace2a7-278f-458b-bd7b-844f9d380c56)). Rundll32.exe command will help you answer the questions.
9. “*What is the C2 URL?*” We can look into VirusTotal > Community > Joe Sandbox Analysis ([HTML Report](https://www.joesandbox.com/analysis/854354/0/html)). Under ‘Malware Configuration > C2 list” you will get the answer of C2 URL. 
10. ‘*What is the URL that serves the payload?*’ Now we found the C2 URL from the previous findings in step 9 and we will further investigate what happen after `**forum.php.html**` 
    It shows that after `**forum.php.html**` it downloads 3 files (***24.bin, 24s.bin and 6hjusfd8.exe***) from `8.211.5.232 (gromber6.ru)`. Let’s try upload the 3 items into VirusTotal and check its [Result](https://www.virustotal.com/gui/file/94e60de577c84625da69f785ffe7e24c889bfa6923dc7b017c21e8a313e4e8e1). “***6hjusfd8.exe”*** files identified by VirusTotal is malicious so it should be the payload. To capture the exact URL, we can use WireShark and filter with `ip.addr == 8.211.5.232` and follow TCP stream. 
11. “*What is the name of the malware this payload links back to?*” We found from the “VirusTotal > Community” comments, it is the “Hancitor | Cobalt Strike | Ficker Stealer | Sendsafe spambot”. So, the malware name of this payload should be “Ficker Stealer”
12. “*What is the popular hacking framework being used in this campaign?*” When we’re findings the malware name it does mention Cobalt Strike, somemore the Topic of the LetsDefend Challenge mentioned it, so it is the answer.
13. “*What is the popular storage service used by the attacker to deliver the malware?*” We can go to “NetworkMiner > DNS” and filter keyword `google` and the results of overall ‘docs.google.com’ is more making sense to the “*popular storage service*”.
