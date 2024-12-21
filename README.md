# Zeus Banking Trojan
Detect and analyze the Zeus Banking Trojan using various tools and techniques, including malware simulation, network monitoring, memory analysis, and signature-based detection
### Zeus Trojan Overview
One of the most high-profile pieces of malware in the current threat landscape is [Zeus/Zbot](https://en.wikipedia.org/wiki/Zeus_%28malware%29), a nasty trojan that has been employed by botnet operators around the world to steal banking credentials and other personal data, participate in click-fraud schemes, and likely numerous other criminal enterprises.

Download the trojan from theZoo github repo [here](https://github.com/ytisf/theZoo/tree/master/malware/Binaries/ZeusBankingVersion_26Nov2013).

---
### Zeus Trojan Analysis Using [Virustotal](https://www.virustotal.com/gui/home)

<img src="https://github.com/user-attachments/assets/7c067471-520e-404b-850b-3f4bdcb17b46" style="height:70%;width:90%">

![image](https://github.com/user-attachments/assets/0216ac1a-1bbc-4f0f-ba97-c0d0781cd3df)

<img src="https://github.com/user-attachments/assets/4d4dc7e4-7ecc-44e4-ab62-4a71eae1e3a3" style="width:70%;height:60%;">

---
## Suricata
##### Using Suricata to monitor network traffic and use the default rules to detect common threats:
- See the video here: https://youtu.be/91Nsmrs6PYs

- Set the rules to the default on the `suricata.yaml`

![image](https://github.com/user-attachments/assets/4f5df0f4-1171-49c9-b91c-6190293b745d)

- Run Suricata

![image](https://github.com/user-attachments/assets/014cae81-ac0f-4654-96cb-b9b75593cec6)

- Logs created

![image](https://github.com/user-attachments/assets/808b7b06-d507-4b6e-933a-50f970231f98)

##### Write custom Suricata rules to detect Zeus-specific network patterns, such as C2 communication
- As the conducted analysis resulted, it detected two contacted URLs as Indicators of Compromise (IOCs), So we gonna write rules to block them.

<img src="https://github.com/user-attachments/assets/4d4dc7e4-7ecc-44e4-ab62-4a71eae1e3a3" style="width:50%;height:40%;">

- The rules we will use:
	``` txt
	alert http any any -> any any (msg:"Block Flash Player IOC - Macromedia (Warning Zeus Trojan!!!)"; flow:to_server; content:"fpdownload.macromedia.com"; http_host; classtype:bad-unknown; sid:200001; rev:2;)
	
	alert http any any -> any any (msg:"Block MaxMind GeoIP IOC (Warning Zeus Trojan!!!)"; flow:to_server; content:"j.maxmind.com"; http_host; classtype:bad-unknown; sid:200002; rev:2;)
	```

- Edit the `suricata.yaml` to add our new rules.

![image](https://github.com/user-attachments/assets/1c80bec9-4595-437e-a6dd-52768f5a0cce)

- Run Suricata

<img src="https://github.com/user-attachments/assets/ce8d50cf-6a9d-4d25-ba94-4d6e5d16fd1c">

- Logs created

<img src="https://github.com/user-attachments/assets/1c009d74-817c-420d-8292-9acc18cc1757">

## Splunk
Video: https://drive.google.com/file/d/1CanA8VcTJibNGryDi-giK6CpGPr-IES6/view?usp=drive_link

Ingesting Suricata logs and system logs into Splunk.
![Screenshot 2024-12-19 160901](https://github.com/user-attachments/assets/81a6ba5e-eb30-47fe-9456-c9e95ea254eb)

Creating correlation rules in Splunk to detect abnormal outbound traffic. We used event_type = alert, which returned 4 events.
![Screenshot 2024-12-19 161423](https://github.com/user-attachments/assets/f05e8863-ebfa-4dde-9966-7af64a110c1a)
![Screenshot 2024-12-19 192742](https://github.com/user-attachments/assets/3d08dade-b160-475c-8fae-e2e962ee0922)

Upon inspecting those 4 events, we can see "Warning Zeus Trojan - Potentially Bad Traffic" 
![Screenshot 2024-12-19 192800](https://github.com/user-attachments/assets/4060ece9-b5b7-40a1-895e-3a4f9d7547fa)

Creating visual dashboards in Splunk to track malicious activity. Here we see the times at which the alerts where generated.
![Screenshot 2024-12-19 193023](https://github.com/user-attachments/assets/af2c4e9d-dbf3-4271-b96a-db7ba0e48450)


## volatility
##### Capture a memory dump from the infected VM by using virtualboxManager.exe from "C:\Program Files\Oracle\VirtualBox" using debugvm (here the .vmem are provided so we did not do this step ) then we use volatility to Identify active , injected processes  and Analyze Zeus-related network . The following section will show the details of each step 


the steps will be here : https://github.com/Ahmed-Mahmoud-M/Zeus-Banking-Trojan-/blob/main/proactive%20project%20volatility.pdf
the video explanation steps will be here : https://drive.google.com/file/d/1lac_CNT9xceep_gzy-DdLWDcpDjFR7tL/view?usp=sharing



## YARA Rules
This part of the documentation covers the following points:
* Write custom YARA rules to detect Zeus-related patterns in binaries, configuration files, and memory dumps.
* Scan the infected system and memory dumps with YARA to identify Zeus artifacts.

Video explanation: https://drive.google.com/file/d/1tjLoOkXVbe-qzelb2oo-4ghIO1-fTnrt/view?usp=sharing

### 1. Write custom YARA rules to detect Zeus-related patterns in binaries, configuration files, and memory dumps
We found one executable file in particular and we tried to identify the trojan in it with YARA rules:
```
rule DetectZeusTrojan {
    meta:
        author = "Mohamed Moataz"
        description = "Proactive Security Project: Detecting the Zeus Banking Trojan"
    strings:
        $file_name = "invoice_2318362983713_823931342io.pdf.exe"
	$PE_header = "MZ"
        $function1_str = "CellrotoCrudUntohighCols" ascii
        $function2_hex = {43 61 6D 65 56 61 6C 65 57 61 75 6C 65 72}
    condition:
        $file_name and $PE_header at 0 and $function1_str or $function2_hex
}
```
#### Explanation:
**Strings Section:** The strings section defines the patterns to look for within the file.
- *$file_name = "invoice_2318362983713_823931342io.pdf.exe"*: Malware file name.
- *$function1_str = "CellrotoCrudUntohighCols" ascii*: After previous analyzing for the trojan, we found that this string represents a suspected function name or DLL functionality that the malware might use, defined as an ASCII string. So we use YARA to look for it so we can detect this trojan.
- *$PE_header = "MZ"*: The "MZ" string is related to the header that indicates a file is a Portable Executable. We need that because a trojan is an executable file.
- *$function2_hex = {43 61 6D 65 56 61 6C 65 72 57 61 75 6C 65 72}*: This is a hexadecimal string which represents a sequence of bytes that represent a unique function name in the Zeus banking trojan, which is "CameValeWauler".

**Condition Section:** Defines conditions for the rule to work and identify the presence of the trojan.
- *$file_name and $PE_header at 0 and $function1_str or $function2_hex*: The rule is true when the filename is the same as the one we have, the PE_header is at the file's start, and the file contains one of the 2 functions related to the trojan.
---
We also wrote another set of rules to detect the trojan from patterns in the memory dump.
```
rule ZeusBankingTrojan {
    meta:
        author = "Mohamed Moataz"
        description = "Detects Zeus Banking Trojan in memory dump"
    strings:
        $a1 = "Zeus" nocase
        $a2 = "ZeuS" nocase
        $a3 = "ihah.exe" nocase
        $a4 = "nifek_locked.exe" nocase
        $a5 = "b98679df6defbb3" nocase
        $a6 = { c1 00 00 00 00 01 00 00 ff ee ff ee 09 00 00 00}
    condition:
        any of ($a*)
}
```
      		
### 2. Scan the infected system and memory dumps with YARA to identify Zeus artifacts
Using: `yara64 zeus_rule.yara invoice_2318362983713_823931342io.pdf.exe -s -w -p 32`

![image](https://github.com/user-attachments/assets/aa949c5e-983a-49b7-9b96-b51868b8b1c3)

This command is used to detect the Zeus trojan based on unique strings in the executable file with the above yara rules.

Flags:
```
-s : Print matched strings to stdout.
-w : Ignore warnings.
-p 32 : Allocate 32 threads
```

And we also detect the trojan in the memory dump using:
`vol -f .\zeus2x4.vmem windows.vadyarascan.VadYaraScan .\zeus.yar`

![image](https://github.com/user-attachments/assets/0a67cce2-3425-4e77-a4b4-5481b49b8148)




  


  


 
 


