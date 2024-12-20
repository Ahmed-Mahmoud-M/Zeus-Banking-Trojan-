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

1- List Running Processes :
	python .\volatility3\vol.py -f .\zeus2x4.vmem windows.pslist

 ![image](https://github.com/user-attachments/assets/5eff3fb1-ca10-4d9f-a1aa-8e3db9ba7578)


   	KeyObservations:
    		1.System Processes: The list includes essential system processes like System, smss.exe, csrss.exe, winlogon.exe, and lsass.exe, which are critical for Windows operation. These processes are normal in a running system.
      		2. Unusual Processes: The presence of processes like ImmunityDebugger, nifek_locked.exe, and vaelh.exe suggests that there may be debugging or potentially malicious activity.
		3.Processes with Suspicious Names: Specifically, processes like b98679df6defbb3, ihah.exe, and nifek_locked.exe have non-standard names, which could indicate hidden or malicious processes.


  2- Detect hidden processes:
  		 python .\volatility3\vol.py -f .\zeus2x4.vmem windows.psxview

![image](https://github.com/user-attachments/assets/3198c230-e693-44b1-a9d4-bf485b61df1a)


	keyObservation: Some processes, such as ImmunityDebugger, prl_cc.exe, and svchost.exe, are flagged as False in pslist or psscan. This suggests they are potentially hidden or masked from normal process listing mechanisms.

     

      

  3- Check for injected Processes:
  		python .\volatility3\vol.py -f .\zeus2x4.vmem windows.malfind 
    
![image](https://github.com/user-attachments/assets/b9dc494f-ab22-4acc-9ae4-6f066925ba1b)


		KeyObservations :
  			1.Suspicious Pages Found: Highlight that the output shows processes with suspicious memory regions marked as PAGE_EXECUTE_READ, which is often associated with potential malicious code or rootkits.
     			2.Several system processes (e.g., csrss.exe, winlogon.exe, svchost.exe, etc.) have been flagged with suspicious memory regions.
			3. These hex values (e.g,. c1 00 00 00 00 01...) show potentially injected shellcode or malicious content.



  4-Analyze Zeus-related Network Connections :

  	python volatility.py -f memorydump.raw --profile=Win7SP1x64 netscan


  5- Use filescan to locate files related to Zeus:
  ![image](https://github.com/user-attachments/assets/37dbbd94-c152-4ed9-aadf-033b101efa88)
  The output shows a list of files loaded into memory, including standard system files like tcpip6.sys, oleaut32.dll, and ntdll.dll

  6-Check Registry Keys for Zeus persistence:
  ![image](https://github.com/user-attachments/assets/1c6a043a-d49b-4806-a0ef-364e637fb0e7)

these registry keys are located within the NTUSER.DAT hive for the Administrator user and represent persistent, non-volatile settings. The last write time for the keys suggests that user-specific settings were modified regularly between 2009 and 2010. There are no volatile keys, indicating that the settings are retained across reboots. The Environment, Identities, and Keyboard Layout keys could contain additional useful information for forensic investigation, such as environment variables or user credentials.

## YARA Rules
This part of the documentation covers the following points:
* Write custom YARA rules to detect Zeus-related patterns in binaries, configuration files, and memory dumps.
* Scan the infected system and memory dumps with YARA to identify Zeus artifacts.

### 1. Write custom YARA rules to detect Zeus-related patterns in binaries, configuration files, and memory dumps
We found one binary file in particular can identify the YARA rules:
```
rule DetectZeusTrojan {
    meta:
        Author = "Mohamed Moataz"
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
      		
### 2. Scan the infected system and memory dumps with YARA to identify Zeus artifacts
Using: `yara64 zeus_rule.yara invoice_2318362983713_823931342io.pdf.exe -s -w -p 32`

![image](https://github.com/user-attachments/assets/aa949c5e-983a-49b7-9b96-b51868b8b1c3)

This command is used to detect the Zeus trojan based on unique strings with the above yara rules.

Flags:
```
-s : Print matched strings to stdout.
-w : Ignore warnings.
-p 32 : Allocate 32 threads
```
    		
  	



  


  


 
 


