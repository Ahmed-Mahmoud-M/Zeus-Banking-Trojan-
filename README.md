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

  6-Check Registry Keys for Zeus persistence:
  ![image](https://github.com/user-attachments/assets/1c6a043a-d49b-4806-a0ef-364e637fb0e7)



	



   

      		


    		
  	



  


  


 
 


