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
