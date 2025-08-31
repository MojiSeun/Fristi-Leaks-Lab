# Fristi-Leaks-Lab

Objective

The FrisitLeaks is a small virtual machine designed with web vulnerabilities to be detected by the penetration testers. The goal of this excercise was to identify the vulnerabilities on the server, exploit the vulnerabilities to access the root id, capture the flag stored in the root directory.

Skills Learned
- Vulnerability assessment using Nmap and Gobuster
- Remote code Execution via the upload of PHP scripts
- Privilege Escalatio techniqe in order to gain unauthenticated access.
- Problem solving and critical thinking in finding and exploitng vulnerabilites.
- Directory bruteforcing.
- Documentation and reporting of vulnerabilites along with mitigation strategies.

Tools Used
- Nmap: Vulnerability analysis tool.
- Gobuster - Directory bruteforcing tool
- Whatweb - Web Enumeration tool
- VmWare workstation - virtual machine environment
- Kali Linux - Os used to carry out attacks and hosted on vmware.

Steps
- Step 1: Install and configure Fristileaks virtual machine.
The  compressed target VM file was downloaded from the vulnhub platform, after the file was extracted and added to the VMware workstation as a virtual machine.

 <img width="480" height="270" alt="Screenshot (47)" src="https://github.com/user-attachments/assets/aa72ab35-2f37-4530-88a4-5d18a4267b5b" />

- Step 2:  Vulnerability assessment.
The target machine was scanned using nmap, were the IP address of the machine was specified along with option -sV. The -sV directs nmap to check for the version of the current services run on any open port found. The purpose of this scan is to identify any open port and oudated service on the open port that can be exploited in order to get a foothold on the target machine. From the conducted scan, the port 80 was found open with apache web server running on it this signifies web application service running on the server to which can be exploited.

<img width="480" height="270" alt="Screenshot (35)" src="https://github.com/user-attachments/assets/df05425b-8568-4d5b-98df-0e3f3f98347b" />

For more investigation a directory brute force test was conducted via Gobuster, the tool uses a list of possible directory names and traverses through them in order to obtain possible web directories that can be accessed In order to find more vulnerabilities.

<img width="480" height="270" alt="Screenshot (28)" src="https://github.com/user-attachments/assets/6d46e2c4-77f1-4d03-89bb-76e87e7b70fc" />

From the scan three accessible directories where found, /robots.txt, /fristi, /index.html. Normally, the /robots.txt file carries sensitive information that can be used to exploit hence upon checking this, three users were found which were /bola, /sisi, /cola but unfortunately there was nothing intrested found after navigating to these users directories. The next approach was to navigate to the /fristi directory. After navigating to this directory a login page was found. after trying possible passwords lie admin:admin it was found to be inactive hence the next approach was to check the source code of the login page for any clues. From the source code two potential clues were obtained a username "eezeepz" and an md5 hash base64 encoded text. 

<img width="480" height="270" alt="Screenshot (30)" src="https://github.com/user-attachments/assets/625465c3-e338-4cbd-8226-06e33d56cbbd" />
<img width="480" height="270" alt="Screenshot (29)" src="https://github.com/user-attachments/assets/678841e7-78b4-4aa9-b689-148c17b3b331" />
<img width="480" height="270" alt="Screenshot (31)" src="https://github.com/user-attachments/assets/b4df5b9e-8725-4077-ae36-057390b0acbb" />

After decodeing the base64 encoded png image I found a text "keKkeKKeKKeKkEkkEk" indicating this could be a possible password. Now the next stage was to try potentially obtained credentials eezeepz:keKkeKKeKKeKkEkkEk. Attempting this login credential led to a successful login.

<img width="480" height="270" alt="Screenshot (32)" src="https://github.com/user-attachments/assets/5936347e-c40f-485d-bce0-e2b64e2b8234" />
<img width="480" height="270" alt="Screenshot (33)" src="https://github.com/user-attachments/assets/547d05fe-83f6-4ac6-8208-b9f31e548f1e" />

- Step 3: Exploitation - Gaining foothold of the machine.






 
 



Ref 1: Network Diagram
