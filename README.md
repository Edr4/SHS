# SCIENCE, HACKING AND SECURITY

+400 pages of personal notes on cybersecurity, hacking

Autor :  Comores11
Contribution : Edra

-   [Google Doc]()
-   [PDF]()
-   [HTML]()
-   [Markdown]() 


**1) Linux commands**
-	list
-	Nmap commands
-	
**2)	About PHP	**
-	PHP - Difference between ‘ and “
-	PHP - Path and dot truncation
-	PHP - Loose comparaison
-	PHP - preg_replace exploit
-	Cookies vs. sessions ( no PHP )
-	
**3)	Iptables**

**4)	Network**
TCP header FLag
-	Modèle TCP/IP
-	Certificat et PKI
-	Protocole TLS ( Transport Layer Security ) / SSL ( Secure Sockets Layer )
-	Port Knocking
-	Network File System (NFS)

**5)	Web**
-	(Se/Deser)-ialisation
Some tools
-	Identify insecure deserialization
-	Magic methods
-	Gadget Chains
-	JWT (JSON Web Token
-	SQL injection
-	étapes dans une SQLi Union
-	Potentielles étapes pour une BSQLi
-	Exemples de payloads
-	LDAP injection
-	MongoDB injection
-	SQL Truncation
-	Open Redirect
Some payload
-	LFI/RFI
Some payloads
RCE via Log poisoning
RCE via Proc Environ Injection
RCE via SSH Log Poisoning
RCE via SMTP Log Poisoning
-	How to Detect
-	XML external entity (XXE) injection
-	XSS ( Cross-site scripting )
Interesting payload
-	Dangling markup injection
-	Definiton
Interesting payload
-	DOM XSS
-	Cross-Site WebSocket Hijacking
-	Definition
-	Exploitation
-	Authentication
-	Server-side request forgery (SSRF)
-	finding vuln
Useful payloads
-	Os command injection
Some payload
-	Cross-site request forgery (CSRF)
-	Definiton
-	Preventing
-	Exploit techniques
-	Business logic vulnerabilities
-	Directory traversal
Some interesting payloads
-	Web cache poisoning	
-	Access Control	
-	Cross-origin resource sharing (CORS)	
-	Definition	
-	Exploit	
-	Server-side template injection	
-	Définition	
-	Detect	
-	Identify	
-	Explore	
-	Preventing	
-	HTTP Parameter Pollution	
Différents Entêtes HTTP	
-	MIME sniffing	
-	Exploiting PUT Method	
-	With Cadaver	
-	With Nmap	
-	With Burp-Suite	
-	Finding PUT Method vuln	
-	HTTP Host header attacks	
-	Definition	
-	Prévention	
Test HTTP Host header attack :	
-	Password reset poisoning :	
-	HTTP request smuggling	
-	Definition	
-	CL.TE vuln	
-	TE.CL vuln	
-	TE.TE vuln	
-	Prevention	
-	Finding CL.TE vuln	
-	Finding TE.CL vuln	
-	IDOR ( Insecure Direct object Reference )	
-	OAuth 2.0 authentication vulnerabilities	
What is OAuth ?
How does OAuth 2.0 Work ?	
-	How do OAuth authentication vulnerabilities arise?	
-	SAML	
-	Definiton	
Some Vulnerability :	
-	Injection de commentaire XML :
-	Phar://	
-	Different file extensions	
-	JS prototype Pollution :	
-	Règle et de bonnes pratiques :	
-	Session Management :	
-	Cookies Management :	
-	AJAX Management :	
-	Authentication Management :	
-	Credential Stuffing Prevention	
CSRF (Cross-Site Request Forgery Prevention)	
-	XSS	
Résumé :	
Cryptographic Storage	
Database Security	
Php configuration	
Unvalidated Redirects and Forwards	
File Uploads	
-	Password Storage	
-	MISC	
MISC checklist

**7)	Javascript security	**
-	CDN in JS:	
Description	
Impact	
-	Incorrect Referrer Policy :
-		
**8)	ClickJacking**
-	prevention	228
-	
**9)	Linux**
-	/etc/passwd file :	
Some Environment variables in Linux:	
-	Fonctionnement de la HEAP ( glibc heap ):	
-	Some basic HEAP rules:	
Spécification :	
Some important file in Linux system	
-	SMB Penetration Testing (Port 445)	
Phishing tools	
File System in Linux	
-	Shell restreint	
/etc/shadow file fields	
-	Système de volume logique de linux	
Shared Library Hijacking :	
MISC	

**10)	Linux Hardening Rules**

**11)	PWN - Exploit mistakes in programming and execution	**
-	Memory leak	
-	Exploits de type “format strings”:	
-	L’ASLR	
Définition	
-	Bypass ASRL :	
-	SSP ( stack smashing protector )	54
-	RELRO	
-	Use-After-Free :	
-	Return-to-libc :	
-	ROP - Return Oriented Programming	
Double free :	
-	The House of Force attack	
Code execution techniques :	
-	The Fastbin dups ( duplication ) attack	
MISC	

**12)	Gdb command**

**13)	ARM**
-	Differents instructions	
CPSR	
condition codes :	
MISC	

**14)	Assembleur x86**
MISC	

**15)	Stéganographie**
Steganography tools	
Some useful commands	

**16)	Cryptographie**
Cryptography tools	
Useful Commands	
Catégorisation d'algorithmes cryptographique	
Taille de différents Hash :	
-	Man In The Middle291
-	RSA :	
Intro :	
-	Déroulement de l’algorithme :	
-	Attacking RSA keys	
-	Modulus too small ( n )	
-	Low private exponent ( d )	
-	Bit-flipping attack	
-	CBC-MAC :	
-	Mode opératoire CTR :	
-	Mode opératoire ECB :	
-	Diffie-Hellman	
intro :	
-	Fonctionnement de Diffie-Hellman :	
DH avec courbe elliptique :	
-	AES ( Advanced Encryption Standard )	
-	PKCS#5 and PKCS#7 padding :	
-	Perfect Forward Secrecy ( PFS ):	
Hash length attack extension	
Liste d’Algo de générateur de nombres pseudo-aléatoires	
-	ECDSA ("Elliptic Curve Digital Signature Algorithm")	
Algorithme RC4 :	
EDDSA	
DES	
An Initialization Vector (IV)	
-	Padding oracle attacks :	
-	Définition :	
Prévention	
-	GCM ( Galois Counter Mode )	
-	Le Salt	
MISC	

**17)	Forensic**	
Some tools and command	
-	Volatility	
Some Volatility command and plugin	
-	Les Rootkit :	
-	MISC	

**18)	Linux Privilege Escalation**
System enumeration command :	
-	Kernel exploitation :	
-	Passwords & File Permissions exploitation :	
-	Sudo exploitation :	
-	LD_PRELOAD :	
-	SUID Exploitation	
-	Shared Object Injection :
-	VIA Environment Variables :	
-	Exploiting SUID permission in cpulimit command :	
-	RCE through mysql command on a writeable directory :	
-	Lxd Privilege Escalation	
-	Python Library Hijacking	
Method 1 : From Bad Write Permission	
Method 2 : Priority Order	
Method 3 : PYTHONPATH Environment Variable

**20)	Format ELF**
Section in ELF	
Environnement d'exécution :

**21)	Python**
-	MISC
-	
**22)	OSINT**
Useful tools	

**23)	Metasploit**
-	Autoroute exploit :	
-	Ping sweep :
-	auxiliary tcp port scanner :
-		
**24)	GraphQL**
-	Definiton
-	Common GraphQL endpoint :
-	GraphQL injection :	
-	Useful Introspection query	
-	MISC
-	
**25)	Bash**	
-	MISC	
-	
**26)	Ruby-On-Rails**
-	MISC	
-	
**27)	PowerShell**
-	Definition
-	
**28)	Others**	
-	Recovering saved macOS user passwords	
-	Mass assignment	
Tunneling with Chisel :	

**29)	Active Directory**

**30)	DNS**
Différents Commands
-	DNSSEC
-	MISC	

**31)	Android**
Tools	
-	Decompile APK
-	AndroidManifest.xml :
-	Root détection :	
-	Bypass root detection :	
-	Android Activity lifecycle :	
-	Rooting and Jailbreaking :
-	Signing mobile application :	
MISC	

**32)	IOS**
Tools	
-	MISC	

**33)	Reverse**
-	Techniques d’anti-reverse :	
- Polymorphisme et métamorphisme	
- Packer	
- Anti-virtualisation et anti-émulation	

**34)	Container Security**	
-	Definition	
- Some Commands	
-	Registre Docker	
-	Docker Compose	
-	Dockerfile	
- Container Breakouts :	
-	Misc

**35)	S3 (Simple Storage Service) AWS (Amazon Web Services)**
-	Définition	
-	S3 Buckets	
-	ACL ( Access control list )	

**36)	Smart Contract**	

**37)	Windows in general**
Commands	
-	NT hash	
-	Hiberfill.sys file	
-	DLL Hijacking definiton	
DLL Hijacking techniques	
-	UAC Bypass definiton	
UAC bypass techniques	
-	Process migration :	
-	Misc	

**38)	Wifi**	
Tools	
-	SSID	
-	WLAN	
-	WPA PSK	
-	WPA ou WPA2	
-	WPA-Personal vs WPA-Entreprise	
-	WPA/WPA2 MGT	
-	Protocole WPS	
-	AP ( Access Point )	
-	BSSID	
-	BSS	
-	Password Cracking ( WPA/WPA2 BForcing )	
Steps :	

**39)	DevOps / DevOpsSec**
-	Définition	
Etape Dev et Ops :	 	
Version Control System :	
Testing :	
Intégration Continue :	
Infrastructure as Code	

**40)	Audit en boîte blanche**
Code Review : Strategies :	
Code Review : Reviewing :	
-	Méthode 1	 

**41)	Bug bounty Tips**
-	BB - Recon (file, url, subdomains):	
-	BB - CSRF Bypass protection :	
-	BB - OAuth :	
-	BB - SAML  :	
-	BB - Bypassing 403 and 401 error :
-	BB : File upload :	
-	BB : Broken access control :	
-	BB - XSS  :	
-	BB - SSRF  :	
-	BB - Login/password form  :	
-	BB - CORS :	
-	BB - Web Cache Poisoning :	
-	BB - HTTP response header injection :	
-	BB - HTTP Host header attacks :	
-	BB - API :	
-	BB - Information Disclosure/gathering :	
-	BB - Business logic vulnerabilities :	
-	BB - GraphQL :	
-	BB - APK :	
-	Non technique, normes, ...	
PCI DSS	
-	Secure PHP Software Guideline	
-	Dependency Management	
-	Recommended Packages	
Subresource Integrity	
Document Relationships	
Database Interaction	
File Uploads	
-	Security Web Testing Guide	
Information Gathering	
-	General	
-	Shodan	
Configuration and Deployment Management Testing	
-	Review each version (if possible) of each element related to the server web (DB, proxy, …)	
Client-side Testing	
-	DOM XSS	
-	Test automatique :	
-	FindomXSS :	
-	DOM based XSS Finder (extension CHROME) (FUZZ)	
-	DOM Invader (en ouvrant le navigateur depuis BURP)	
-	XSStrike (FUZZ)	
-	Test manuel :	
API Testing	
-	GraphQL	
Testing Browser Storage	
Testing Web Messaging	450
Testing for Cross Site Script Inclusion	
Testing for Host Header Injection	
Testing for SQLi	

**42 ) Search Engine**

