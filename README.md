# SCIENCE, HACKING AND SECURITY

+400 pages of personal notes on cybersecurity, hacking

Autor :  Comores11
Contribution : Edra

-   [Google Doc]()
-   [PDF]()
-   [HTML]()
-   [Markdown]() 



-	list	13
-	Nmap commands	27
2)	About PHP	28
-	PHP - Difference between ‘ and “:	28
-	PHP - Path and dot truncation :	28
-	PHP - Loose comparaison :	28
-	PHP - preg_replace exploit :	29
-	Cookies vs. sessions ( no PHP ) :	29
3)	Iptables	30
4)	Network	39
TCP header FLag	39
-	Modèle TCP/IP :	44
-	Certificat et PKI:	45
-	Protocole TLS ( Transport Layer Security ) / SSL ( Secure Sockets Layer ) :	49
-	Port Knocking	72
-	Network File System (NFS)	73
5)	Web	73
-	(Se/Deser)-ialisation	73
Some tools	73
-	Identify insecure deserialization :	73
-	Magic methods	75
-	Gadget Chains :	75
-	JWT (JSON Web Token)	76
-	SQL injection :	78
-	étapes dans une SQLi Union :	78
-	Potentielles étapes pour une BSQLi :	78
-	Exemples de payloads	78
-	LDAP injection	83
-	MongoDB injection	84
-	SQL Truncation :	86
-	Open Redirect	86
Some payload	86
-	LFI/RFI :	87
Some payloads	87
RCE via Log poisoning	88
RCE via Proc Environ Injection	88
RCE via SSH Log Poisoning	89
RCE via SMTP Log Poisoning	89
-	How to Detect	90
-	XML external entity (XXE) injection	91
-	XSS ( Cross-site scripting ) :	100
Interesting payload	101
-	Dangling markup injection :	105
-	Definiton	105
Interesting payloads	108
-	DOM XSS :	111
-	Cross-Site WebSocket Hijacking	114
-	Definition	114
-	Exploitation	114
-	Authentication :	120
-	Server-side request forgery (SSRF)	123
-	finding vuln	124
Useful payloads	124
-	Os command injection	126
Some payload	127
-	Cross-site request forgery (CSRF)	127
-	Definiton	127
-	Preventing	128
-	Exploit techniques	130
-	Business logic vulnerabilities	133
-	Directory traversal	133
Some interesting payloads	133
-	Web cache poisoning	135
-	Access Control	136
-	Cross-origin resource sharing (CORS)	136
-	Definition	136
-	Exploit	139
-	Server-side template injection	139
-	Définition	139
-	Detect	141
-	Identify	143
-	Explore	144
-	Preventing	145
-	HTTP Parameter Pollution	145
Différents Entêtes HTTP	146
-	MIME sniffing	148
-	Exploiting PUT Method	148
-	With Cadaver	150
-	With Nmap	150
-	With Burp-Suite	151
-	Finding PUT Method vuln	153
-	HTTP Host header attacks	153
-	Definition	153
-	Prévention	156
Test HTTP Host header attack :	156
-	Password reset poisoning :	159
-	HTTP request smuggling	161
-	Definition	161
-	CL.TE vuln	165
-	TE.CL vuln	165
-	TE.TE vuln	166
-	Prevention	166
-	Finding CL.TE vuln	167
-	Finding TE.CL vuln	168
-	IDOR ( Insecure Direct object Reference )	169
-	OAuth 2.0 authentication vulnerabilities	169
What is OAuth ?	169
How does OAuth 2.0 Work ?	170
-	How do OAuth authentication vulnerabilities arise?	178
-	SAML	181
-	Definiton	181
Some Vulnerability :	183
-	Injection de commentaire XML :	183
-	Phar://	184
-	Different file extensions	185
-	JS prototype Pollution :	185
-	Règle et de bonnes pratiques :	187
-	Session Management :	187
-	Cookies Management :	188
-	AJAX Management :	190
-	Authentication Management :	191
-	Credential Stuffing Prevention	194
CSRF (Cross-Site Request Forgery Prevention)	195
-	XSS	197
Résumé :	200
Cryptographic Storage	200
Database Security	206
Php configuration	208
Unvalidated Redirects and Forwards	208
File Uploads	210
-	Password Storage	214
-	MISC	216
MISC checklist	216
7)	Javascript security	225
-	CDN in JS:	225
Description	225
Impact	226
-	Incorrect Referrer Policy :	226
8)	ClickJacking	228
-	prevention	228
9)	Linux	228
-	/etc/passwd file :	229
Some Environment variables in Linux:	230
-	Fonctionnement de la HEAP ( glibc heap ):	230
-	Some basic HEAP rules:	230
Spécification :	231
Some important file in Linux system	232
-	SMB Penetration Testing (Port 445)	232
Phishing tools	234
File System in Linux	234
-	Shell restreint	238
/etc/shadow file fields	243
-	Système de volume logique de linux	243
Shared Library Hijacking :	244
MISC	246
10)	Linux Hardening Rules	249
11)	PWN - Exploit mistakes in programming and execution	250
-	Memory leak	250
-	Exploits de type “format strings”:	250
-	L’ASLR	252
Définition	252
-	Bypass ASRL :	253
-	SSP ( stack smashing protector )	254
-	RELRO	254
-	Use-After-Free :	255
-	Return-to-libc :	255
-	ROP - Return Oriented Programming	256
Double free :	258
-	The House of Force attack	262
Code execution techniques :	263
-	The Fastbin dups ( duplication ) attack	264
MISC	267
12)	Gdb command	269
13)	ARM	272
-	Differents instructions	272
CPSR	274
condition codes :	276
MISC	277
14)	Assembleur x86	277
MISC	286
15)	Stéganographie	286
Steganography tools	287
Some useful commands	288
16)	Cryptographie	289
Cryptography tools	289
Useful Commands	289
Catégorisation d'algorithmes cryptographique	290
Taille de différents Hash :	291
-	Man In The Middle	291
-	RSA :	292
Intro :	292
-	Déroulement de l’algorithme :	293
-	Attacking RSA keys	295
-	Modulus too small ( n )	295
-	Low private exponent ( d )	295
-	Bit-flipping attack	298
-	CBC-MAC :	299
-	Mode opératoire CTR :	301
-	Mode opératoire ECB :	302
-	Diffie-Hellman	303
intro :	303
-	Fonctionnement de Diffie-Hellman :	304
DH avec courbe elliptique :	306
-	AES ( Advanced Encryption Standard )	309
-	PKCS#5 and PKCS#7 padding :	313
-	Perfect Forward Secrecy ( PFS ):	313
Hash length attack extension	314
Liste d’Algo de générateur de nombres pseudo-aléatoires	315
-	ECDSA ("Elliptic Curve Digital Signature Algorithm")	316
Algorithme RC4 :	318
EDDSA	318
DES	319
An Initialization Vector (IV)	319
-	Padding oracle attacks :	321
-	Définition :	321
Prévention	322
-	GCM ( Galois Counter Mode )	323
-	Le Salt	323
MISC	324
17)	Forensic	327
Some tools and command	327
-	Volatility	327
Some Volatility command and plugin	328
-	Les Rootkit :	334
-	MISC	335
18)	Linux Privilege Escalation	336
System enumeration command :	337
-	Kernel exploitation :	339
-	Passwords & File Permissions exploitation :	339
-	Sudo exploitation :	340
-	LD_PRELOAD :	340
-	SUID Exploitation	341
-	Shared Object Injection :	341
-	VIA Environment Variables :	342
-	Exploiting SUID permission in cpulimit command :	344
-	RCE through mysql command on a writeable directory :	345
-	Lxd Privilege Escalation	345
-	Python Library Hijacking	346
Method 1 : From Bad Write Permission	346
Method 2 : Priority Order	346
Method 3 : PYTHONPATH Environment Variable	347
20)	Format ELF	351
Section in ELF	351
Environnement d'exécution :	352
21)	Python	353
-	MISC	353
22)	OSINT	354
Useful tools	354
23)	Metasploit	356
-	Autoroute exploit :	356
-	Ping sweep :	356
-	auxiliary tcp port scanner :	357
24)	GraphQL	357
-	Definiton	357
-	Common GraphQL endpoint :	359
-	GraphQL injection :	360
-	Useful Introspection query	360
-	MISC	361
25)	Bash	361
-	MISC	361
26)	Ruby-On-Rails	362
-	MISC	362
27)	PowerShell	364
-	Definition	364
28)	Others	365
-	Recovering saved macOS user passwords	366
-	Mass assignment	366
Tunneling with Chisel :	367
29)	Active Directory	368
30)	DNS	368
Différents Commands	368
-	DNSSEC	370
-	MISC	370
31)	Android	371
Tools	371
-	Decompile APK	371
-	AndroidManifest.xml :	372
-	Root détection :	372
-	Bypass root detection :	372
-	Android Activity lifecycle :	373
-	Rooting and Jailbreaking :	374
-	Signing mobile application :	375
MISC	376
32)	IOS	377
Tools	377
-	MISC	377
33)	Reverse	378
-	Techniques d’anti-reverse :	378
1)	Polymorphisme et métamorphisme	378
2)	Packer	378
3)	Anti-virtualisation et anti-émulation	379
34)	Container Security	380
-	Definition	380
Some Commands	381
-	Registre Docker	383
-	Docker Compose	383
-	Dockerfile	383
Container Breakouts :	384
-	Misc	386
35)	S3 (Simple Storage Service) AWS (Amazon Web Services)	387
-	Définition	388
-	S3 Buckets	388
-	ACL ( Access control list )	388
36)	Smart Contract	390
37)	Windows in general	390
Commands	390
-	NT hash	390
-	Hiberfill.sys file	391
-	DLL Hijacking definiton	392
DLL Hijacking techniques	392
-	UAC Bypass definiton	392
UAC bypass techniques	393
-	Process migration :	394
-	Misc	395
38)	Wifi	395
Tools	395
-	SSID	395
-	WLAN	396
-	WPA PSK	396
-	WPA ou WPA2	397
-	WPA-Personal vs WPA-Entreprise	397
-	WPA/WPA2 MGT	398
-	Protocole WPS	398
-	AP ( Access Point )	398
-	BSSID	399
-	BSS	399
-	Password Cracking ( WPA/WPA2 BForcing )	401
Steps :	401
39)	DevOps / DevOpsSec	403
-	Définition	403
Etape Dev et Ops :	 	404
Version Control System :	404
Testing :	405
Intégration Continue :	405
Infrastructure as Code	406
40)	Audit en boîte blanche	407
Code Review : Strategies :	407
Code Review : Reviewing :	409
-	Méthode 1	409
41)	Bug bounty Tips	410
-	BB - Recon (file, url, subdomains):	410
-	BB - CSRF Bypass protection :	411
-	BB - OAuth :	413
-	BB - SAML  :	414
-	BB - Bypassing 403 and 401 error :	414
-	BB : File upload :	416
-	BB : Broken access control :	418
-	BB - XSS  :	419
-	BB - SSRF  :	420
-	BB - Login/password form  :	422
-	BB - CORS :	423
-	BB - Web Cache Poisoning :	426
-	BB - HTTP response header injection :	426
-	BB - HTTP Host header attacks :	427
-	BB - API :	428
-	BB - Information Disclosure/gathering :	431
-	BB - Business logic vulnerabilities :	433
-	BB - GraphQL :	433
-	BB - APK :	434
-	Non technique, normes, ...	434
PCI DSS	434
-	Secure PHP Software Guideline	436
-	Dependency Management	436
-	Recommended Packages	436
Subresource Integrity	436
Document Relationships	437
Database Interaction	438
File Uploads	438
-	Security Web Testing Guide	438
Information Gathering	439
-	General	440
-	Shodan	445
Configuration and Deployment Management Testing	445
-	Review each version (if possible) of each element related to the server web (DB, proxy, …)	445
Client-side Testing	449
-	DOM XSS	449
-	Test automatique :	449
-	FindomXSS :	449
-	DOM based XSS Finder (extension CHROME) (FUZZ)	449
-	DOM Invader (en ouvrant le navigateur depuis BURP)	449
-	XSStrike (FUZZ)	449
-	Test manuel :	449
API Testing	450
-	GraphQL	450
Testing Browser Storage	450
Testing Web Messaging	450
Testing for Cross Site Script Inclusion	451
Testing for Host Header Injection	451
Testing for SQLi	453
Search Engine	454
Mimicatz	455

