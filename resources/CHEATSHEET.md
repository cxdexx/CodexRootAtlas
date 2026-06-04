# Offensive Security Cheatsheet

## Recon
- `nmap -sC -sV -oA recon/scan target`
- `dirsearch -u https://target -e php,html,js`
- `gobuster dir -u https://target -w wordlist.txt -t 50`

## Web testing
- `sqlmap -u "https://target/vuln?id=1" --batch`
- `ffuf -u https://target/FUZZ -w wordlist.txt`
- `xsser --crawl https://target`

## Exploitation
- `msfconsole -q`
- `searchsploit mysql 5.7`
- `python3 exploit.py`

## Post-exploitation
- `ssh user@target`
- `impacket-secretsdump -system SYSTEM -security SECURITY -ntds NTDS.dit LOCAL`
- `crackmapexec smb target -u user -p pass --shares`
