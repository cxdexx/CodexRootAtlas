# Learning

 PortSwigger Web Security Academy: https://portswigger.net/web-security
 
 TryHackMe: https://tryhackme.com
 
 HackTheBox: https://hackthebox.com

 https://www.exploit-db.com: Each confirmed vulnerability is assigned a unique identifier in the format CVE-YEAR-NUMBER, such as CVE-2025-55182. If the vulnerability is impactful enough, it may even get a moniker. You may have heard of vulnerabilities such as Heartbleed, React2Shell, and Log4Shell. These vulnerabilities are given a score (CVSS) based on a variety of factors, such as:

    Impact - What damage can this vulnerability lead to?
    Complexity - Is the vulnerability easy to exploit or not? 
    Availability - How likely is it that someone can exploit this? 
    
    Organisations use scoring like this to prioritise their level of risk. Addressing the highest scoring first.
    
    These identifiers function as a reference point among vendors, researchers, security tools, and documentation, ensuring that everyone discussing a vulnerability refers to the same issue. Websites like ExploitDB compile this information alongside "Proof of Concepts" (PoCs), which are scripts capable of demonstrating the vulnerability.

 
 OWASP Juice Shop: https://owasp.org/www-project-juice-shop

 Semgrep: https://semgrep.dev/

 Subnetting By Network Chunk: https://www.youtube.com/watch?v=oZGZRtaGyG8&start=541

 # OSINT : 
        
        https://exiftool.org/exiftool_pod.html
        https://www.shodan.io/ 
        https://earth.google.com/
        https://intelbase.is/
        https://app.osint.industries/
        https://github.com/owasp-amass/amass
        https://github.com/cxdexx/sherlock
        https://www.spiderfoot.net/
        https://www.shodan.io/
        AbuseIPDB, and Cisco Talos Intelligence ----for performing a reputation and location check for the IP address
        https://www.virustotal.com/ -----VirusTotal collates results from over 70 antivirus engines and website scanners into a single interface. Submit a file, a URL, a domain, or a file hash. VirusTotal will tell you whether any of those engines have flagged it as malicious or not.

WHOIS is a query/response protocol defined in 3912 (opens in new tab). WHOIS servers listen on port 43 and provide registration details for domain names. The domain registrar maintains these records for the domains they lease.

nslookup and dig. Both query DNS, but dig (historically a backronym for "Domain Information Groper") is the modern, preferred option. It provides cleaner output, displays TTL values by default (showing how long records are cached), and is more reliable for complex queries and scripting. nslookup is covered here for compatibility, since you will encounter it in older documentation and on Windows systems, but dig should be your default tool.

 DNSDumpster.com: It aggregates public DNS data from sources such as search engine caches, zone transfer databases, and certificate records.

 Certificate Transparency Logs (crt.sh): is a public logging framework (mandatory since approximately 2015) that records every SSL/TLS certificate issued by participating Certificate Authorities. Each certificate contains a Subject Alternative Name (SAN) field listing the domains and subdomains it covers. By searching these logs, you can discover subdomains without sending any traffic to the target.

# Phishing

1. Gophish (https://github.com/gophish/gophish): is a web-based framework that makes setting up phising campaigns more straightforward. It allows you to store your SMTP server settings for sending emails and has a web-based tool for creating email templates using a simple WYSIWYG (What You See Is What You Get) editor. You can also schedule emails and have an analytics dashboard that shows open and click rates. 

2. EvilNginx(https://github.com/kgretzky/evilginx2): is a tool designed for advanced phising campaigns that bypass multi-factor authentication (MFA). It acts as a reverse between victims and legitimate sites, capturing credentials and session tokens in real time.

3. The Social Engineering ToolKit(https://github.com/trustedsec/social-engineer-toolkit):contains many tools. Still, some of the important ones for phisong  are the ability to create spear-phising attacks and deploy fake versions of common websites to trick victims into entering their credentials. In task 6, we will get hands-on experience with this tool.
