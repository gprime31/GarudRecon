# GarudRecon


<h3>Under Construction.....</h3><br><br>

GarudRecon is an automated reconnaissance scanner that can be used to discover assets and scan for vulnerabilities using the latest open source tools and techniques.


```
  ___    __    ____  __  __  ____  ____  ____  ___  _____  _  _ 
 / __)  /__\  (  _ \(  )(  )(  _ \(  _ \( ___)/ __)(  _  )( \( )
( (_-. /(__)\  )   / )(__)(  )(_) ))   / )__)( (__  )(_)(  )  ( 
 \___/(__)(__)(_)\_)(______)(____/(_)\_)(____)\___)(_____)(_)\_)

```                                                                                                  

<h3>Installation</h3>

**System requirements:** Recommended to run on vps with ``1VCPU`` and ``2GB RAM``.<br>
Make sure you're root before installing the tool

```bash
git clone https://github.com/rix4uni/GarudRecon.git && cd GarudRecon/ && chmod +x garudrecon install.sh && mv garudrecon /usr/bin/ && ./install.sh
```

<h3>Usage</h3>

``` 
  ___    __    ____  __  __  ____  ____  ____  ___  _____  _  _ 
 / __)  /__\  (  _ \(  )(  )(  _ \(  _ \( ___)/ __)(  _  )( \( )
( (_-. /(__)\  )   / )(__)(  )(_) ))   / )__)( (__  )(_)(  )  ( 
 \___/(__)(__)(_)\_)(______)(____/(_)\_)(____)\___)(_____)(_)\_)

Example Usage:
garudrecon [-d domain.com] [-x exclude domains] [--json] [-s]
      -d  | --domain      (required) : Domain in domain.tld format
      -r  | --recon       (optional) : Search subdomains for the specified domain
      -s  | --scan        (optional) : Scan the specified domain
      -c  | --amassconfig (optional) : Provide Amass configuration files for better results
      -rp | --resultspath (optional) : Defines the output folder
      -x  | --exclude     (optional) : Exclude out of scope domains
      -s  | --silent      (optional) : Hide output in the terminal
      -j  | --json        (optional) : Store output in a single json file
      -v  | --version     (optional) : Print current version of GarudRecon

```

**Example Usage**

```txt
garudrecon -d hackerone.com
```
Exclude out of scope domains
```txt
echo test.hackerone.com > ossdomain.txt
garudrecon -d hackerone.com -x ~/ossdomain.txt
```
With all flags
```txt
garudrecon -d hackerone.com -j -s -x /home/oss.txt
```

Hide output in the terminal

```txt
garudrecon -d hackerone.com -s
```
# Tools

## Subdomain Enumeration
  - [aquatone](https://github.com/michenriksen/aquatone)
  - [knockpy](https://github.com/guelfoweb/knock)
  
  - [subbrute](https://github.com/TheRook/subbrute)
  
  - [assetfinder](https://github.com/tomnomnom/assetfinder)
  
  - [domain-finder](https://raw.githubusercontent.com/gwen001/pentest-tools/master/domain-finder.py)
  
  - [rsdl](https://github.com/tismayil/rsdl)
  
  - [subDomainizer](https://github.com/nsonaniya2010/SubDomainizer)
  
  - [domain_analyzer](https://github.com/eldraco/domain_analyzer)
  
  - [massdns](https://github.com/blechschmidt/massdns)
  
  - [subfinder](https://github.com/subfinder/subfinder)
  
  - [amass](https://github.com/caffix/amass)
  
  - [sub.sh](https://github.com/cihanmehmet/sub.sh)
  
  - [sublist3r](https://github.com/aboul3la/Sublist3r)
  
  - [Sudomy](https://github.com/Screetsec/Sudomy)
  
  - [dnsenum](https://github.com/fwaeytens/dnsenum)
  
  ## Content Discovery
  
  ### API
  
  - [secretx](https://github.com/xyele/secretx)
  
  
  ### AWS S3 Bucket
  
  - [s3brute](https://github.com/ghostlulzhacks/s3brute)
  
  - [s3-bucket-finder](https://github.com/gwen001/s3-buckets-finder)
  
  - [bucket-stream](https://github.com/eth0izzle/bucket-stream)
  
  - [slurp](https://github.com/nuncan/slurp)
  
  - [lazys3](https://github.com/nahamsec/lazys3)
  
  - [cred_scanner](https://github.com/disruptops/cred_scanner)
  
  - [DumpsterDiver](https://github.com/securing/DumpsterDiver)
  
  - [S3Scanner](https://github.com/sa7mon/S3Scanner)
  
  ### Inspecting JS Files
  
  - [JSParser](https://github.com/nahamsec/JSParser)
  
  - [relative-url-extractor](https://github.com/jobertabma/relative-url-extractor)
  
  - [github-search](https://raw.githubusercontent.com/gwen001/github-search/master/github-subdomains.py)
  - [sub.js](https://github.com/lc/subjs)
  
  ### Code Audit
  
  - [Cobra](https://github.com/WhaleShark-Team/cobra)
  
  ### Crawlers
  
  - [Crawler](https://github.com/ghostlulzhacks/crawler)
  
  - [waybackMachine](https://github.com/ghostlulzhacks/waybackMachine)
  
  - [meg](https://github.com/tomnomnom/meg)
  
  - [hakrawler](https://github.com/hakluke/hakrawler)
  
  - [igoturls](https://github.com/xyele/igoturls)
  
  ### Directory Bruteforcers & Fuzzers
  
  - [gobuster](https://github.com/OJ/gobuster)
  
  - [ffuf](https://github.com/ffuf/ffuf)
  
  - [dirsearch](https://github.com/maurosoria/dirsearch)
  
  ## Exploitation
  
  ### Subdomain Takeover
  
  - [subjack](https://github.com/haccer/subjack)
  
  - [subdomain-takeover](https://github.com/antichown/subdomain-takeover)
  
  - [takeover](https://github.com/m4ll0k/takeover)
  
  - [SubOver](https://github.com/Ice3man543/SubOver)
  
  
  ### Google Cloud Storage
  
  - [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute)
  
  ### Digital Ocean
  
  - [spaces-finder](https://github.com/appsecco/spaces-finder)
  
  ### XXE
  
  - [XXEinjector](https://github.com/enjoiz/XXEinjector)
  
  ### CSRF
  
  - [XSRFProbe](https://github.com/0xInfection/XSRFProbe)
  
  ### Command Injection
  
  - [commix](https://github.com/commixproject/commix)
  
  
  ### SQLi
  
  - [sqlmap](https://github.com/sqlmapproject/sqlmap)
  
  - [sqliv](https://github.com/the-robot/sqliv)
  
  - [sqlmate](https://github.com/s0md3v/sqlmate)
  
  ### XSS
  
  - [XSStrike](https://github.com/s0md3v/XSStrike)
  
  - [XSS-keylogger](https://github.com/hadynz/xss-keylogger)
  
  
  ## CMS
  
  - [CMSmap](https://github.com/Dionach/CMSmap)
  
  - [CMSeeK](https://github.com/Tuhinshubhra/CMSeeK)
  
  - [wpscan](https://github.com/wpscanteam/wpscan)
  
  - [Joomscan](https://github.com/rezasp/joomscan)
  
  - [Droopescan](https://github.com/droope/droopescan)
  
  - [Drupwn](https://github.com/immunIT/drupwn)
  
  ## CloudFlare
  
  - [CloudFail](https://github.com/m0rtem/CloudFail)
  
  ## Git
  
  - [truffleHog](https://github.com/dxa4481/truffleHog.git)
  
  - [git-dumper](https://github.com/arthaud/git-dumper)
  
  ## Frameworks
  
  - [Sn1per](https://github.com/1N3/Sn1per)
  
  - [XRay](https://github.com/evilsocket/xray)
  
  - [datasploit](https://github.com/DataSploit/datasploit)
  
  - [Osmedeus](https://github.com/j3ssie/Osmedeus)
  
  - [TIDoS-Framework](https://github.com/0xinfection/tidos-framework)
  
  - [discover](https://github.com/leebaird/discover)
  
  - [lazyrecon](https://github.com/nahamsec/lazyrecon)
  
  - [003Recon](https://github.com/003random/003Recon)
  
  - [LazyRecon](https://github.com/capt-meelo/LazyRecon)
  
  - [Vulmap](https://github.com/zhzyker/vulmap)
  
  
  ## Wordlists
  
  - [SecLists](https://github.com/danielmiessler/SecLists)
  
  - [Jhaddix Wordlist](https://gist.githubusercontent.com/jhaddix/b80ea67d85c13206125806f0828f4d10/raw/c81a34fe84731430741e0463eb6076129c20c4c0/content_discovery_all.txt)  
  
  - [Nahamsec list](https://gist.githubusercontent.com/Leoid/38984017886cd058a314dfda5c3d6c6e/raw/1ee5fe1da82a3ae92b0c486f86fbe26bbdff1e06/Nahamsec%2520Thread)  
  
  ## Other
  
  - [altdns](https://github.com/infosec-au/altdns)
  
  - [nmap](https://nmap.org/)
  
  - [Blazy](https://github.com/s0md3v/Blazy)
  
  - [httprobe](https://github.com/tomnomnom/httprobe)
  
  - [broken-link-checker](https://github.com/stevenvachon/broken-link-checker)
  
  - [wafw00f](https://github.com/EnableSecurity/wafw00f)

## Mindmap/Workflow
![Flow](workflow.png)
