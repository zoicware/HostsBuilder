## Hosts Builder
Create a custom hosts file to block various DNS servers to increase privacy and security
## Features

#### Choose Blocklists
- **Threat Intelligence Feeds** - Source : [hagezi dns blocklist](https://github.com/hagezi/dns-blocklists?tab=readme-ov-file#tif)
- **Multi PRO** - Source : [hagezi dns blocklist](https://github.com/hagezi/dns-blocklists?tab=readme-ov-file#pro)
- **Steven Black Hosts** - Source : [Steven Black Hosts](https://github.com/StevenBlack/hosts/blob/master/data/StevenBlack/hosts)
- **URL Haus Malware** - Source : [URL Haus Host File](https://urlhaus.abuse.ch/downloads/hostfile/)
- **AdguardDNS** - Source : [AdguardDNS](https://v.firebog.net/hosts/AdguardDNS.txt)

### Hosts File Compression
With the large size of these lists its neccesary to compress them using [Hosts-BL](https://github.com/ScriptTiger/Hosts-BL)

The script will compile lists and compress them by removing comments, removing duplicate DNS servers, and adding the max (9) DNS servers on each line instead of 1

### Backup Hosts
This option will backup the current hosts file with the name `hosts.bak`

**Note if this file already exists the script will assign a random 3 digit number to the name**

### Reset Hosts 

This option resets the current hosts back to the default Microsoft hosts format


### Flush DNS

**Recommended to do after building a new list**

Runs command `ipconfig /flushdns`


### DEMO
![image](https://github.com/zoicware/HostsBuilder/assets/118035521/0a973fe6-c01c-4514-ac58-9ec2ca587cf5)
