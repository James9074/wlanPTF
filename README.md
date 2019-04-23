# wlanPTF 👀
A real neato automated recon tool by https://wlan1.net

_wlanPTF automates the first step in any recon job:
"Run a light nmap scan, investigate the http ports, see what's up with open SMB shares, etc."_

*Designed for scenarios where making noise isn't an issue.
```
██╗    ██╗██╗      █████╗ ███╗   ██╗██████╗ ████████╗███████╗
██║    ██║██║     ██╔══██╗████╗  ██║██╔══██╗╚══██╔══╝██╔════╝
██║ █╗ ██║██║     ███████║██╔██╗ ██║██████╔╝   ██║   █████╗  
██║███╗██║██║     ██╔══██║██║╚██╗██║██╔═══╝    ██║   ██╔══╝  
╚███╔███╔╝███████╗██║  ██║██║ ╚████║██║        ██║   ██║     
╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝        ╚═╝   ╚═╝     
E N T E R P R I S E                       E D I T I O N

Default Usage: ./ptf scan 10.10.10.10

Options: 
     ./ptf status     Show all scanners spawned and their statuses
     ./ptf stop       Stops all scanners in motion
     ./ptf cleanup    Stops all scanners and removes all files

Extended usage:
    --http     Limit scanning to http/s services
    --smb      Limit scanning to SMB services

**Note: Scanners == Programs like nikto, nmap, etc that investigate open ports found**
```

## Quick Start Example
```
$ ptf scan wlan1.net
Beginning probe scans for wlan1.net
Starting light nmap scan for initial recon...
Auto investigating the following identified services. Run `ptf status` for an update.
+-------+----------+-----------+--------+------------+---------------+------------+---------+
|   PID | Name     | Target    | Port   | Service    | Output        | Start      | End     |
|-------+----------+-----------+--------+------------+---------------+------------+---------|
|  5896 | nikto    | wlan1.net | 80     | http       | nikto80.txt   | 5:42:16 PM | Running |
|  5898 | nikto    | wlan1.net | 8080   | http-proxy | nikto8080.txt | 5:42:16 PM | Running |
|  5900 | nikto    | wlan1.net | 443    | https      | nikto443.txt  | 5:42:16 PM | Running |
|  5902 | nmapFull | wlan1.net |        |            | nmapFull.txt  | 5:42:16 PM | Running |
+-------+----------+-----------+--------+------------+---------------+------------+---------+



$ head nikto80.txt                                                                                                                         
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          70.142.220.45
+ Target Hostname:    wlan1.net
+ Target Port:        80
+ Start Time:         2019-04-23 17:42:16 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.25 (Debian)
+ Server leaks inodes via ETags, header found with file /, fields: 0x1171 0x5714a1c99dad7
+ The anti-clickjacking X-Frame-Options header is not present.
```
