# KOF
![index image](/images/kof/index.png)

## Recon
In the beginning I used NMAP with the following parameters. So I found just ports 22 and 8000 open (it's seens a django application in a linux)
```
sudo nmap 172.16.11.225 -Pn -sSVC -T5

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http-alt WSGIServer/0.2 CPython/3.9.19
|_http-server-header: WSGIServer/0.2 CPython/3.9.19
|_http-title: KOF 2002 Championship
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```