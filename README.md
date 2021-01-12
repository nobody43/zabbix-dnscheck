# zabbix-dnscheck
## Features
This external check allows public dns records monitoring without zabbix agent or dns server access. It is also useful when you want to know if the pinged host does not exist (that's right).

- Low-Level Discovery
- Bulk items upload with zabbix-sender
- Efficient: no unnecessary processes are spawned
- Configurable

Note: for simple agent dns monitoring you should use [net.dns.record](https://www.zabbix.com/documentation/2.4/manual/config/items/itemtypes/zabbix_agent)

![Triggers](https://raw.githubusercontent.com/nobodysu/zabbix-dnscheck/master/screenshots/dnscheck-triggers-cut.png)

It is possible to control what data is gathered by providing arguments to the discovery script in `template -> Discovery -> DNS Check Discovery -> Key`. Based on that, items and triggers will be created and the script will behave differently. For simplicity's sake templates are created for general use: `Workstation`, `Server` and `Mail Server`. Its contents are identical, only arguments to the script differs.

| Argument         | Possible values     | Comment                                                                             |
| ---------------- | ------------------- | ----------------------------------------------------------------------------------- |
| sys.argv[1]      | get, getverb        | Regular or verbose mode. In verbose you can see zabbix sender output.               |
| sys.argv[2]      | e.g. `example.org`  | DNS name of the host. `{HOST.DNS}` in zabbix.                                       |
| sys.argv[3]      | e.g. `Example host` | `Host name` from host's configuration. `{HOST.HOST}` in zabbix.                     |
| sys.argv[4]      | ptrYES, ptrNO       | Whether gather PTR or not. Will spawn additional process for each found IP address. |
| sys.argv[5]      | ipv6YES, ipv6NO     | IPv6 records. Will not spawn additional process.                                    |
| sys.argv[6]      | mxYES, mxNO         | MX. Will not spawn additional process.                                              |
| sys.argv[7]      | txtYES, txtNO       | TXT. Will spawn additional process.                                                 |

## Installation
Requires `python3`, `zabbix-sender`, `bind9-host` (Debian) or `bind-utils` (Centos) packages. Uses `host` binary.<br />

Take a look at script's first lines and change values if necessary. Its important to specify `serverIP` (server or proxy) in `dnscheck-send.py`.

Place scripts in `externalscripts` directory on your server or proxy.
```bash
mv dnscheck-gather-lld.py dnscheck-send.py /usr/lib/zabbix/externalscripts/
```

Apply necessary permissions.
```bash
chmod 750 dnscheck-gather-lld.py
chown root:zabbix dnscheck-gather-lld.py
chmod 750 dnscheck-send.py
chown root:zabbix dnscheck-send.py
```

Import required templates in zabbix web interface. Then assign hosts and wait. 

Note: before scripts would work, zabbix server must first discover available items. It is done in 12 hour cycles by default. You can temporary decrease this parameter for testing in `template -> Discovery -> DNS Check Discovery -> Update interval`.

## Testing
```bash
./dnscheck-gather-lld.py get 'pc1.example.org' 'Example workstation' ptrNO ipv6NO mxNO txtNO
```
Process host `Example workstation` with dns `pc1.example.org` gathering only IPv4 records.
<br /><br />

```bash
./dnscheck-gather-lld.py getverb 'server.example.org' 'Example server' ptrYES ipv6YES mxNO txtNO
```
Verbosely process host `Example server` with dns `server.example.org` gathering IPv4, PTR and IPv6 records.
<br /><br />

```bash
./dnscheck-gather-lld.py getverb 'mail.example.org' 'Example mail server' ptrYES ipv6YES mxYES txtYES
```
Verbosely process host `Example mail server` with dns `mail.example.org` gathering IPv4, PTR, IPv6, MX and TXT records.
<br /><br />

These scripts were tested to work with following configurations:
- Centos 7 / Zabbix 3.0 / Python 3.4
- Debian 10 / Zabbix 5.0 / Python 3.7

## Links
- http://unlicense.org
