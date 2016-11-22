#!/usr/bin/env python3

## Installation instructions: https://github.com/nobodysu/zabbix-dnscheck ##

dnsWait = '1'     # each dns query will take no more than one second (multiple DNS servers ARE processed)

hostPath = 'host'
#hostPath = r'/usr/bin/host'             # if host isn't in PATH
pythonPath = 'python3'
#pythonPath = '/usr/local/bin/python3'   # if python isn't in PATH
senderPyPath = r'/usr/lib/zabbix/externalscripts/dnscheck-send.py'

## End of configuration ##

import sys
import re
import json
import subprocess

hostname = sys.argv[2]

ptrCheck = sys.argv[3]
IPv6Check = sys.argv[4]
mxCheck = sys.argv[5]
txtCheck = sys.argv[6]

jsonData = []
senderData = []

hostOut = subprocess.check_output([hostPath, '-W', dnsWait, hostname], universal_newlines=True)

ipv4Re = re.findall(r' has address (.+)$', hostOut, re.I | re.M)
ipv4Re.sort()   # prevent ips mess up on each query

if ipv4Re:
    for num4, ip4 in enumerate(ipv4Re, start=1):
        num4 = str(num4)
        jsonData.append({'{#HOSTNAME}':hostname, '{#IPV4NUM}':num4})
        senderData.append(hostname + ' dnscheck.ipv4[' + num4 + '] "' + ip4 + '"')   # example.org dnscheck.ipv4[1] "192.0.2.1"

        if ptrCheck == 'ptrYES':
            hostPtr4Out = subprocess.check_output([hostPath, '-W', dnsWait, ip4], universal_newlines=True)

            ptr4Re = re.findall(' domain name pointer (.+)$', hostPtr4Out, re.I | re.M)

            if ptr4Re:
                for i in ptr4Re:
                    jsonData.append({'{#HOSTNAME}':hostname, '{#PTR4NUM}':num4})
                    senderData.append(hostname + ' dnscheck.ptr4[' + num4 + '] "' + i + '"')   # example.org dnscheck.ptr4[1] "example.org."

                if len(ptr4Re) > 1:   # if more than one PTR per IP were found
                    jsonData.append({'{#HOSTNAME}':hostname, '{#PTR4NUM}':num4})
                    senderData.append(hostname + ' dnscheck.ptr4[' + num4 + '] "MULTIPTR"')

            elif hostPtr4Out.find('no servers could be reached') != -1:
                jsonData.append({'{#HOSTNAME}':hostname, '{#PTR4NUM}':num4})
                senderData.append(hostname + ' dnscheck.ptr4[' + num4 + '] "TIMEOUT"')

            else:
                jsonData.append({'{#HOSTNAME}':hostname, '{#PTR4NUM}':num4})
                senderData.append(hostname + ' dnscheck.ptr4[' + num4 + '] "NOPTR"')

elif hostOut.find('no servers could be reached') != -1:
    jsonData.append({'{#HOSTNAME}':hostname, '{#IPV4NUM}':'1'})
    senderData.append(hostname + ' dnscheck.ipv4[1] "TIMEOUT"')

else:
    jsonData.append({'{#HOSTNAME}':hostname, '{#IPV4NUM}':'1'})
    senderData.append(hostname + ' dnscheck.ipv4[1] "NOIPV4"')


if IPv6Check == 'ipv6YES':
    ipv6Re = re.findall(' has IPv6 address (.+)$', hostOut, re.I | re.M)
    ipv6Re.sort()

    if ipv6Re:
        for num6, ip6 in enumerate(ipv6Re, start=1):
            num6 = str(num6)
            jsonData.append({'{#HOSTNAME}':hostname, '{#IPV6NUM}':num6})
            senderData.append(hostname + ' dnscheck.ipv6[' + num6 + '] "' + ip6 + '"')

            if ptrCheck == 'ptrYES':
                hostPtr6Out = subprocess.check_output([hostPath, '-W', dnsWait, ip6], universal_newlines=True)

                ptr6Re = re.findall(' domain name pointer (.+)$', hostPtr6Out, re.I | re.M)

                if ptr6Re:
                    for i in ptr6Re:
                        jsonData.append({'{#HOSTNAME}':hostname, '{#PTR6NUM}':num6})
                        senderData.append(hostname + ' dnscheck.ptr6[' + num6 + '] "' + i + '"')

                    if len(ptr6Re) > 1:   # if more than one PTR per IP were found
                        jsonData.append({'{#HOSTNAME}':hostname, '{#PTR6NUM}':num6})
                        senderData.append(hostname + ' dnscheck.ptr6[' + num6 + '] "MULTIPTR"')

                elif hostPtr6Out.find('no servers could be reached') != -1:
                    jsonData.append({'{#HOSTNAME}':hostname, '{#PTR6NUM}':num6})
                    senderData.append(hostname + ' dnscheck.ptr6[' + num6 + '] "TIMEOUT"')

                else:
                    jsonData.append({'{#HOSTNAME}':hostname, '{#PTR6NUM}':num6})
                    senderData.append(hostname + ' dnscheck.ptr6[' + num6 + '] "NOPTR"')

    elif hostOut.find('no servers could be reached') != -1:
        jsonData.append({'{#HOSTNAME}':hostname, '{#IPV6NUM}':'1'})
        senderData.append(hostname + ' dnscheck.ipv6[1] "TIMEOUT"')

    else:
        jsonData.append({'{#HOSTNAME}':hostname, '{#IPV6NUM}':'1'})
        senderData.append(hostname + ' dnscheck.ipv6[1] "NOIPV6"')


if mxCheck == 'mxYES':
    mxRe = re.findall(r' mail is handled by\s+(\d+)\s+(.+)$', hostOut, re.I | re.M)
    mxRe.sort()

    if mxRe:
        for numMX, (valMXpri, valMX) in enumerate(mxRe, start=1):
            numMX = str(numMX)
            jsonData.append({'{#HOSTNAME}':hostname, '{#MXNUM}':numMX})
            senderData.append(hostname + ' dnscheck.mx[' + numMX + '] "' + valMX + '"')
            jsonData.append({'{#HOSTNAME}':hostname, '{#MXPRINUM}':numMX})
            senderData.append(hostname + ' dnscheck.mxpri[' + numMX + '] "' + valMXpri + '"')

    elif hostOut.find('no servers could be reached') != -1:
        jsonData.append({'{#HOSTNAME}':hostname, '{#MXNUM}':'1'})
        senderData.append(hostname + ' dnscheck.mx[1] "TIMEOUT"')
        #jsonData.append({'{#HOSTNAME}':hostname, '{#MXPRINUM}':'1'})   # priority is not gathered when no MX is present
        #senderData.append(hostname + ' dnscheck.mxpri[1] "TIMEOUT"')

    else:
        jsonData.append({'{#HOSTNAME}':hostname, '{#MXNUM}':'1'})
        senderData.append(hostname + ' dnscheck.mx[1] "NOMX"')
        #jsonData.append({'{#HOSTNAME}':hostname, '{#MXPRINUM}':'1'})
        #senderData.append(hostname + ' dnscheck.mxpri[1] "NOMX"')


if txtCheck == 'txtYES':
    txtOut = subprocess.check_output([hostPath, '-W', dnsWait, '-t', 'txt', hostname], universal_newlines=True)

    txtRe = re.findall(' descriptive text (.+)$', txtOut, re.I | re.M)
    txtRe.sort()

    if txtRe:
        for numTxt, valTxt in enumerate(txtRe, start=1):
            if not re.search('^".+"$', valTxt):   # if value is not encased in quotes
                valTxt = '"' + valTxt + '"'

            numTxt = str(numTxt)
            jsonData.append({'{#HOSTNAME}':hostname, '{#TXTNUM}':numTxt})
            senderData.append(hostname + ' dnscheck.txt[' + numTxt + '] ' + valTxt)

    elif hostOut.find('no servers could be reached') != -1:
        jsonData.append({'{#HOSTNAME}':hostname, '{#TXTNUM}':'1'})
        senderData.append(hostname + ' dnscheck.txt[1] "TIMEOUT"')

    else:
        jsonData.append({'{#HOSTNAME}':hostname, '{#TXTNUM}':'1'})
        senderData.append(hostname + ' dnscheck.txt[1] "NOTXT"')


print(json.dumps({"data": jsonData}, indent=4))   # print json for LLD

senderDataNStr = '\n'.join(senderData)   # items for zabbix sender separated by newlines

# pass senderDataNStr to dnscheck-send.py:
if sys.argv[1] == 'get':
    subprocess.Popen([pythonPath, senderPyPath, 'get', senderDataNStr], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)   # spawn new process and regain shell control immediately
elif sys.argv[1] == 'getverb':
    subprocess.Popen([pythonPath, senderPyPath, 'getverb', senderDataNStr])   # do not detach if in verbose mode, also skips timeout in dnscheck-send.py
else:
    print(sys.argv[0] + ": Not supported. Use 'get' or 'getverb'.")
    sys.exit(1)

